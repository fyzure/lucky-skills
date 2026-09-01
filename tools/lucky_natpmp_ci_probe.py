#!/usr/bin/env python3
"""Runtime-verify Lucky 3.0.0 NAT-PMP mapping on an isolated CI bridge.

The probe is intentionally GitHub-Actions-only. It starts a fresh pinned Lucky
container on a Docker ``--internal`` bridge, creates a second isolated veth/
network-namespace "WAN", and runs three tiny stdlib UDP fixtures on the Docker
bridge host gateway address:

* a STUN Binding responder;
* a NAT-PMP gateway on the standard UDP/5351 port;
* a UDP echo target behind the Lucky STUN rule.

Lucky is configured exclusively through its HTTP API. A temporary UDP STUN
rule must ask the fake gateway for a NAT-PMP mapping. The fake gateway then
opens one owned UDP mapping relay on the isolated WAN address. A client in the
WAN namespace sends a random marker through the mapped port; the bytes must
travel WAN -> mapping relay -> Lucky -> echo target -> Lucky -> mapping relay
-> WAN and return exactly. Disabling/deleting the TEST rule must also produce
the NAT-PMP lifetime=0 deletion request and close the owned mapping relay.

No production Lucky instance, physical interface, firewall, router, public
STUN server, UPnP device or Internet route is involved.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import secrets
import select
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from lucky_docker_build_ci_probe import (
    ADMIN_PORT,
    EXPECTED_LUCKY_VERSION,
    PINNED_LUCKY_IMAGE,
    ProbeError,
    cleanup_root_owned_conf,
    docker,
    enable_open_token,
    json_request,
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    run,
    wait_for_lucky,
)


TEST_PREFIX = "TEST-lucky-skills-natpmp-ci-"
STUN_COOKIE = 0x2112A442
NATPMP_PORT = 5351
TEST_WAN_GATEWAY = "192.0.2.1"
TEST_WAN_CLIENT = "192.0.2.2"
TEST_WAN_PREFIX = "30"


def docker_network_values(network_name: str) -> tuple[str, str]:
    raw = docker("network", "inspect", network_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker network inspect response")
    configs = rows[0].get("IPAM", {}).get("Config", [])
    if not isinstance(configs, list):
        raise ProbeError("Docker network inspect missing IPAM config")
    for config in configs:
        if not isinstance(config, dict):
            continue
        gateway = config.get("Gateway")
        subnet = config.get("Subnet")
        if not isinstance(gateway, str) or not isinstance(subnet, str):
            continue
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            gateway_ip = ipaddress.ip_address(gateway)
        except ValueError as exc:
            raise ProbeError("Docker internal bridge IPAM values are invalid") from exc
        if isinstance(network, ipaddress.IPv4Network) and network.is_private and gateway_ip in network:
            return gateway, subnet
    raise ProbeError("Docker internal bridge did not expose a private IPv4 subnet/gateway")


def container_ipv4(container_name: str, network_name: str) -> str:
    raw = docker("inspect", container_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    networks = rows[0].get("NetworkSettings", {}).get("Networks", {})
    item = networks.get(network_name) if isinstance(networks, dict) else None
    value = item.get("IPAddress") if isinstance(item, dict) else None
    if not isinstance(value, str) or not value:
        raise ProbeError("temporary Lucky container has no internal-network IPv4")
    try:
        socket.inet_aton(value)
    except OSError as exc:
        raise ProbeError("temporary Lucky internal address is not IPv4") from exc
    return value


def admin_port_is_unpublished(container_name: str) -> bool:
    raw = docker("inspect", container_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    bindings = rows[0].get("HostConfig", {}).get("PortBindings", {})
    if not isinstance(bindings, dict):
        raise ProbeError("Docker inspect missing HostConfig.PortBindings")
    return not bindings.get(f"{ADMIN_PORT}/tcp")


def api_json(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        path,
        method=method,
        payload=payload,
        open_token=token,
        timeout=30,
    )
    return require_ret_zero(status, response, f"{method} {path}")


def stun_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    payload = api_json(base_url, token, "/api/stunrulelist")
    rows = payload.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("STUN rule list has unexpected shape")
    return rows


def rule_key(row: dict[str, Any]) -> str:
    value = row.get("Key")
    return value if isinstance(value, str) else ""


def wait_for_owned_rule(base_url: str, token: str, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        matches = [row for row in stun_rows(base_url, token) if row.get("Name") == name]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ProbeError("duplicate TEST STUN rules appeared")
        time.sleep(0.4)
    raise ProbeError("TEST STUN rule did not appear")


def choose_udp_port(bind_ip: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_ip, 0))
        return int(sock.getsockname()[1])


class UdpEchoServer:
    def __init__(self, bind_ip: str) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((bind_ip, 0))
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self.stop_event = threading.Event()
        self.request_count = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, address = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.request_count += 1
            try:
                self.socket.sendto(payload, address)
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class StunBindingServer:
    def __init__(self, bind_ip: str, public_ip: str) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((bind_ip, 0))
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self.stop_event = threading.Event()
        self.request_count = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.public_ip = ipaddress.IPv4Address(public_ip)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        cookie_bytes = STUN_COOKIE.to_bytes(4, "big")
        while not self.stop_event.is_set():
            try:
                payload, address = self.socket.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(payload) < 20:
                continue
            message_type, _length, cookie = struct.unpack("!HHI", payload[:8])
            if message_type != 0x0001 or cookie != STUN_COOKIE:
                continue
            transaction_id = payload[8:20]
            source_port = int(address[1])
            xor_port = source_port ^ (STUN_COOKIE >> 16)
            xor_ip = bytes(a ^ b for a, b in zip(self.public_ip.packed, cookie_bytes))
            attribute = struct.pack("!HHBBH4s", 0x0020, 8, 0, 1, xor_port, xor_ip)
            response = struct.pack("!HHI12s", 0x0101, len(attribute), STUN_COOKIE, transaction_id) + attribute
            self.request_count += 1
            try:
                self.socket.sendto(response, address)
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class UdpMappingForwarder:
    """One owned NAT-PMP-style UDP mapping between isolated WAN and Lucky LAN."""

    def __init__(
        self,
        *,
        public_ip: str,
        external_port: int,
        lan_ip: str,
        lucky_ip: str,
        internal_port: int,
    ) -> None:
        self.public_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.public_socket.bind((public_ip, external_port))
        self.public_socket.setblocking(False)
        self.lan_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.lan_socket.bind((lan_ip, 0))
        self.lan_socket.setblocking(False)
        self.lucky_ip = lucky_ip
        self.internal_port = internal_port
        self.stop_event = threading.Event()
        self.external_peer: tuple[str, int] | None = None
        self.forward_count = 0
        self.return_count = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                readable, _writable, _errors = select.select(
                    [self.public_socket, self.lan_socket], [], [], 0.2
                )
            except (OSError, ValueError):
                break
            for ready in readable:
                try:
                    payload, address = ready.recvfrom(65535)
                except (BlockingIOError, OSError):
                    continue
                try:
                    if ready is self.public_socket:
                        self.external_peer = (str(address[0]), int(address[1]))
                        self.lan_socket.sendto(payload, (self.lucky_ip, self.internal_port))
                        self.forward_count += 1
                    elif self.external_peer is not None:
                        self.public_socket.sendto(payload, self.external_peer)
                        self.return_count += 1
                except OSError:
                    self.stop_event.set()
                    break

    def close(self) -> None:
        self.stop_event.set()
        self.public_socket.close()
        self.lan_socket.close()
        self.thread.join(timeout=2)


class NatPmpGateway:
    def __init__(
        self,
        gateway_ip: str,
        lucky_ip: str,
        *,
        public_ip: str,
    ) -> None:
        self.gateway_ip = gateway_ip
        self.lucky_ip = lucky_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((gateway_ip, NATPMP_PORT))
        self.socket.settimeout(0.2)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.public_ip = ipaddress.IPv4Address(public_ip)
        self.started_at = time.monotonic()
        self.public_address_requests = 0
        self.add_requests = 0
        self.delete_requests = 0
        self.last_internal_port = 0
        self.last_requested_external_port = 0
        self.last_external_port = 0
        self.last_protocol_opcode = 0
        self.add_event = threading.Event()
        self.delete_event = threading.Event()
        self.forwarder: UdpMappingForwarder | None = None
        self.lock = threading.Lock()

    def start(self) -> None:
        self.thread.start()

    def _epoch(self) -> int:
        return max(1, int(time.monotonic() - self.started_at))

    def _choose_external_port(self, requested: int, internal: int) -> int:
        for candidate in (requested, internal):
            if candidate <= 0 or candidate == NATPMP_PORT:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind((str(self.public_ip), candidate))
                except OSError:
                    continue
            return candidate
        return choose_udp_port(str(self.public_ip))

    def _replace_forwarder(self, external_port: int, internal_port: int) -> None:
        if self.forwarder is not None:
            self.forwarder.close()
        forwarder = UdpMappingForwarder(
            public_ip=str(self.public_ip),
            external_port=external_port,
            lan_ip=self.gateway_ip,
            lucky_ip=self.lucky_ip,
            internal_port=internal_port,
        )
        forwarder.start()
        self.forwarder = forwarder

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, address = self.socket.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(payload) < 2 or payload[0] != 0:
                continue
            opcode = int(payload[1])
            if opcode == 0 and len(payload) >= 2:
                self.public_address_requests += 1
                response = struct.pack(
                    "!BBHI4s",
                    0,
                    128,
                    0,
                    self._epoch(),
                    self.public_ip.packed,
                )
                try:
                    self.socket.sendto(response, address)
                except OSError:
                    break
                continue
            if opcode not in (1, 2) or len(payload) < 12:
                continue
            _version, _opcode, _reserved, internal_port, requested_external, lifetime = struct.unpack(
                "!BBHHHI", payload[:12]
            )
            with self.lock:
                self.last_protocol_opcode = opcode
                self.last_internal_port = internal_port
                self.last_requested_external_port = requested_external
                if lifetime == 0:
                    self.delete_requests += 1
                    external_port = self.last_external_port or requested_external or internal_port
                    if self.forwarder is not None:
                        self.forwarder.close()
                        self.forwarder = None
                    self.delete_event.set()
                else:
                    self.add_requests += 1
                    external_port = self._choose_external_port(requested_external, internal_port)
                    self._replace_forwarder(external_port, internal_port)
                    self.last_external_port = external_port
                    self.add_event.set()
            response = struct.pack(
                "!BBHIHHI",
                0,
                opcode | 0x80,
                0,
                self._epoch(),
                internal_port,
                external_port,
                0 if lifetime == 0 else min(int(lifetime), 120),
            )
            try:
                self.socket.sendto(response, address)
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)
        with self.lock:
            if self.forwarder is not None:
                self.forwarder.close()
                self.forwarder = None


def rule_options() -> dict[str, Any]:
    return {
        # The TEST target lives on the Docker-bridge gateway itself. Disable
        # Lucky's self-forwarding guard for this owned isolated rule so that
        # the synthetic topology is not mistaken for an unsafe loop.
        "DisableSelfForwardingCheck": True,
        "SingleProxyMaxTCPConnections": 64,
        "SingleProxyMaxUDPReadTargetDatagoroutineCount": 16,
        "UDPShortMode": False,
        "SafeMode": "blacklist",
        "SecurityGroupKeys": [],
        "SecurityGroupAccessMode": "disabled",
        "SecurityGroupRefreshOnTraffic": False,
        "TCPListenTLS": False,
        "TCPRelayTLS": False,
        "TCPRelayTLSServerName": "",
        "TCPRelayTLSInsecureSkipVerify": False,
        "TCPAcceptProxyProtocolV2": False,
        "TCPProxyProtocolV2": False,
        "TCPStreamEncryptionSource": False,
        "TCPStreamEncryptionAccept": False,
        "TCPStreamEncryptionKey": "",
        "SinglePortSpeedLimit": False,
        "SinglePortSendSpeedLimit": 0,
        "SinglePortReceSpeedLimit": 0,
        "RuleSpeedLimit": False,
        "RuleSendSpeedLimit": 0,
        "RuleReceSpeedLimit": 0,
        "UDPSessionTimeout": 30000,
        "UDPPacketSourceEncryption": False,
        "UDPPacketAcceptEncryption": False,
        "UDPPacketEncryptionKey": "",
        "UDPPacketSize": 1500,
    }


def rule_payload(
    name: str,
    lucky_ip: str,
    listen_port: int,
    gateway_ip: str,
    stun_port: int,
    target_port: int,
) -> dict[str, Any]:
    return {
        "Name": name,
        "Key": "",
        "Enable": True,
        "UseGlobalStunServerList": False,
        "DiaglogShowMode": "simple",
        "StunHeartbeatInterval": 2300,
        "StunTimeout": 1500,
        "StunRetryInterval": 1000,
        "StunAutoRetry": True,
        "AutoAddPubAddrWhiteList": False,
        "StunType": "udp4",
        "StunListenType": "ip",
        "SpecifyNetworkInterface": "",
        "NetworkInterfaceReg": "",
        "ListenIP": lucky_ip,
        "AutoOptionsFirewall": False,
        "ListenPort": listen_port,
        "NatPMP": True,
        "UPnPGawayIP": "",
        "NatPMPGateway": gateway_ip,
        "UPnP": False,
        "UPnPLocalPort": 0,
        "UPnpLocalHost": "",
        "UPnPInternalClientIP": "",
        "UpnPDiyControlAPIUrl": "",
        # The CI STUN responder intentionally advertises a documentation-range
        # public address on a Docker --internal network. Disable Lucky's
        # external reachability check so the test exercises the isolated UDP
        # forwarding data plane instead of requiring an Internet-routable IP.
        "DisableStunAvalidCheck": True,
        "DisablePortForward": False,
        "TargetAddressList": [gateway_ip],
        "TargetPort": target_port,
        "LogLevel": 4,
        "LogOutputToConsole": False,
        "AccessLogMaxNum": 128,
        "WebListShowLastLogMaxCount": 20,
        "Options": rule_options(),
        "StunServerList": [f"{gateway_ip}:{stun_port}"],
        "TcpKeepAliveServerList": [],
        "GlobalWebhook": False,
        "WebhookEnable": False,
        "WebhookOnlyAddrChange": True,
        "WebhookURL": "",
        "WebhookMethod": "",
        "WebhookHeaders": [],
        "WebhookRequestBody": "",
        "WebhookDisableCallbackSuccessContentCheck": False,
        "WebhookSuccessContent": [],
        "WebhookProxy": "",
        "WebhookProxyAddr": "",
        "WebhookProxyUser": "",
        "WebhookProxyPassword": "",
        "CallScript": False,
        "CallScriptContent": "",
        "RetryCount": 0,
        "RetryInterval": 500,
        "LogStreamSettings": {},
    }


def wait_event(event: threading.Event, label: str, timeout: float = 20.0) -> None:
    if not event.wait(timeout):
        raise ProbeError(f"timed out waiting for {label}")


def contains_string(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(contains_string(item, needle) for item in value.values())
    if isinstance(value, list):
        return any(contains_string(item, needle) for item in value)
    return False


def wait_runtime_stun_endpoint(
    base_url: str,
    token: str,
    key: str,
    public_ip: str,
    *,
    timeout: float = 12.0,
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        listing = api_json(base_url, token, "/api/stunrulelist")
        rows = listing.get("list") or []
        owned = [
            row
            for row in rows
            if isinstance(row, dict) and rule_key(row) == key
        ]
        if contains_string(owned, public_ip):
            return True
        logs = api_json(base_url, token, f"/api/stun/{key}/lastlogs")
        if contains_string(logs, public_ip):
            return True
        time.sleep(0.4)
    return False


def setup_wan_namespace(namespace: str, host_veth: str, ns_veth: str) -> None:
    run(["ip", "netns", "add", namespace], timeout=20)
    try:
        run(
            ["ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth],
            timeout=20,
        )
        run(["ip", "link", "set", ns_veth, "netns", namespace], timeout=20)
        run(
            ["ip", "addr", "add", f"{TEST_WAN_GATEWAY}/{TEST_WAN_PREFIX}", "dev", host_veth],
            timeout=20,
        )
        run(["ip", "link", "set", host_veth, "up"], timeout=20)
        run(["ip", "-n", namespace, "link", "set", "lo", "up"], timeout=20)
        run(
            [
                "ip", "-n", namespace, "addr", "add",
                f"{TEST_WAN_CLIENT}/{TEST_WAN_PREFIX}", "dev", ns_veth,
            ],
            timeout=20,
        )
        run(["ip", "-n", namespace, "link", "set", ns_veth, "up"], timeout=20)
        run(
            ["ip", "-n", namespace, "route", "add", "default", "via", TEST_WAN_GATEWAY],
            timeout=20,
        )
    except Exception:
        run(["ip", "netns", "del", namespace], check=False, timeout=20)
        run(["ip", "link", "del", host_veth], check=False, timeout=20)
        raise


def cleanup_wan_namespace(namespace: str, host_veth: str) -> None:
    run(["ip", "netns", "del", namespace], check=False, timeout=20)
    run(["ip", "link", "del", host_veth], check=False, timeout=20)


def namespace_udp_roundtrip(
    namespace: str,
    host: str,
    port: int,
    marker: bytes,
) -> tuple[bool, int, str]:
    code = (
        "import socket,sys;"
        "m=bytes.fromhex(sys.argv[1]);"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.settimeout(8);"
        "\ntry:\n"
        " s.connect((sys.argv[2],int(sys.argv[3]))); s.send(m); d=s.recv(65535);"
        " sys.exit(0 if d==m else 7)\n"
        "except Exception as e:\n"
        " print(type(e).__name__+':'+str(e),file=sys.stderr); sys.exit(8)"
    )
    result = run(
        [
            "ip", "netns", "exec", namespace,
            sys.executable, "-c", code,
            marker.hex(), host, str(port),
        ],
        check=False,
        timeout=15,
    )
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    if "network is unreachable" in stderr:
        failure_kind = "unreachable"
    elif "connection refused" in stderr:
        failure_kind = "refused"
    elif "timed out" in stderr or "timeouterror" in stderr:
        failure_kind = "timeout"
    elif result.returncode == 0:
        failure_kind = ""
    else:
        failure_kind = "other"
    return result.returncode == 0, int(result.returncode), failure_kind


def direct_udp_roundtrip(
    source_ip: str,
    lucky_ip: str,
    listen_port: int,
    marker: bytes,
) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((source_ip, 0))
        client.settimeout(5)
        client.sendto(marker, (lucky_ip, listen_port))
        try:
            response, _address = client.recvfrom(65535)
        except socket.timeout:
            return False
    return response == marker


def safe_log_samples(payload: Any, public_ip: str, limit: int = 8) -> list[str]:
    samples: list[str] = []

    def visit(value: Any) -> None:
        if len(samples) >= limit:
            return
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return
            lowered = text.lower()
            if not any(
                keyword in lowered
                for keyword in ("stun", "nat", "forward", "listen", "target", "udp", "error", "fail")
            ):
                return
            text = text.replace(public_ip, "<test-public-ip>")
            text = text[:240]
            if text not in samples:
                samples.append(text)
            return
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return samples


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if os.geteuid() != 0:
        raise ProbeError("isolated NAT-PMP probe requires sudo/root on the ephemeral GitHub runner")
    required_commands = ("docker", "openssl", "ip")
    missing = [command for command in required_commands if shutil.which(command) is None]
    if missing:
        raise ProbeError(f"missing required GitHub-runner commands: {', '.join(missing)}")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-natpmp-ci-{nonce}"
    network_name = f"lucky-natpmp-ci-{nonce}"
    bridge_name = f"lnat-{nonce[:8]}"
    wan_namespace = f"lnat-wan-{nonce}"
    wan_host_veth = f"lnh{nonce[:8]}"
    wan_ns_veth = f"lnn{nonce[:8]}"
    rule_name = TEST_PREFIX + nonce
    open_token = secrets.token_hex(16)
    marker = secrets.token_bytes(32)

    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_lucky_operations": True,
        "runner_root": True,
        "network_internal": False,
        "wan_namespace_isolated": False,
        "wan_client_route_ok": False,
        "wan_gateway_roundtrip": False,
        "admin_port_unpublished": False,
        "admin_reachable_on_internal_bridge": False,
        "baseline_empty": False,
        "stun_module_present": False,
        "module_transient_not_ready_observed": False,
        "module_enabled_for_probe": False,
        "module_baseline_restored": False,
        "rule_created": False,
        "rule_natpmp_enabled": False,
        "rule_upnp_disabled": False,
        "rule_firewall_automation_disabled": False,
        "fake_stun_used": False,
        "runtime_stun_endpoint_observed": False,
        "natpmp_public_address_request_seen": False,
        "natpmp_udp_add_seen": False,
        "natpmp_internal_port_matches_listener": False,
        "natpmp_mapping_installed": False,
        "mapping_forward_count": 0,
        "mapping_return_count": 0,
        "direct_listener_roundtrip": False,
        "mapped_data_roundtrip": False,
        "mapped_client_returncode": 0,
        "mapped_client_failure_kind": "",
        "mapped_echo_target_used": False,
        "echo_target_used": False,
        "rule_log_surface_read": False,
        "rule_log_samples": [],
        "rule_disabled": False,
        "natpmp_delete_seen": False,
        "mapping_removed": False,
        "rule_deleted": False,
        "baseline_restored": False,
        "upnp_exercised": False,
        "internet_route_required": False,
    }

    with tempfile.TemporaryDirectory(prefix="lucky-natpmp-ci-", dir=runner_temp) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        conf_dir = temp_dir / "conf"
        conf_dir.mkdir()
        pull_pinned_image()
        run(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--opt",
                f"com.docker.network.bridge.name={bridge_name}",
                network_name,
            ],
            timeout=45,
        )
        try:
            setup_wan_namespace(wan_namespace, wan_host_veth, wan_ns_veth)
            report["wan_namespace_isolated"] = True
        except Exception:
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            raise
        stun_server: StunBindingServer | None = None
        echo_server: UdpEchoServer | None = None
        wan_echo_server: UdpEchoServer | None = None
        natpmp: NatPmpGateway | None = None
        base_url = ""
        created_key = ""
        module_baseline: dict[str, Any] | None = None
        module_changed = False

        try:
            gateway_ip, _subnet = docker_network_values(network_name)
            report["network_internal"] = True

            route_check = run(
                ["ip", "-n", wan_namespace, "route", "get", TEST_WAN_GATEWAY],
                check=False,
                timeout=20,
            )
            report["wan_client_route_ok"] = route_check.returncode == 0
            wan_echo_server = UdpEchoServer(TEST_WAN_GATEWAY)
            wan_echo_server.start()
            wan_ok, _wan_rc, _wan_failure = namespace_udp_roundtrip(
                wan_namespace,
                TEST_WAN_GATEWAY,
                wan_echo_server.port,
                marker,
            )
            report["wan_gateway_roundtrip"] = wan_ok

            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                network_name,
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            lucky_ip = container_ipv4(container_name, network_name)
            base_url = f"http://{lucky_ip}:{ADMIN_PORT}"
            wait_for_lucky(base_url, container_name)
            report["admin_port_unpublished"] = admin_port_is_unpublished(container_name)
            report["admin_reachable_on_internal_bridge"] = True
            if not report["admin_port_unpublished"]:
                raise ProbeError("temporary Lucky admin port was unexpectedly published")

            stun_server = StunBindingServer(gateway_ip, TEST_WAN_GATEWAY)
            echo_server = UdpEchoServer(gateway_ip)
            natpmp = NatPmpGateway(
                gateway_ip,
                lucky_ip,
                public_ip=TEST_WAN_GATEWAY,
            )
            stun_server.start()
            echo_server.start()
            natpmp.start()

            admin_token = login_default_admin(base_url, temp_dir)
            enable_open_token(base_url, admin_token, open_token)
            info = api_json(base_url, open_token, "/api/info")
            info_object = info.get("info")
            if not isinstance(info_object, dict):
                raise ProbeError("Lucky info response missing info object")
            version = str(info_object.get("Version") or "")
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {version!r}")

            modules_response = api_json(base_url, open_token, "/api/modules/list")
            modules = modules_response.get("Modules")
            report["stun_module_present"] = isinstance(modules, list) and "stun" in modules
            if not report["stun_module_present"]:
                raise ProbeError("fresh Lucky module list does not contain STUN")

            opener = urllib.request.build_opener()
            configure: dict[str, Any] | None = None
            deadline = time.time() + 35
            while time.time() < deadline:
                config_status, module_response = json_request(
                    opener,
                    base_url,
                    "/api/stun/configure",
                    open_token=open_token,
                    timeout=10,
                )
                if config_status != 200:
                    raise ProbeError(f"STUN configure GET returned HTTP {config_status}")
                if module_response.get("ret") == 0:
                    candidate_config = module_response.get("configure")
                    if not isinstance(candidate_config, dict):
                        raise ProbeError("STUN module configure response missing configure object")
                    configure = candidate_config
                    break
                if module_response.get("ret") != -10:
                    raise ProbeError(
                        f"unexpected STUN configure ret={module_response.get('ret')!r}"
                    )
                report["module_transient_not_ready_observed"] = True
                time.sleep(1)
            if configure is None:
                raise ProbeError("STUN module did not become ready after transient ret=-10")

            module_baseline = copy.deepcopy(configure)
            if configure.get("EnableModule") is not True:
                candidate = copy.deepcopy(configure)
                candidate["EnableModule"] = True
                candidate.setdefault("WebhookProxyPassword", "")
                api_json(
                    base_url,
                    open_token,
                    "/api/stun/configure",
                    method="PUT",
                    payload=candidate,
                )
                module_changed = True
            live_module = api_json(base_url, open_token, "/api/stun/configure").get("configure")
            report["module_enabled_for_probe"] = (
                isinstance(live_module, dict) and live_module.get("EnableModule") is True
            )
            if not report["module_enabled_for_probe"]:
                raise ProbeError("STUN module did not become enabled in disposable Lucky")

            # Fresh Lucky returns ret=-10 from /api/stunrulelist while the STUN
            # module is disabled, so establish the rule baseline only after the
            # disposable module has been enabled through its API.
            baseline_keys = {rule_key(row) for row in stun_rows(base_url, open_token) if rule_key(row)}
            report["baseline_empty"] = not baseline_keys
            if not report["baseline_empty"]:
                raise ProbeError("fresh Lucky STUN rule baseline was not empty")

            listen_port = 20000 + secrets.randbelow(25000)
            create = api_json(
                base_url,
                open_token,
                "/api/stunrule",
                method="POST",
                payload=rule_payload(
                    rule_name,
                    lucky_ip,
                    listen_port,
                    gateway_ip,
                    stun_server.port,
                    echo_server.port,
                ),
            )
            created_key_value = create.get("key") or create.get("Key")
            if isinstance(created_key_value, str):
                created_key = created_key_value
            row = wait_for_owned_rule(base_url, open_token, rule_name)
            created_key = created_key or rule_key(row)
            if not created_key or created_key in baseline_keys:
                raise ProbeError("disposable STUN rule did not receive a unique Key")
            report["rule_created"] = True

            detail = api_json(base_url, open_token, f"/api/stun/{created_key}").get("rule")
            if not isinstance(detail, dict):
                raise ProbeError("STUN rule detail response missing rule object")
            report["rule_natpmp_enabled"] = (
                detail.get("NatPMP") is True and detail.get("NatPMPGateway") == gateway_ip
            )
            report["rule_upnp_disabled"] = detail.get("UPnP") is False
            report["rule_firewall_automation_disabled"] = detail.get("AutoOptionsFirewall") is False

            wait_event(natpmp.add_event, "NAT-PMP add mapping")
            deadline = time.time() + 8
            while time.time() < deadline and stun_server.request_count == 0:
                time.sleep(0.1)
            report["fake_stun_used"] = stun_server.request_count > 0
            report["natpmp_public_address_request_seen"] = natpmp.public_address_requests > 0
            report["natpmp_udp_add_seen"] = (
                natpmp.add_requests > 0 and natpmp.last_protocol_opcode == 1
            )
            report["natpmp_internal_port_matches_listener"] = natpmp.last_internal_port == listen_port
            external_port = natpmp.last_external_port
            report["natpmp_mapping_installed"] = (
                external_port > 0 and natpmp.forwarder is not None
            )
            if not report["natpmp_mapping_installed"]:
                raise ProbeError("fake NAT-PMP gateway did not install the UDP mapping")

            report["runtime_stun_endpoint_observed"] = wait_runtime_stun_endpoint(
                base_url,
                open_token,
                created_key,
                TEST_WAN_GATEWAY,
            )

            report["direct_listener_roundtrip"] = direct_udp_roundtrip(
                gateway_ip,
                lucky_ip,
                listen_port,
                marker,
            )

            echo_before_mapped = echo_server.request_count
            mapped_ok, mapped_returncode, mapped_failure_kind = namespace_udp_roundtrip(
                wan_namespace,
                TEST_WAN_GATEWAY,
                external_port,
                marker,
            )
            report["mapped_data_roundtrip"] = mapped_ok
            report["mapped_client_returncode"] = mapped_returncode
            report["mapped_client_failure_kind"] = mapped_failure_kind
            report["mapped_echo_target_used"] = echo_server.request_count > echo_before_mapped
            if natpmp.forwarder is not None:
                report["mapping_forward_count"] = natpmp.forwarder.forward_count
                report["mapping_return_count"] = natpmp.forwarder.return_count
            report["echo_target_used"] = echo_server.request_count > 0

            logs = api_json(base_url, open_token, f"/api/stun/{created_key}/lastlogs")
            report["rule_log_surface_read"] = logs.get("ret") == 0
            report["rule_log_samples"] = safe_log_samples(logs, TEST_WAN_GATEWAY)

            query = urllib.parse.urlencode({"key": created_key, "enable": "false"})
            api_json(base_url, open_token, f"/api/stunrule/enable?{query}")
            report["rule_disabled"] = True
            if not natpmp.delete_event.wait(8):
                delete_query = urllib.parse.urlencode({"key": created_key})
                api_json(base_url, open_token, f"/api/stunrule?{delete_query}", method="DELETE")
                created_key = ""
                report["rule_deleted"] = True
                natpmp.delete_event.wait(5)
            report["natpmp_delete_seen"] = natpmp.delete_requests > 0
            report["mapping_removed"] = natpmp.forwarder is None

            if created_key:
                delete_query = urllib.parse.urlencode({"key": created_key})
                api_json(base_url, open_token, f"/api/stunrule?{delete_query}", method="DELETE")
                created_key = ""
                report["rule_deleted"] = True
            final_keys = {rule_key(row) for row in stun_rows(base_url, open_token) if rule_key(row)}
            report["baseline_restored"] = final_keys == baseline_keys

            if module_changed:
                if module_baseline is not None:
                    restore = copy.deepcopy(module_baseline)
                    restore.setdefault("WebhookProxyPassword", "")
                    api_json(
                        base_url,
                        open_token,
                        "/api/stun/configure",
                        method="PUT",
                        payload=restore,
                    )
                    module_changed = False
                    restored_module = api_json(
                        base_url,
                        open_token,
                        "/api/stun/configure",
                    ).get("configure")
                    report["module_baseline_restored"] = (
                        isinstance(restored_module, dict)
                        and restored_module.get("EnableModule") == module_baseline.get("EnableModule")
                    )
            else:
                report["module_baseline_restored"] = True
        finally:
            if created_key and base_url:
                query = urllib.parse.urlencode({"key": created_key})
                try:
                    api_json(base_url, open_token, f"/api/stunrule/enable?{urllib.parse.urlencode({'key': created_key, 'enable': 'false'})}")
                except Exception:  # noqa: BLE001 - disposable teardown safety net
                    pass
                try:
                    api_json(base_url, open_token, f"/api/stunrule?{query}", method="DELETE")
                except Exception:  # noqa: BLE001 - disposable teardown safety net
                    pass
            if module_changed and base_url:
                try:
                    if module_baseline is not None:
                        restore = copy.deepcopy(module_baseline)
                        restore.setdefault("WebhookProxyPassword", "")
                    else:
                        restore = None
                    if restore is None:
                        raise ProbeError("missing STUN module restore payload")
                    api_json(
                        base_url,
                        open_token,
                        "/api/stun/configure",
                        method="PUT",
                        payload=restore,
                    )
                except Exception:  # noqa: BLE001 - disposable teardown safety net
                    pass
            if natpmp is not None:
                natpmp.close()
            if stun_server is not None:
                stun_server.close()
            if echo_server is not None:
                echo_server.close()
            if wan_echo_server is not None:
                wan_echo_server.close()
            cleanup_wan_namespace(wan_namespace, wan_host_veth)
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "api_only_lucky_operations",
        "runner_root",
        "network_internal",
        "wan_namespace_isolated",
        "wan_client_route_ok",
        "wan_gateway_roundtrip",
        "admin_port_unpublished",
        "admin_reachable_on_internal_bridge",
        "baseline_empty",
        "stun_module_present",
        "module_enabled_for_probe",
        "module_baseline_restored",
        "rule_created",
        "rule_natpmp_enabled",
        "rule_upnp_disabled",
        "rule_firewall_automation_disabled",
        "fake_stun_used",
        "runtime_stun_endpoint_observed",
        "natpmp_udp_add_seen",
        "natpmp_internal_port_matches_listener",
        "natpmp_mapping_installed",
        "direct_listener_roundtrip",
        "mapped_data_roundtrip",
        "mapped_echo_target_used",
        "echo_target_used",
        "rule_log_surface_read",
        "rule_disabled",
        "natpmp_delete_seen",
        "mapping_removed",
        "rule_deleted",
        "baseline_restored",
    )
    failed = [key for key in required_true if report.get(key) is not True]
    if int(report.get("mapping_forward_count") or 0) <= 0:
        failed.append("mapping_forward_count")
    if int(report.get("mapping_return_count") or 0) <= 0:
        failed.append("mapping_return_count")
    if report.get("lucky_version") != EXPECTED_LUCKY_VERSION:
        failed.append("lucky_version")
    if report.get("upnp_exercised") is not False:
        failed.append("upnp_exercised")
    if report.get("internet_route_required") is not False:
        failed.append("internet_route_required")
    print(json.dumps({**report, "failed": failed}, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

