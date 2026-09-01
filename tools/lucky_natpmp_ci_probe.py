#!/usr/bin/env python3
"""Runtime-verify Lucky 3.0.0 NAT-PMP mapping on an isolated CI bridge.

The probe is intentionally GitHub-Actions-only. It starts a fresh pinned Lucky
container on a Docker ``--internal`` bridge and runs three tiny stdlib UDP
fixtures bound only to that bridge's host gateway address:

* a STUN Binding responder;
* a NAT-PMP gateway on the standard UDP/5351 port;
* a UDP echo target behind the Lucky STUN rule.

Lucky is configured exclusively through its HTTP API. A temporary UDP STUN
rule must ask the fake gateway for a NAT-PMP mapping, and the fake gateway
installs an in-process UDP relay for the returned external port. A client bound
to the same isolated bridge gateway then sends a random marker through the
mapped port; the bytes must travel gateway -> Lucky -> echo target -> Lucky ->
gateway and return exactly. Disabling/deleting the TEST rule must also produce
the NAT-PMP lifetime=0 deletion request.

No production Lucky instance, physical interface, firewall, router, public
STUN server, UPnP device or Internet route is involved.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import secrets
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
    def __init__(self, bind_ip: str) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((bind_ip, 0))
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self.stop_event = threading.Event()
        self.request_count = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.public_ip = ipaddress.IPv4Address("198.51.100.42")

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
    def __init__(self, gateway_ip: str, external_port: int, lucky_ip: str, internal_port: int) -> None:
        self.gateway_ip = gateway_ip
        self.external_port = external_port
        self.lucky_ip = lucky_ip
        self.internal_port = internal_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((gateway_ip, external_port))
        self.socket.settimeout(0.2)
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
                payload, address = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if address[0] == self.lucky_ip:
                    if self.external_peer is not None:
                        self.socket.sendto(payload, self.external_peer)
                        self.return_count += 1
                else:
                    self.external_peer = (str(address[0]), int(address[1]))
                    self.socket.sendto(payload, (self.lucky_ip, self.internal_port))
                    self.forward_count += 1
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class NatPmpGateway:
    def __init__(self, gateway_ip: str, lucky_ip: str) -> None:
        self.gateway_ip = gateway_ip
        self.lucky_ip = lucky_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((gateway_ip, NATPMP_PORT))
        self.socket.settimeout(0.2)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.public_ip = ipaddress.IPv4Address("198.51.100.42")
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
                    probe.bind((self.gateway_ip, candidate))
                except OSError:
                    continue
            return candidate
        return choose_udp_port(self.gateway_ip)

    def _replace_forwarder(self, external_port: int, internal_port: int) -> None:
        if self.forwarder is not None:
            self.forwarder.close()
        forwarder = UdpMappingForwarder(
            self.gateway_ip,
            external_port,
            self.lucky_ip,
            internal_port,
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
        "DisableSelfForwardingCheck": False,
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


def mapped_udp_roundtrip(gateway_ip: str, external_port: int, marker: bytes) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((gateway_ip, 0))
        client.settimeout(8)
        client.sendto(marker, (gateway_ip, external_port))
        try:
            response, _address = client.recvfrom(65535)
        except socket.timeout:
            return False
    return response == marker


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise ProbeError("docker and openssl are required on the GitHub runner")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-natpmp-ci-{nonce}"
    network_name = f"lucky-natpmp-ci-{nonce}"
    bridge_name = f"lnat-{nonce[:8]}"
    rule_name = TEST_PREFIX + nonce
    open_token = secrets.token_hex(16)
    marker = secrets.token_bytes(32)

    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_lucky_operations": True,
        "network_internal": False,
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
        "natpmp_public_address_request_seen": False,
        "natpmp_udp_add_seen": False,
        "natpmp_internal_port_matches_listener": False,
        "natpmp_mapping_installed": False,
        "mapped_data_roundtrip": False,
        "echo_target_used": False,
        "rule_log_surface_read": False,
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

        stun_server: StunBindingServer | None = None
        echo_server: UdpEchoServer | None = None
        natpmp: NatPmpGateway | None = None
        base_url = ""
        created_key = ""
        module_baseline: dict[str, Any] | None = None
        module_changed = False

        try:
            gateway_ip, _subnet = docker_network_values(network_name)
            report["network_internal"] = True

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

            stun_server = StunBindingServer(gateway_ip)
            echo_server = UdpEchoServer(gateway_ip)
            natpmp = NatPmpGateway(gateway_ip, lucky_ip)
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

            report["mapped_data_roundtrip"] = mapped_udp_roundtrip(
                gateway_ip,
                external_port,
                marker,
            )
            report["echo_target_used"] = echo_server.request_count > 0

            logs = api_json(base_url, open_token, f"/api/stun/{created_key}/lastlogs")
            report["rule_log_surface_read"] = logs.get("ret") == 0

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
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "api_only_lucky_operations",
        "network_internal",
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
        "natpmp_udp_add_seen",
        "natpmp_internal_port_matches_listener",
        "natpmp_mapping_installed",
        "mapped_data_roundtrip",
        "echo_target_used",
        "rule_log_surface_read",
        "rule_disabled",
        "natpmp_delete_seen",
        "mapping_removed",
        "rule_deleted",
        "baseline_restored",
    )
    failed = [key for key in required_true if report.get(key) is not True]
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

