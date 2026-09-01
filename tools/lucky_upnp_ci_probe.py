#!/usr/bin/env python3
"""Runtime-verify Lucky 3.0.0 UPnP IGD UDP mapping in isolated CI.

The probe is GitHub-Actions-only. Lucky runs on a Docker ``--internal`` LAN;
an independent veth-backed network namespace acts as a synthetic WAN.  A tiny
stdlib UPnP IGD v1 fixture is bound only to the owned Docker bridge and exposes
SSDP discovery plus the minimum WANIPConnection SOAP actions needed for a UDP
port mapping.  AddPortMapping creates an owned userspace UDP mapping relay on
the synthetic WAN address; DeletePortMapping removes it.

Lucky configuration changes exclusively through Lucky HTTP APIs.  No
production Lucky instance, real router, Internet route, iptables, sysctl,
physical NIC or public STUN service is touched.
"""

from __future__ import annotations

import copy
import http.server
import ipaddress
import json
import os
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
import xml.etree.ElementTree as ET
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
from lucky_natpmp_ci_probe import (
    TEST_WAN_CLIENT,
    TEST_WAN_GATEWAY,
    TEST_WAN_PREFIX,
    StunBindingServer,
    UdpEchoServer,
    UdpMappingForwarder,
    cleanup_wan_namespace,
    namespace_udp_roundtrip,
    setup_wan_namespace,
)


TEST_PREFIX = "TEST-lucky-skills-upnp-ci-"
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SERVICE_TYPE = "urn:schemas-upnp-org:service:WANIPConnection:1"
DEVICE_TYPE = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"


def docker_network_values(network_name: str) -> tuple[str, str]:
    rows = json.loads(docker("network", "inspect", network_name, timeout=30))
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
    rows = json.loads(docker("inspect", container_name, timeout=30))
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    networks = rows[0].get("NetworkSettings", {}).get("Networks", {})
    item = networks.get(network_name) if isinstance(networks, dict) else None
    value = item.get("IPAddress") if isinstance(item, dict) else None
    if not isinstance(value, str) or not value:
        raise ProbeError("temporary Lucky container has no internal-network IPv4")
    socket.inet_aton(value)
    return value


def admin_port_is_unpublished(container_name: str) -> bool:
    rows = json.loads(docker("inspect", container_name, timeout=30))
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    bindings = rows[0].get("HostConfig", {}).get("PortBindings", {})
    return isinstance(bindings, dict) and not bindings.get(f"{ADMIN_PORT}/tcp")


def api_json(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status, response = json_request(
        urllib.request.build_opener(),
        base_url,
        path,
        method=method,
        payload=payload,
        open_token=token,
        timeout=30,
    )
    return require_ret_zero(status, response, f"{method} {path}")


def stun_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    rows = api_json(base_url, token, "/api/stunrulelist").get("list") or []
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


def wait_contains(base_url: str, token: str, key: str, needle: str, timeout: float = 12.0) -> bool:
    def contains(value: Any) -> bool:
        if isinstance(value, str):
            return needle in value
        if isinstance(value, dict):
            return any(contains(item) for item in value.values())
        if isinstance(value, list):
            return any(contains(item) for item in value)
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        if contains(api_json(base_url, token, f"/api/stun/{key}/lastlogs")):
            return True
        if contains(api_json(base_url, token, "/api/stunrulelist")):
            return True
        time.sleep(0.4)
    return False


class IgdHttpServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], gateway: "FakeUpnpIgd") -> None:
        self.gateway = gateway
        super().__init__(server_address, IgdHandler)


class IgdHandler(http.server.BaseHTTPRequestHandler):
    server: IgdHttpServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _send_xml(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", 'text/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/wanipconnSCPD.xml":
            self._send_xml(200, self.server.gateway.service_description())
            return
        if self.path not in ("/rootDesc.xml", "/igd.xml"):
            self.send_error(404)
            return
        self.server.gateway.description_requests += 1
        self._send_xml(200, self.server.gateway.device_description())

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length)
        action_header = (self.headers.get("SOAPAction") or "").strip().strip('"')
        action = action_header.rsplit("#", 1)[-1] if "#" in action_header else ""
        if not action:
            try:
                root = ET.fromstring(body)
                action_node = next(iter(next(iter(root))))
                action = action_node.tag.rsplit("}", 1)[-1]
            except Exception:  # noqa: BLE001
                action = ""
        self.server.gateway.soap_actions.append(action or "UNKNOWN")
        try:
            arguments = self.server.gateway.parse_action_arguments(body)
            response = self.server.gateway.handle_action(action, arguments)
        except ProbeError:
            self._send_xml(500, self.server.gateway.soap_fault(501, "Action Failed"))
            return
        self._send_xml(200, response)


class FakeUpnpIgd:
    def __init__(self, lan_ip: str, public_ip: str, lucky_ip: str, bridge_name: str) -> None:
        self.lan_ip = lan_ip
        self.public_ip = public_ip
        self.lucky_ip = lucky_ip
        self.bridge_name = bridge_name
        self.description_requests = 0
        self.ssdp_requests = 0
        self.ssdp_responses = 0
        self.soap_actions: list[str] = []
        self.add_requests = 0
        self.delete_requests = 0
        self.last_external_port = 0
        self.last_internal_port = 0
        self.last_internal_client = ""
        self.last_protocol = ""
        self.forwarder: UdpMappingForwarder | None = None
        self.add_event = threading.Event()
        self.delete_event = threading.Event()
        self.stop_event = threading.Event()
        self.httpd = IgdHttpServer((lan_ip, 0), self)
        self.http_port = int(self.httpd.server_address[1])
        self.http_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.ssdp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_BINDTODEVICE"):
            self.ssdp_socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                bridge_name.encode("utf-8") + b"\x00",
            )
        self.ssdp_socket.bind(("", SSDP_PORT))
        membership = socket.inet_aton(SSDP_ADDR) + socket.inet_aton(lan_ip)
        self.ssdp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        self.ssdp_socket.settimeout(0.2)
        self.ssdp_thread = threading.Thread(target=self._serve_ssdp, daemon=True)

    def start(self) -> None:
        self.http_thread.start()
        self.ssdp_thread.start()

    @property
    def location(self) -> str:
        return f"http://{self.lan_ip}:{self.http_port}/rootDesc.xml"

    def device_description(self) -> str:
        return f'''<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <URLBase>http://{self.lan_ip}:{self.http_port}/</URLBase>
  <device>
    <deviceType>{DEVICE_TYPE}</deviceType>
    <friendlyName>Lucky Skills TEST IGD</friendlyName>
    <manufacturer>Lucky Skills CI</manufacturer>
    <modelName>Disposable IGD</modelName>
    <UDN>uuid:lucky-skills-ci-igd</UDN>
    <deviceList><device>
      <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <friendlyName>WAN Device</friendlyName><manufacturer>CI</manufacturer><modelName>WAN</modelName>
      <UDN>uuid:lucky-skills-ci-wan</UDN>
      <deviceList><device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <friendlyName>WAN Connection</friendlyName><manufacturer>CI</manufacturer><modelName>WANConn</modelName>
        <UDN>uuid:lucky-skills-ci-wanconn</UDN>
        <serviceList><service>
          <serviceType>{SERVICE_TYPE}</serviceType>
          <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
          <SCPDURL>/wanipconnSCPD.xml</SCPDURL>
          <controlURL>/upnp/control/WANIPConn1</controlURL>
          <eventSubURL>/upnp/event/WANIPConn1</eventSubURL>
        </service></serviceList>
      </device></deviceList>
    </device></deviceList>
  </device>
</root>'''

    @staticmethod
    def service_description() -> str:
        return '''<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <actionList>
    <action><name>GetExternalIPAddress</name></action>
    <action><name>GetStatusInfo</name></action>
    <action><name>GetNATRSIPStatus</name></action>
    <action><name>AddPortMapping</name></action>
    <action><name>DeletePortMapping</name></action>
    <action><name>GetSpecificPortMappingEntry</name></action>
  </actionList>
  <serviceStateTable></serviceStateTable>
</scpd>'''

    def _serve_ssdp(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, address = self.ssdp_socket.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            text = payload.decode("utf-8", errors="replace")
            if not text.upper().startswith("M-SEARCH"):
                continue
            self.ssdp_requests += 1
            st = DEVICE_TYPE
            for line in text.splitlines():
                if line.lower().startswith("st:"):
                    st = line.split(":", 1)[1].strip() or DEVICE_TYPE
                    break
            response = (
                "HTTP/1.1 200 OK\r\n"
                "CACHE-CONTROL: max-age=120\r\n"
                f"LOCATION: {self.location}\r\n"
                "SERVER: LuckySkillsCI/1.0 UPnP/1.0 IGD/1.0\r\n"
                f"ST: {st}\r\n"
                "USN: uuid:lucky-skills-ci-igd::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                "EXT:\r\n\r\n"
            ).encode("ascii")
            try:
                self.ssdp_socket.sendto(response, address)
                self.ssdp_responses += 1
            except OSError:
                break

    @staticmethod
    def parse_action_arguments(body: bytes) -> dict[str, str]:
        root = ET.fromstring(body)
        envelope_body = next(iter(root))
        action_node = next(iter(envelope_body))
        return {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in action_node}

    @staticmethod
    def soap_envelope(action: str, fields: dict[str, str] | None = None) -> str:
        inner = "".join(f"<{key}>{value}</{key}>" for key, value in (fields or {}).items())
        return (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action}Response xmlns:u="{SERVICE_TYPE}">{inner}'
            f'</u:{action}Response></s:Body></s:Envelope>'
        )

    @staticmethod
    def soap_fault(code: int, description: str) -> str:
        return (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            '<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>'
            '<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">'
            f'<errorCode>{code}</errorCode><errorDescription>{description}</errorDescription>'
            '</UPnPError></detail></s:Fault></s:Body></s:Envelope>'
        )

    def _replace_mapping(self, external_port: int, internal_port: int) -> None:
        if (
            self.forwarder is not None
            and self.last_external_port == external_port
            and self.last_internal_port == internal_port
        ):
            return
        if self.forwarder is not None:
            self.forwarder.close()
        forwarder = UdpMappingForwarder(
            public_ip=self.public_ip,
            external_port=external_port,
            lan_ip=self.lan_ip,
            lucky_ip=self.lucky_ip,
            internal_port=internal_port,
        )
        forwarder.start()
        self.forwarder = forwarder

    def handle_action(self, action: str, arguments: dict[str, str]) -> str:
        if action == "GetExternalIPAddress":
            return self.soap_envelope(action, {"NewExternalIPAddress": self.public_ip})
        if action == "GetStatusInfo":
            return self.soap_envelope(
                action,
                {"NewConnectionStatus": "Connected", "NewLastConnectionError": "ERROR_NONE", "NewUptime": "3600"},
            )
        if action == "GetNATRSIPStatus":
            return self.soap_envelope(action, {"NewRSIPAvailable": "0", "NewNATEnabled": "1"})
        if action == "AddPortMapping":
            protocol = arguments.get("NewProtocol", "").upper()
            if protocol != "UDP":
                raise ProbeError("TEST IGD only permits the owned UDP mapping")
            try:
                external_port = int(arguments.get("NewExternalPort") or "0")
                internal_port = int(arguments.get("NewInternalPort") or "0")
            except ValueError as exc:
                raise ProbeError("invalid UPnP mapping port") from exc
            internal_client = arguments.get("NewInternalClient", "")
            if not (0 < external_port <= 65535 and 0 < internal_port <= 65535):
                raise ProbeError("invalid UPnP mapping port range")
            if internal_client != self.lucky_ip:
                raise ProbeError("UPnP mapping escaped the disposable Lucky client")
            self._replace_mapping(external_port, internal_port)
            self.add_requests += 1
            self.last_external_port = external_port
            self.last_internal_port = internal_port
            self.last_internal_client = internal_client
            self.last_protocol = protocol
            self.add_event.set()
            return self.soap_envelope(action)
        if action == "DeletePortMapping":
            self.delete_requests += 1
            if self.forwarder is not None:
                self.forwarder.close()
                self.forwarder = None
            self.delete_event.set()
            return self.soap_envelope(action)
        if action == "GetSpecificPortMappingEntry":
            if self.forwarder is None:
                raise ProbeError("mapping not present")
            return self.soap_envelope(
                action,
                {
                    "NewInternalPort": str(self.last_internal_port),
                    "NewInternalClient": self.last_internal_client,
                    "NewEnabled": "1",
                    "NewPortMappingDescription": "Lucky Skills TEST",
                    "NewLeaseDuration": "0",
                },
            )
        raise ProbeError(f"unsupported SOAP action: {action}")

    def close(self) -> None:
        self.stop_event.set()
        if self.forwarder is not None:
            self.forwarder.close()
            self.forwarder = None
        self.httpd.shutdown()
        self.httpd.server_close()
        self.ssdp_socket.close()
        self.http_thread.join(timeout=2)
        self.ssdp_thread.join(timeout=2)


def rule_options() -> dict[str, Any]:
    return {
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
        "NatPMP": False,
        "UPnPGawayIP": gateway_ip,
        "NatPMPGateway": "",
        "UPnP": True,
        "UPnPLocalPort": listen_port,
        "UPnpLocalHost": lucky_ip,
        "UPnPInternalClientIP": lucky_ip,
        "UpnPDiyControlAPIUrl": "",
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


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if os.geteuid() != 0:
        raise ProbeError("isolated UPnP probe requires sudo/root on the ephemeral GitHub runner")
    missing = [name for name in ("docker", "openssl", "ip") if shutil.which(name) is None]
    if missing:
        raise ProbeError(f"missing required GitHub-runner commands: {', '.join(missing)}")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-upnp-ci-{nonce}"
    network_name = f"lucky-upnp-ci-{nonce}"
    bridge_name = f"lupnp-{nonce[:8]}"
    wan_namespace = f"lupnp-wan-{nonce}"
    wan_host_veth = f"luh{nonce[:8]}"
    wan_ns_veth = f"lun{nonce[:8]}"
    rule_name = TEST_PREFIX + nonce
    open_token = secrets.token_hex(16)
    marker = secrets.token_bytes(32)

    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_lucky_operations": True,
        "network_internal": False,
        "wan_namespace_isolated": False,
        "admin_port_unpublished": False,
        "baseline_empty": False,
        "module_enabled_for_probe": False,
        "module_baseline_restored": False,
        "rule_created": False,
        "rule_upnp_enabled": False,
        "rule_natpmp_disabled": False,
        "firewall_automation_disabled": False,
        "fake_stun_used": False,
        "upnp_add_count": 0,
        "repeated_add_seen": False,
        "runtime_public_endpoint_observed": False,
        "ssdp_request_seen": False,
        "ssdp_response_sent": False,
        "description_requested": False,
        "get_external_ip_seen": False,
        "add_port_mapping_seen": False,
        "upnp_internal_port_matches_listener": False,
        "upnp_internal_client_matches_lucky": False,
        "upnp_protocol_udp": False,
        "mapping_installed": False,
        "mapped_data_roundtrip": False,
        "mapped_echo_target_used": False,
        "mapping_forward_count": 0,
        "mapping_return_count": 0,
        "delete_port_mapping_seen": False,
        "mapping_removed": False,
        "rule_deleted": False,
        "baseline_restored": False,
        "internet_route_required": False,
        "soap_actions": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-upnp-ci-", dir=runner_temp) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        conf_dir = temp_dir / "conf"
        conf_dir.mkdir()
        pull_pinned_image()
        run(
            [
                "docker", "network", "create", "--internal",
                "--opt", f"com.docker.network.bridge.name={bridge_name}", network_name,
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
        igd: FakeUpnpIgd | None = None
        base_url = ""
        created_key = ""
        module_baseline: dict[str, Any] | None = None
        module_changed = False
        baseline_keys: set[str] = set()
        try:
            gateway_ip, _subnet = docker_network_values(network_name)
            report["network_internal"] = True
            docker(
                "run", "-d", "--name", container_name, "--network", network_name,
                "-v", f"{conf_dir}:/app/conf", PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            lucky_ip = container_ipv4(container_name, network_name)
            base_url = f"http://{lucky_ip}:{ADMIN_PORT}"
            wait_for_lucky(base_url, container_name)
            report["admin_port_unpublished"] = admin_port_is_unpublished(container_name)
            if not report["admin_port_unpublished"]:
                raise ProbeError("temporary Lucky admin port was unexpectedly published")

            stun_server = StunBindingServer(gateway_ip, TEST_WAN_GATEWAY)
            echo_server = UdpEchoServer(gateway_ip)
            igd = FakeUpnpIgd(gateway_ip, TEST_WAN_GATEWAY, lucky_ip, bridge_name)
            stun_server.start()
            echo_server.start()
            igd.start()

            admin_token = login_default_admin(base_url, temp_dir)
            enable_open_token(base_url, admin_token, open_token)
            info = api_json(base_url, open_token, "/api/info").get("info")
            if not isinstance(info, dict):
                raise ProbeError("Lucky info response missing info object")
            report["lucky_version"] = str(info.get("Version") or "")
            if report["lucky_version"] != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {report['lucky_version']!r}")

            opener = urllib.request.build_opener()
            configure: dict[str, Any] | None = None
            deadline = time.time() + 35
            while time.time() < deadline:
                status, response = json_request(
                    opener, base_url, "/api/stun/configure", open_token=open_token, timeout=10
                )
                if status != 200:
                    raise ProbeError(f"STUN configure GET returned HTTP {status}")
                if response.get("ret") == 0:
                    candidate = response.get("configure")
                    if not isinstance(candidate, dict):
                        raise ProbeError("STUN configure response missing configure object")
                    configure = candidate
                    break
                if response.get("ret") != -10:
                    raise ProbeError(f"unexpected STUN configure ret={response.get('ret')!r}")
                time.sleep(1)
            if configure is None:
                raise ProbeError("STUN module did not become ready")
            module_baseline = copy.deepcopy(configure)
            if configure.get("EnableModule") is not True:
                candidate = copy.deepcopy(configure)
                candidate["EnableModule"] = True
                candidate.setdefault("WebhookProxyPassword", "")
                api_json(base_url, open_token, "/api/stun/configure", method="PUT", payload=candidate)
                module_changed = True
            live_module = api_json(base_url, open_token, "/api/stun/configure").get("configure")
            report["module_enabled_for_probe"] = isinstance(live_module, dict) and live_module.get("EnableModule") is True
            baseline_keys = {rule_key(row) for row in stun_rows(base_url, open_token) if rule_key(row)}
            report["baseline_empty"] = not baseline_keys
            if not report["baseline_empty"]:
                raise ProbeError("fresh Lucky STUN rule baseline was not empty")

            listen_port = 20000 + secrets.randbelow(25000)
            created = api_json(
                base_url,
                open_token,
                "/api/stunrule",
                method="POST",
                payload=rule_payload(
                    rule_name, lucky_ip, listen_port, gateway_ip, stun_server.port, echo_server.port
                ),
            )
            created_key_value = created.get("key") or created.get("Key")
            if isinstance(created_key_value, str):
                created_key = created_key_value
            row = wait_for_owned_rule(base_url, open_token, rule_name)
            created_key = created_key or rule_key(row)
            if not created_key or created_key in baseline_keys:
                raise ProbeError("disposable UPnP STUN rule did not receive a unique key")
            report["rule_created"] = True
            detail = api_json(base_url, open_token, f"/api/stun/{created_key}").get("rule")
            if not isinstance(detail, dict):
                raise ProbeError("STUN rule detail response missing rule object")
            report["rule_upnp_enabled"] = detail.get("UPnP") is True
            report["rule_natpmp_disabled"] = detail.get("NatPMP") is False
            report["firewall_automation_disabled"] = detail.get("AutoOptionsFirewall") is False

            if not igd.add_event.wait(20):
                # Keep the report useful when Lucky fails before AddPortMapping.
                report["soap_actions"] = list(igd.soap_actions)
            report["fake_stun_used"] = stun_server.request_count > 0
            report["upnp_add_count"] = igd.add_requests
            report["repeated_add_seen"] = igd.add_requests > 1
            report["ssdp_request_seen"] = igd.ssdp_requests > 0
            report["ssdp_response_sent"] = igd.ssdp_responses > 0
            report["description_requested"] = igd.description_requests > 0
            report["get_external_ip_seen"] = "GetExternalIPAddress" in igd.soap_actions
            report["add_port_mapping_seen"] = igd.add_requests > 0
            report["upnp_internal_port_matches_listener"] = igd.last_internal_port == listen_port
            report["upnp_internal_client_matches_lucky"] = igd.last_internal_client == lucky_ip
            report["upnp_protocol_udp"] = igd.last_protocol == "UDP"
            report["mapping_installed"] = igd.forwarder is not None
            report["runtime_public_endpoint_observed"] = wait_contains(
                base_url, open_token, created_key, TEST_WAN_GATEWAY, timeout=5
            )
            if igd.forwarder is not None and igd.last_external_port > 0:
                echo_before = echo_server.request_count
                mapped_ok, _rc, _failure = namespace_udp_roundtrip(
                    wan_namespace, TEST_WAN_GATEWAY, igd.last_external_port, marker
                )
                report["mapped_data_roundtrip"] = mapped_ok
                report["mapped_echo_target_used"] = echo_server.request_count > echo_before
                report["mapping_forward_count"] = igd.forwarder.forward_count
                report["mapping_return_count"] = igd.forwarder.return_count

            query = urllib.parse.urlencode({"key": created_key, "enable": "false"})
            api_json(base_url, open_token, f"/api/stunrule/enable?{query}")
            if not igd.delete_event.wait(8):
                delete_query = urllib.parse.urlencode({"key": created_key})
                api_json(base_url, open_token, f"/api/stunrule?{delete_query}", method="DELETE")
                created_key = ""
                report["rule_deleted"] = True
                igd.delete_event.wait(5)
            report["delete_port_mapping_seen"] = igd.delete_requests > 0
            report["mapping_removed"] = igd.forwarder is None
            if created_key:
                delete_query = urllib.parse.urlencode({"key": created_key})
                api_json(base_url, open_token, f"/api/stunrule?{delete_query}", method="DELETE")
                created_key = ""
                report["rule_deleted"] = True
            report["baseline_restored"] = {
                rule_key(row) for row in stun_rows(base_url, open_token) if rule_key(row)
            } == baseline_keys

            if module_changed and module_baseline is not None:
                restore = copy.deepcopy(module_baseline)
                restore.setdefault("WebhookProxyPassword", "")
                api_json(base_url, open_token, "/api/stun/configure", method="PUT", payload=restore)
                module_changed = False
                restored = api_json(base_url, open_token, "/api/stun/configure").get("configure")
                report["module_baseline_restored"] = (
                    isinstance(restored, dict)
                    and restored.get("EnableModule") == module_baseline.get("EnableModule")
                )
            else:
                report["module_baseline_restored"] = True
            report["soap_actions"] = list(igd.soap_actions)
        finally:
            if created_key and base_url:
                query = urllib.parse.urlencode({"key": created_key})
                try:
                    api_json(base_url, open_token, f"/api/stunrule?{query}", method="DELETE")
                except Exception:  # noqa: BLE001
                    pass
            if module_changed and base_url and module_baseline is not None:
                try:
                    restore = copy.deepcopy(module_baseline)
                    restore.setdefault("WebhookProxyPassword", "")
                    api_json(base_url, open_token, "/api/stun/configure", method="PUT", payload=restore)
                except Exception:  # noqa: BLE001
                    pass
            if igd is not None:
                igd.close()
            if stun_server is not None:
                stun_server.close()
            if echo_server is not None:
                echo_server.close()
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            cleanup_wan_namespace(wan_namespace, wan_host_veth)
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "api_only_lucky_operations",
        "network_internal",
        "wan_namespace_isolated",
        "admin_port_unpublished",
        "baseline_empty",
        "module_enabled_for_probe",
        "module_baseline_restored",
        "rule_created",
        "rule_upnp_enabled",
        "rule_natpmp_disabled",
        "firewall_automation_disabled",
        "runtime_public_endpoint_observed",
        "ssdp_request_seen",
        "ssdp_response_sent",
        "description_requested",
        "get_external_ip_seen",
        "add_port_mapping_seen",
        "upnp_internal_port_matches_listener",
        "upnp_internal_client_matches_lucky",
        "upnp_protocol_udp",
        "mapping_installed",
        "mapped_data_roundtrip",
        "mapped_echo_target_used",
        "delete_port_mapping_seen",
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
