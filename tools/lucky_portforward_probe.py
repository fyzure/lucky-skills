#!/usr/bin/env python3
"""Runtime-verify Lucky v3 TCP/UDP PortForward data flow.

The probe creates two uniquely named loopback-only TEST rules: one tcp4 and
one udp4. Both Lucky listeners bind only to 127.0.0.1 and forward to ephemeral
loopback echo servers owned by this process. It sends real application bytes
through Lucky, checks the replies, reads detail/log/statistics surfaces, then
deletes only the TEST rules and verifies the original rule baseline and closed
listener ports.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError, LuckyAPIError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-PORTFORWARD"
TEST_PREFIX = "TEST-lucky-skills-portforward-"


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(base_url, token, catalog=catalog, retries=0, timeout=20)
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(
        values["base_url"], values["open_token"], catalog=catalog, retries=0, timeout=20
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    body_supplied: bool = False,
    attempts: int = 6,
) -> Any:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {"allow_unsafe": True}
        if query is not None:
            kwargs["query"] = query
        if body_supplied:
            kwargs["json_body"] = json_body
        try:
            return client.request_json(method, path, **kwargs)
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(6.0 + attempt * 4.0)
    raise AssertionError("unreachable")


def rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/portforwards")
    value = payload.get("list") if isinstance(payload, dict) else None
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("unexpected PortForward list response")
    return [item for item in value if isinstance(item, dict)]


def row_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def wait_rule(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in rows(client):
            if row.get("Name") == name:
                return row
        time.sleep(0.4)
    raise RuntimeError("TEST PortForward rule did not appear")


def create_rule(client: LuckyClient, payload: dict[str, Any]) -> dict[str, Any]:
    """Create once, then resolve Lucky's ret=9 partial-success behavior by readback."""
    name = str(payload.get("Name") or "")
    try:
        mutate(
            client,
            "POST",
            "/api/portforward",
            json_body=payload,
            body_supplied=True,
        )
    except LuckyAPIError as error:
        if error.ret != 9:
            raise
        # A busy response can occur after the rule is already persisted and
        # enabled. Never retry POST blindly because that can duplicate a rule.
    return wait_rule(client, name, timeout=20.0)


def delete_rule(client: LuckyClient, key: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    attempted = False
    while time.monotonic() < deadline:
        if not any(row_key(row) == key for row in rows(client)):
            return True
        if attempted:
            time.sleep(0.8)
        try:
            mutate(client, "DELETE", "/api/portforward", query={"key": key})
            attempted = True
        except LuckyAPIError as error:
            if error.ret != 9:
                raise
            attempted = True
            time.sleep(1.0)
    return not any(row_key(row) == key for row in rows(client))


def free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class TCPEcho:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.port = int(self.sock.getsockname()[1])
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.0)
                while not self.stop_event.is_set():
                    try:
                        data = conn.recv(65535)
                    except (socket.timeout, OSError):
                        break
                    if not data:
                        break
                    try:
                        conn.sendall(data)
                    except OSError:
                        break

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)


class UDPEcho:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.5)
        self.port = int(self.sock.getsockname()[1])
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.sock.sendto(data, addr)
            except OSError:
                break

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)


def options() -> dict[str, Any]:
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


def rule_payload(name: str, protocol: str, listen_port: int, target_port: int) -> dict[str, Any]:
    return {
        "Name": name,
        "Key": "",
        "DiaglogShowMode": "simple",
        "ForwardTypes": [protocol],
        "ListenAddress": "127.0.0.1",
        "ListenPorts": str(listen_port),
        "TargetAddressList": ["127.0.0.1"],
        "TargetPorts": str(target_port),
        "Enable": True,
        "LogLevel": 4,
        "OpenFirewallPorts": False,
        "LogOutputToConsole": False,
        "AccessLogMaxNum": 128,
        "WebListShowLastLogMaxCount": 20,
        "Options": options(),
        "LogStreamSettings": {},
    }


def tcp_roundtrip(port: int, payload: bytes) -> bool:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = sock.recv(len(payload) - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                return bytes(received) == payload
        except OSError:
            time.sleep(0.3)
    return False


def udp_roundtrip(port: int, payload: bytes) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.2)
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            try:
                sock.sendto(payload, ("127.0.0.1", port))
                data, _ = sock.recvfrom(65535)
                return data == payload
            except socket.timeout:
                continue
        return False
    finally:
        sock.close()


def tcp_closed(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0
    finally:
        sock.close()


def cleanup_tests(client: LuckyClient) -> int:
    removed = 0
    for row in rows(client):
        if not str(row.get("Name", "")).startswith(TEST_PREFIX):
            continue
        key = row_key(row)
        if not key:
            continue
        try:
            if delete_rule(client, key):
                removed += 1
        except Exception:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline = rows(client)
    baseline_keys = {row_key(row) for row in baseline if row_key(row)}
    if any(str(row.get("Name", "")).startswith(TEST_PREFIX) for row in baseline):
        raise RuntimeError("pre-existing TEST PortForward rule found")

    nonce = secrets.token_hex(5)
    tcp_name = TEST_PREFIX + nonce + "-tcp"
    udp_name = TEST_PREFIX + nonce + "-udp"
    tcp_listen = free_tcp_port()
    udp_listen = free_udp_port()
    tcp_echo = TCPEcho()
    udp_echo = UDPEcho()
    tcp_echo.start()
    udp_echo.start()
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        tcp_row = create_rule(
            client, rule_payload(tcp_name, "tcp4", tcp_listen, tcp_echo.port)
        )
        tcp_key = row_key(tcp_row)
        results["tcp_rule_create"] = bool(tcp_key)

        # Let Lucky finish the listener reconfiguration triggered by the TCP
        # create before adding the UDP rule.
        time.sleep(1.2)
        udp_row = create_rule(
            client, rule_payload(udp_name, "udp4", udp_listen, udp_echo.port)
        )
        udp_key = row_key(udp_row)
        results["udp_rule_create"] = bool(udp_key)

        tcp_detail_payload = client.request_json("GET", f"/api/portforward/{tcp_key}")
        tcp_detail = tcp_detail_payload.get("rule") if isinstance(tcp_detail_payload, dict) else None
        udp_detail_payload = client.request_json("GET", f"/api/portforward/{udp_key}")
        udp_detail = udp_detail_payload.get("rule") if isinstance(udp_detail_payload, dict) else None
        results["tcp_detail_protocol"] = isinstance(tcp_detail, dict) and tcp_detail.get("ForwardTypes") == ["tcp4"]
        results["udp_detail_protocol"] = isinstance(udp_detail, dict) and udp_detail.get("ForwardTypes") == ["udp4"]

        tcp_payload = ("tcp-" + nonce).encode("ascii") * 64
        udp_payload = ("udp-" + nonce).encode("ascii") * 32
        results["tcp_roundtrip"] = tcp_roundtrip(tcp_listen, tcp_payload)
        results["udp_roundtrip"] = udp_roundtrip(udp_listen, udp_payload)

        # Exercise both log surfaces after real traffic. The content itself is
        # not retained; only response-envelope/type observations are recorded.
        tcp_last = client.request_json("GET", f"/api/portforward/{tcp_key}/lastlogs")
        udp_last = client.request_json("GET", f"/api/portforward/{udp_key}/lastlogs")
        results["tcp_log_surface"] = isinstance(tcp_last, dict) and tcp_last.get("ret") == 0
        results["udp_log_surface"] = isinstance(udp_last, dict) and udp_last.get("ret") == 0
        observations["tcp_lastlogs_kind"] = type(tcp_last.get("lastLogs")).__name__ if isinstance(tcp_last, dict) else "invalid"
        observations["udp_lastlogs_kind"] = type(udp_last.get("lastLogs")).__name__ if isinstance(udp_last, dict) else "invalid"

        list_after = client.request_json("GET", "/api/portforwards")
        stats = list_after.get("statistics") if isinstance(list_after, dict) else None
        results["statistics_surface"] = isinstance(stats, dict)
        observations["statistics_rule_entries"] = len(stats) if isinstance(stats, dict) else 0
    finally:
        cleanup["test_rules_removed"] = cleanup_tests(client)
        tcp_echo.close()
        udp_echo.close()

    time.sleep(0.8)
    final = rows(client)
    cleanup["rule_key_baseline_restored"] = {
        row_key(row) for row in final if row_key(row)
    } == baseline_keys
    cleanup["leftover_test_rules"] = sum(
        1 for row in final if str(row.get("Name", "")).startswith(TEST_PREFIX)
    )
    cleanup["tcp_listener_closed"] = tcp_closed(tcp_listen)

    failed = sorted(key for key, value in results.items() if not value)
    for key in ("rule_key_baseline_restored", "tcp_listener_closed"):
        if not cleanup.get(key):
            failed.append(key)
    if cleanup.get("leftover_test_rules") != 0:
        failed.append("leftover_test_rules")

    print(
        json.dumps(
            {
                "target": "Lucky PortForward TCP/UDP loopback data flow",
                "results": results,
                "observations": observations,
                "cleanup": cleanup,
                "failed": sorted(set(failed)),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
