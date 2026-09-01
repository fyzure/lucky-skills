#!/usr/bin/env python3
"""Runtime-verify Lucky v3 FRP server/client/proxy behavior on loopback only.

The probe creates one disposable frps instance and one disposable frpc instance
inside the same Lucky process.  Both bind/connect only on 127.0.0.1.  A single
TCP proxy exposes a loopback echo server on another ephemeral loopback port;
real bytes are sent through frpc -> frps -> echo and verified on return.

The proxy is also updated and deleted through Lucky's proxy CRUD endpoints.
Only uniquely TEST-prefixed instances/proxies are touched, and the original FRP
instance-key baseline is verified after cleanup.
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


CONFIRMATION = "PROBE-AND-CLEAN-FRP"
TEST_PREFIX = "TEST-lucky-skills-frp-"


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(base_url, token, catalog=catalog, retries=0, timeout=25)
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(
        values["base_url"], values["open_token"], catalog=catalog, retries=0, timeout=25
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    json_body: Any = None,
    body_supplied: bool = False,
    attempts: int = 6,
) -> Any:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {"allow_unsafe": True}
        if body_supplied:
            kwargs["json_body"] = json_body
        try:
            return client.request_json(method, path, **kwargs)
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(5.0 + attempt * 3.0)
    raise AssertionError("unreachable")


def rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/frp/list")
    value = payload.get("list") if isinstance(payload, dict) else None
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("unexpected FRP list response")
    return [item for item in value if isinstance(item, dict)]


def key_of(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class EchoServer:
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
                try:
                    while not self.stop_event.is_set():
                        data = conn.recv(65535)
                        if not data:
                            break
                        conn.sendall(data)
                except OSError:
                    pass

    def close(self) -> None:
        self.stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2.0)


def server_params(bind_port: int, token: str) -> dict[str, Any]:
    return {
        "BindAddr": "127.0.0.1",
        "BindPort": bind_port,
        "ProxyBindAddr": "127.0.0.1",
        "KCPBindPort": 0,
        "QUICBindPort": 0,
        "VhostHTTPPort": 0,
        "VhostHTTPTimeout": 60,
        "VhostHTTPSPort": 0,
        "TCPMuxHTTPConnectPort": 0,
        "TCPMuxPassthrough": False,
        "TCPMux": True,
        "TCPMuxKeepaliveInterval": 60,
        "TCPKeepalive": 7200,
        "MaxPoolCount": 5,
        "MaxPortsPerClient": 0,
        "AllowPorts": "",
        "HeartbeatTimeout": 90,
        "UserConnTimeout": 10,
        "TLSOnly": False,
        "UDPPacketSize": 1500,
        "DetailedErrorsToClient": True,
        "DashboardPort": 0,
        "DashboardUser": "admin",
        "Token": token,
    }


def client_params(server_port: int, token: str) -> dict[str, Any]:
    return {
        "ServerAddr": "127.0.0.1",
        "ServerPort": server_port,
        "User": "",
        "AuthMethod": "token",
        "Token": token,
        "AuthAdditionalScopes": [],
        "OIDCClientID": "",
        "OIDCClientSecret": "",
        "OIDCAudience": "",
        "OIDCScope": "",
        "OIDCTokenEndpointURL": "",
        "OIDCAdditionalEndpointParams": {},
        "Protocol": "tcp",
        "NatHoleStunServer": "",
        "DialServerTimeout": 10,
        "DialServerKeepalive": 7200,
        "ConnectServerLocalIP": "127.0.0.1",
        "ProxyURL": "",
        "PoolCount": 1,
        "TCPMux": True,
        "TCPMuxKeepaliveInterval": 60,
        "HeartbeatInterval": 30,
        "HeartbeatTimeout": 90,
        "QUICKeepalivePeriod": 30,
        "QUICMaxIdleTimeout": 30,
        "QUICMaxIncomingStreams": 100000,
        "TLSEnable": True,
        "TLSServerName": "",
        "DisableCustomTLSFirstByte": False,
        "TLSInsecureSkipVerify": True,
        "UDPPacketSize": 1500,
        "DNSServer": "",
        "LoginFailExit": False,
        "Start": [],
        "Metadatas": {},
        "VirtualNetAddress": "",
        "AdminPort": 0,
        "AdminUser": "admin",
    }


def proxy_model(name: str, local_port: int, remote_port: int) -> dict[str, Any]:
    return {
        "name": name,
        "type": "tcp",
        "disabled": False,
        "annotations": {},
        "metadatas": {},
        "localIP": "127.0.0.1",
        "localPort": local_port,
        "remotePort": remote_port,
        "useEncryption": False,
        "useCompression": False,
        "proxyProtocolVersion": "",
        "plugin": "",
        "natTraversal": {"disableAssistedAddrs": True},
    }


def wait_instance(
    client: LuckyClient, remark: str, *, running: bool | None = None, timeout: float = 25.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        for row in rows(client):
            if str(row.get("Remark") or "") != remark:
                continue
            last = row
            if running is None or bool(row.get("Running")) is running:
                return row
        time.sleep(0.5)
    if last:
        return last
    raise RuntimeError("TEST FRP instance did not appear")


def proxy_rows(client: LuckyClient, client_key: str) -> list[dict[str, Any]]:
    payload = client.request_json("GET", f"/api/frp/{client_key}/proxies")
    for key in ("list", "proxies", "Proxies"):
        value = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def wait_proxy(
    client: LuckyClient, client_key: str, name: str, timeout: float = 20.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in proxy_rows(client, client_key):
            if str(row.get("name") or row.get("Name") or "") == name:
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST FRP proxy did not appear")


def tcp_roundtrip(port: int, payload: bytes, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(payload)
                received = sock.recv(len(payload) + 32)
                return received == payload
        except OSError:
            time.sleep(0.5)
    return False


def delete_instance(client: LuckyClient, key: str) -> bool:
    try:
        mutate(client, "DELETE", f"/api/frp/list/{key}")
    except LuckyAPIError:
        pass
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if not any(key_of(row) == key for row in rows(client)):
            return True
        time.sleep(0.5)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline = rows(client)
    baseline_keys = {key_of(row) for row in baseline if key_of(row)}
    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in baseline):
        raise RuntimeError("pre-existing TEST FRP instance found")

    nonce = secrets.token_hex(5)
    server_remark = TEST_PREFIX + "server-" + nonce
    client_remark = TEST_PREFIX + "client-" + nonce
    proxy_name = TEST_PREFIX + "proxy-" + nonce
    auth_token = secrets.token_urlsafe(18)
    server_port = free_tcp_port()
    remote_port = free_tcp_port()
    echo = EchoServer()
    echo.start()

    server_key = ""
    client_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        server_payload = {
            "Key": "",
            "Remark": server_remark,
            "Enable": True,
            "Type": "server",
            "ConfigMode": "form",
            "ConfigText": "",
            "Params": server_params(server_port, auth_token),
            "Proxies": [],
            "Visitors": [],
        }
        mutate(client, "POST", "/api/frp/list", json_body=server_payload, body_supplied=True)
        server_row = wait_instance(client, server_remark, running=True)
        server_key = key_of(server_row)
        results["server_created"] = bool(server_key)
        results["server_running"] = bool(server_row.get("Running"))

        client_payload = {
            "Key": "",
            "Remark": client_remark,
            "Enable": True,
            "Type": "client",
            "ConfigMode": "form",
            "ConfigText": "",
            "Params": client_params(server_port, auth_token),
            "Proxies": [],
            "Visitors": [],
        }
        mutate(client, "POST", "/api/frp/list", json_body=client_payload, body_supplied=True)
        client_row = wait_instance(client, client_remark, running=True)
        client_key = key_of(client_row)
        results["client_created"] = bool(client_key)
        results["client_running"] = bool(client_row.get("Running"))

        proxy = proxy_model(proxy_name, echo.port, remote_port)
        mutate(
            client,
            "POST",
            f"/api/frp/{client_key}/proxies",
            json_body=proxy,
            body_supplied=True,
        )
        wait_proxy(client, client_key, proxy_name)
        results["proxy_created"] = True

        payload = ("lucky-frp-" + nonce).encode("ascii")
        results["tcp_roundtrip"] = tcp_roundtrip(remote_port, payload)

        updated = dict(proxy)
        updated["useCompression"] = True
        mutate(
            client,
            "PUT",
            f"/api/frp/{client_key}/proxies",
            json_body={"oldName": proxy_name, "newProxy": updated},
            body_supplied=True,
        )
        updated_row = wait_proxy(client, client_key, proxy_name)
        results["proxy_updated"] = bool(updated_row.get("useCompression") is True)
        results["tcp_roundtrip_after_update"] = tcp_roundtrip(remote_port, payload + b"-2")

        status_payload = client.request_json("GET", f"/api/frp/{client_key}/status")
        results["status_surface"] = isinstance(status_payload, dict) and status_payload.get("ret") == 0
        logs_payload = client.request_json("GET", f"/api/frp/{client_key}/lastlogs")
        logs = logs_payload.get("logs") if isinstance(logs_payload, dict) else None
        observations["client_log_count"] = len(logs) if isinstance(logs, list) else 0
        results["log_surface"] = isinstance(logs_payload, dict) and logs_payload.get("ret") == 0
        observations["server_running"] = bool(wait_instance(client, server_remark).get("Running"))
        observations["client_running"] = bool(wait_instance(client, client_remark).get("Running"))
        observations["proxy_count"] = len(proxy_rows(client, client_key))

        mutate(client, "DELETE", f"/api/frp/{client_key}/proxies/{proxy_name}")
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and any(
            str(row.get("name") or row.get("Name") or "") == proxy_name
            for row in proxy_rows(client, client_key)
        ):
            time.sleep(0.5)
        results["proxy_deleted"] = not any(
            str(row.get("name") or row.get("Name") or "") == proxy_name
            for row in proxy_rows(client, client_key)
        )

    finally:
        if client_key:
            cleanup["client_deleted"] = delete_instance(client, client_key)
        if server_key:
            cleanup["server_deleted"] = delete_instance(client, server_key)
        # Remove only uniquely TEST-prefixed leftovers in case a create returned
        # an error after persistence.
        removed_leftovers = 0
        for row in list(rows(client)):
            if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
                continue
            key = key_of(row)
            if key and delete_instance(client, key):
                removed_leftovers += 1
        echo.close()
        final_rows = rows(client)
        cleanup["leftover_test_instances"] = sum(
            1 for row in final_rows if str(row.get("Remark") or "").startswith(TEST_PREFIX)
        )
        cleanup["baseline_restored"] = {
            key_of(row) for row in final_rows if key_of(row)
        } == baseline_keys
        cleanup["leftover_instances_removed"] = removed_leftovers

    failed = [name for name, ok in results.items() if ok is not True]
    failed += [
        "cleanup." + name
        for name, ok in cleanup.items()
        if name not in {"leftover_instances_removed", "leftover_test_instances"} and ok is not True
    ]
    if cleanup.get("leftover_test_instances") != 0:
        failed.append("cleanup.leftover_test_instances")

    print(
        json.dumps(
            {
                "target": "Lucky FRP frps + frpc + TCP proxy behavior",
                "results": results,
                "observations": observations,
                "cleanup": cleanup,
                "failed": failed,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
