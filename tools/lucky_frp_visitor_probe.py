#!/usr/bin/env python3
"""Runtime-verify Lucky v3 FRP STCP visitor behavior on loopback only.

The probe creates three uniquely prefixed FRP instances inside the same Lucky
runtime: one loopback frps server, one provider frpc and one visitor frpc. The
provider publishes an STCP proxy backed by a loopback echo server; the visitor
binds only 127.0.0.1 on an ephemeral port. Real bytes must round-trip through
visitor -> frps -> provider -> echo before and after a visitor transport update.

Only disposable TEST instances/proxy/visitor objects are touched. Secrets are
kept in memory and never emitted. Cleanup restores the FRP instance-key
baseline exactly.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from tools.lucky_frp_probe import (
    TEST_PREFIX,
    EchoServer,
    client_params,
    delete_instance,
    free_tcp_port,
    key_of,
    make_client,
    mutate,
    proxy_model,
    proxy_rows,
    rows,
    server_params,
    tcp_roundtrip,
    wait_instance,
    wait_proxy,
)


CONFIRMATION = "PROBE-AND-CLEAN-FRP-VISITOR"


def visitor_rows(client: Any, client_key: str) -> list[dict[str, Any]]:
    payload = client.request_json("GET", f"/api/frp/{client_key}/visitors")
    for key in ("list", "visitors", "Visitors"):
        value = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def wait_visitor(
    client: Any, client_key: str, name: str, timeout: float = 20.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in visitor_rows(client, client_key):
            if str(row.get("name") or row.get("Name") or "") == name:
                return row
        time.sleep(0.4)
    raise RuntimeError("TEST FRP visitor did not appear")


def visitor_model(
    name: str,
    server_name: str,
    secret_key: str,
    bind_port: int,
    *,
    encryption: bool = False,
    compression: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "type": "stcp",
        "disabled": False,
        "serverName": server_name,
        "secretKey": secret_key,
        "bindAddr": "127.0.0.1",
        "bindPort": bind_port,
        "serverUser": "",
        "transport": {
            "useEncryption": encryption,
            "useCompression": compression,
        },
        "protocol": "quic",
        "keepTunnelOpen": False,
        "maxRetriesAnHour": 8,
        "minRetryInterval": 90,
        "fallbackTo": "",
        "fallbackTimeoutMs": 0,
        "natTraversal": {"disableAssistedAddrs": True},
        "plugin": {"type": "", "destinationIP": ""},
    }


def wait_absent(
    getter: Any, name: str, timeout: float = 15.0
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(str(row.get("name") or row.get("Name") or "") == name for row in getter()):
            return True
        time.sleep(0.3)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"confirmation must be exactly {CONFIRMATION}")

    client = make_client()
    baseline = rows(client)
    baseline_keys = {key_of(row) for row in baseline if key_of(row)}
    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in baseline):
        raise RuntimeError("pre-existing TEST FRP instance found")

    nonce = secrets.token_hex(5)
    server_remark = f"{TEST_PREFIX}visitor-server-{nonce}"
    provider_remark = f"{TEST_PREFIX}visitor-provider-{nonce}"
    visitor_client_remark = f"{TEST_PREFIX}visitor-client-{nonce}"
    proxy_name = f"{TEST_PREFIX}stcp-proxy-{nonce}"
    visitor_name = f"{TEST_PREFIX}stcp-visitor-{nonce}"
    auth_token = secrets.token_urlsafe(18)
    visitor_secret = secrets.token_urlsafe(18)
    server_port = free_tcp_port()
    bind_port = free_tcp_port()

    echo = EchoServer()
    echo.start()
    server_key = ""
    provider_key = ""
    visitor_client_key = ""
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
        results["server_running"] = bool(server_key and server_row.get("Running"))

        provider_payload = {
            "Key": "",
            "Remark": provider_remark,
            "Enable": True,
            "Type": "client",
            "ConfigMode": "form",
            "ConfigText": "",
            "Params": client_params(server_port, auth_token),
            "Proxies": [],
            "Visitors": [],
        }
        mutate(client, "POST", "/api/frp/list", json_body=provider_payload, body_supplied=True)
        provider_row = wait_instance(client, provider_remark, running=True)
        provider_key = key_of(provider_row)
        results["provider_running"] = bool(provider_key and provider_row.get("Running"))

        visitor_client_payload = {
            "Key": "",
            "Remark": visitor_client_remark,
            "Enable": True,
            "Type": "client",
            "ConfigMode": "form",
            "ConfigText": "",
            "Params": client_params(server_port, auth_token),
            "Proxies": [],
            "Visitors": [],
        }
        mutate(
            client,
            "POST",
            "/api/frp/list",
            json_body=visitor_client_payload,
            body_supplied=True,
        )
        visitor_client_row = wait_instance(client, visitor_client_remark, running=True)
        visitor_client_key = key_of(visitor_client_row)
        results["visitor_client_running"] = bool(
            visitor_client_key and visitor_client_row.get("Running")
        )

        proxy = proxy_model(proxy_name, echo.port, 0)
        proxy.update({"type": "stcp", "secretKey": visitor_secret, "allowUsers": []})
        created_proxy = mutate(
            client,
            "POST",
            f"/api/frp/{provider_key}/proxies",
            json_body=proxy,
            body_supplied=True,
        )
        results["stcp_proxy_create_ret_zero"] = (
            isinstance(created_proxy, dict) and created_proxy.get("ret") == 0
        )
        proxy_row = wait_proxy(client, provider_key, proxy_name)
        results["stcp_proxy_readback"] = str(proxy_row.get("type") or "").lower() == "stcp"

        visitor = visitor_model(visitor_name, proxy_name, visitor_secret, bind_port)
        created_visitor = mutate(
            client,
            "POST",
            f"/api/frp/{visitor_client_key}/visitors",
            json_body=visitor,
            body_supplied=True,
        )
        results["visitor_create_ret_zero"] = (
            isinstance(created_visitor, dict) and created_visitor.get("ret") == 0
        )
        visitor_row = wait_visitor(client, visitor_client_key, visitor_name)
        results["visitor_readback"] = (
            str(visitor_row.get("type") or "").lower() == "stcp"
            and visitor_row.get("bindAddr") == "127.0.0.1"
            and int(visitor_row.get("bindPort") or 0) == bind_port
            and visitor_row.get("serverName") == proxy_name
        )
        observations["visitor_fields"] = sorted(visitor_row.keys())

        payload = f"lucky-frp-visitor-{nonce}".encode("ascii")
        results["stcp_roundtrip"] = tcp_roundtrip(bind_port, payload, timeout=20)

        updated = visitor_model(
            visitor_name,
            proxy_name,
            visitor_secret,
            bind_port,
            encryption=True,
            compression=True,
        )
        updated_response = mutate(
            client,
            "PUT",
            f"/api/frp/{visitor_client_key}/visitors",
            json_body={"oldName": visitor_name, "newVisitor": updated},
            body_supplied=True,
        )
        results["visitor_update_ret_zero"] = (
            isinstance(updated_response, dict) and updated_response.get("ret") == 0
        )
        updated_row = wait_visitor(client, visitor_client_key, visitor_name)
        transport = updated_row.get("transport") if isinstance(updated_row.get("transport"), dict) else {}
        results["visitor_transport_update_readback"] = (
            isinstance(transport, dict)
            and transport.get("useEncryption") is True
            and transport.get("useCompression") is True
        )
        observations["transport_readback_fields"] = (
            sorted(transport.keys()) if isinstance(transport, dict) else []
        )
        results["stcp_roundtrip_after_update"] = tcp_roundtrip(
            bind_port, payload + b"-2", timeout=20
        )

        status_payload = client.request_json("GET", f"/api/frp/{visitor_client_key}/status")
        visitor_statuses = (
            status_payload.get("visitorStatuses") if isinstance(status_payload, dict) else None
        )
        results["status_surface"] = (
            isinstance(status_payload, dict) and status_payload.get("ret") == 0
        )
        observations["visitor_status_count"] = (
            len(visitor_statuses) if isinstance(visitor_statuses, list) else 0
        )
        observations["visitor_status_semantics"] = (
            "status endpoint may return an empty visitorStatuses array even while the STCP visitor data plane works"
        )

        deleted_visitor = mutate(
            client, "DELETE", f"/api/frp/{visitor_client_key}/visitors/{visitor_name}"
        )
        results["visitor_delete_ret_zero"] = (
            isinstance(deleted_visitor, dict) and deleted_visitor.get("ret") == 0
        )
        results["visitor_deleted"] = wait_absent(
            lambda: visitor_rows(client, visitor_client_key), visitor_name
        )

        deleted_proxy = mutate(client, "DELETE", f"/api/frp/{provider_key}/proxies/{proxy_name}")
        results["proxy_delete_ret_zero"] = (
            isinstance(deleted_proxy, dict) and deleted_proxy.get("ret") == 0
        )
        results["proxy_deleted"] = wait_absent(
            lambda: proxy_rows(client, provider_key), proxy_name
        )
    finally:
        if visitor_client_key:
            cleanup["visitor_client_deleted"] = delete_instance(client, visitor_client_key)
        if provider_key:
            cleanup["provider_deleted"] = delete_instance(client, provider_key)
        if server_key:
            cleanup["server_deleted"] = delete_instance(client, server_key)
        echo.close()

    final_rows = rows(client)
    cleanup["frp_key_baseline_restored"] = {
        key_of(row) for row in final_rows if key_of(row)
    } == baseline_keys
    cleanup["leftover_test_instances"] = sum(
        1 for row in final_rows if str(row.get("Remark") or "").startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if value is not True)
    for key, value in cleanup.items():
        if key == "leftover_test_instances":
            if value != 0:
                failed.append(f"cleanup:{key}")
        elif value is not True:
            failed.append(f"cleanup:{key}")

    report = {
        "target": "Lucky FRP STCP visitor loopback behavior",
        "results": results,
        "observations": observations,
        "cleanup": cleanup,
        "failed": sorted(set(failed)),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
