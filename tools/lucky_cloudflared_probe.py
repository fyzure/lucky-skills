#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Cloudflared Tunnel behavior end to end.

The probe creates one disposable remotely-managed Cloudflare Tunnel using the
DevSpace-provided CLOUDFLARE_API_TOKEN, obtains its connector token, then gives
that token to one uniquely named Lucky TEST cloudflared instance. Through
Lucky's own APIs it creates an ingress rule and a proxied CNAME for a unique
one-label hostname under the selected zone, verifies a real public HTTPS
request reaches a loopback-only origin, exercises CNAME check/delete and
ingress/list/log/status surfaces, then removes both Lucky and Cloudflare TEST
resources. Tokens, tunnel IDs, DNS record IDs and live hostnames are never
printed in the JSON result.
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
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


CONFIRMATION = "PROBE-AND-CLEAN-CLOUDFLARED"
TEST_PREFIX = "TEST-lucky-skills-cloudflared-"
ORIGIN_MARKER = "lucky-skills-cloudflared-origin-ok"
CF_API = "https://api.cloudflare.com/client/v4"
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


class CloudflareAPI:
    def __init__(self, token: str) -> None:
        if not token:
            raise RuntimeError("CLOUDFLARE_API_TOKEN is required")
        self._token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = CF_API + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None
        headers = {
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json",
            "User-Agent": "lucky-skills-cloudflared-probe/1",
        }
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            try:
                payload = json.load(error)
            except Exception:
                payload = {}
            codes = [str(item.get("code")) for item in payload.get("errors") or []]
            raise RuntimeError(
                f"Cloudflare API {method} {path} failed HTTP {error.code}; error codes={','.join(codes)}"
            ) from None
        if not isinstance(payload, dict) or payload.get("success") is not True:
            codes = [str(item.get("code")) for item in payload.get("errors") or []]
            raise RuntimeError(
                f"Cloudflare API {method} {path} returned failure; error codes={','.join(codes)}"
            )
        return payload

    def zone(self, name: str) -> tuple[str, str]:
        payload = self.request("GET", "/zones", query={"name": name})
        rows = payload.get("result") or []
        if len(rows) != 1:
            raise RuntimeError("expected exactly one Cloudflare zone")
        zone_id = str(rows[0].get("id") or "")
        account_id = str((rows[0].get("account") or {}).get("id") or "")
        if not zone_id or not account_id:
            raise RuntimeError("Cloudflare zone/account identifiers missing")
        return zone_id, account_id

    def list_tunnels(self, account_id: str, *, name: str | None = None) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"is_deleted": "false", "per_page": 100}
        if name:
            query["name"] = name
        payload = self.request("GET", f"/accounts/{account_id}/cfd_tunnel", query=query)
        rows = payload.get("result") or []
        return [row for row in rows if isinstance(row, dict)]

    def create_tunnel(self, account_id: str, name: str) -> str:
        payload = self.request(
            "POST",
            f"/accounts/{account_id}/cfd_tunnel",
            body={"name": name, "config_src": "cloudflare"},
        )
        result = payload.get("result") or {}
        tunnel_id = str(result.get("id") or "")
        if not tunnel_id:
            raise RuntimeError("Cloudflare Tunnel create returned no id")
        return tunnel_id

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        payload = self.request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"
        )
        token = payload.get("result")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Cloudflare Tunnel token missing")
        return token

    def tunnel(self, account_id: str, tunnel_id: str) -> dict[str, Any]:
        payload = self.request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}"
        )
        value = payload.get("result")
        return value if isinstance(value, dict) else {}

    def connections(self, account_id: str, tunnel_id: str) -> list[dict[str, Any]]:
        payload = self.request(
            "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections"
        )
        rows = payload.get("result") or []
        return [row for row in rows if isinstance(row, dict)]

    def delete_tunnel(self, account_id: str, tunnel_id: str) -> None:
        self.request("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")

    def dns_records(self, zone_id: str, fqdn: str) -> list[dict[str, Any]]:
        payload = self.request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"name": fqdn, "per_page": 100},
        )
        rows = payload.get("result") or []
        return [row for row in rows if isinstance(row, dict)]

    def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        self.request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")


def instance_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/cloudflared/list")
    value = payload.get("list") if isinstance(payload, dict) else None
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("unexpected Lucky Cloudflared list response")
    return [row for row in value if isinstance(row, dict)]


def key_of(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def wait_instance(
    client: LuckyClient, remark: str, *, timeout: float = 20.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in instance_rows(client):
            if row.get("Remark") == remark:
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST Lucky cloudflared instance did not appear")


def wait_connected(
    client: LuckyClient,
    cf: CloudflareAPI,
    *,
    remark: str,
    account_id: str,
    tunnel_id: str,
    timeout: float = 55.0,
) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + timeout
    lucky_row: dict[str, Any] = {}
    cf_tunnel: dict[str, Any] = {}
    while time.monotonic() < deadline:
        for row in instance_rows(client):
            if row.get("Remark") == remark:
                lucky_row = row
                break
        try:
            cf_tunnel = cf.tunnel(account_id, tunnel_id)
        except Exception:
            cf_tunnel = {}
        lucky_ok = bool(
            lucky_row.get("Connected")
            or lucky_row.get("Running") and not lucky_row.get("RunErrorMsg")
        )
        cf_status = str(cf_tunnel.get("status") or "").lower()
        if lucky_ok and cf_status in {"healthy", "degraded"}:
            return True, lucky_row, cf_tunnel
        time.sleep(1.5)
    return False, lucky_row, cf_tunnel


class OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = ORIGIN_MARKER.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def start_origin() -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, int(server.server_address[1])


def wait_public_https(fqdn: str, *, timeout: float = 70.0) -> bool:
    deadline = time.monotonic() + timeout
    url = f"https://{fqdn}/probe"
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "lucky-skills-cloudflared-probe/1"}
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                if response.status == 200 and ORIGIN_MARKER in body:
                    return True
        except Exception:
            pass
        time.sleep(2.0)
    return False


def delete_lucky_test_instances(client: LuckyClient) -> int:
    removed = 0
    for row in instance_rows(client):
        if not str(row.get("Remark", "")).startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", f"/api/cloudflared/list/{key}")
            removed += 1
        except Exception:
            pass
    return removed


def delete_cf_tunnel_with_wait(
    cf: CloudflareAPI, account_id: str, tunnel_id: str, *, timeout: float = 45.0
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            connections = cf.connections(account_id, tunnel_id)
        except Exception:
            connections = []
        if not connections:
            try:
                cf.delete_tunnel(account_id, tunnel_id)
                return True
            except Exception:
                time.sleep(2.0)
                continue
        time.sleep(2.0)
    try:
        cf.delete_tunnel(account_id, tunnel_id)
        return True
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--zone", default="fyzure.fyi")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    cf = CloudflareAPI(cf_token)
    zone_name = args.zone.strip().strip(".").lower()
    zone_id, account_id = cf.zone(zone_name)

    baseline_lucky = instance_rows(client)
    baseline_lucky_keys = {key_of(row) for row in baseline_lucky if key_of(row)}
    if any(str(row.get("Remark", "")).startswith(TEST_PREFIX) for row in baseline_lucky):
        raise RuntimeError("pre-existing TEST Lucky cloudflared instance found")
    baseline_tunnels = cf.list_tunnels(account_id)
    baseline_tunnel_ids = {str(row.get("id") or "") for row in baseline_tunnels}

    nonce = secrets.token_hex(5)
    name = TEST_PREFIX + nonce
    fqdn = f"test-lucky-skills-cf-{nonce}.{zone_name}"
    if cf.dns_records(zone_id, fqdn):
        raise RuntimeError("pre-existing TEST DNS record found")

    origin, origin_thread, origin_port = start_origin()
    tunnel_id = ""
    instance_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        tunnel_id = cf.create_tunnel(account_id, name)
        results["cloudflare_tunnel_created"] = bool(tunnel_id)
        tunnel_token = cf.tunnel_token(account_id, tunnel_id)
        results["cloudflare_tunnel_token_obtained"] = bool(tunnel_token)

        instance_payload = {
            "Key": "",
            "Remark": name,
            "Enable": True,
            "Type": "tunnel",
            "Params": {
                "Token": tunnel_token,
                "EdgeIpVersion": "4",
                "HaConnections": 1,
                "Protocol": "http2",
                "EdgeBindAddress": "",
                "ICMPV4Src": "",
                "ICMPV6Src": "",
                "NoTlsVerify": False,
                "CFApiToken": cf_token,
                "CFAccountId": account_id,
                "CFTunnelId": tunnel_id,
            },
        }
        mutate(
            client,
            "POST",
            "/api/cloudflared/list",
            json_body=instance_payload,
            body_supplied=True,
        )
        row = wait_instance(client, name)
        instance_key = key_of(row)
        results["lucky_instance_created"] = bool(instance_key)

        connected, lucky_runtime, cf_runtime = wait_connected(
            client,
            cf,
            remark=name,
            account_id=account_id,
            tunnel_id=tunnel_id,
        )
        results["tunnel_connected"] = connected
        observations["lucky_running"] = bool(lucky_runtime.get("Running"))
        observations["lucky_connected"] = bool(lucky_runtime.get("Connected"))
        observations["lucky_run_error_present"] = bool(lucky_runtime.get("RunErrorMsg"))
        observations["cloudflare_tunnel_status"] = str(cf_runtime.get("status") or "")

        # Create a real remotely-managed ingress rule through Lucky.
        ingress = {
            "hostname": fqdn,
            "path": "",
            "service": f"http://127.0.0.1:{origin_port}",
            "originRequest": {"keepAliveConnections": 4},
        }
        mutate(
            client,
            "POST",
            f"/api/cloudflared/{instance_key}/ingress",
            json_body=ingress,
            body_supplied=True,
        )
        ingress_read = client.request_json(
            "GET", f"/api/cloudflared/{instance_key}/ingress"
        )
        ingress_rows = (
            ingress_read.get("ingress")
            or ingress_read.get("list")
            or ingress_read.get("rules")
            or []
        )
        if not isinstance(ingress_rows, list):
            ingress_rows = []
        results["lucky_ingress_created"] = any(
            isinstance(item, dict)
            and item.get("hostname") == fqdn
            and item.get("service") == f"http://127.0.0.1:{origin_port}"
            for item in ingress_rows
        )
        observations["ingress_rule_count"] = len(ingress_rows)

        # Exercise Lucky's Cloudflare DNS helper using the instance's API token.
        mutate(
            client,
            "POST",
            f"/api/cloudflared/{instance_key}/cname/create",
            json_body={"hostname": fqdn, "proxied": True},
            body_supplied=True,
        )
        dns_rows = cf.dns_records(zone_id, fqdn)
        results["lucky_cname_created"] = (
            len(dns_rows) == 1
            and str(dns_rows[0].get("type") or "").upper() == "CNAME"
            and bool(dns_rows[0].get("proxied"))
        )

        check = client.request_json(
            "GET",
            f"/api/cloudflared/{instance_key}/cname/check",
            query={"hostname": fqdn},
        )
        results["lucky_cname_check"] = isinstance(check, dict) and check.get("ret") == 0

        results["public_https_roundtrip"] = wait_public_https(fqdn)

        last_logs = client.request_json(
            "GET", f"/api/cloudflared/{instance_key}/lastlogs"
        )
        results["instance_log_surface"] = (
            isinstance(last_logs, dict) and last_logs.get("ret") == 0
        )
        log_rows = last_logs.get("lastLogs") if isinstance(last_logs, dict) else None
        observations["instance_log_count"] = len(log_rows) if isinstance(log_rows, list) else 0

        # Exercise Lucky ingress delete while the connector is still alive.
        mutate(
            client,
            "DELETE",
            f"/api/cloudflared/{instance_key}/ingress",
            query={"hostname": fqdn, "path": ""},
        )
        ingress_after = client.request_json(
            "GET", f"/api/cloudflared/{instance_key}/ingress"
        )
        remaining = (
            ingress_after.get("ingress")
            or ingress_after.get("list")
            or ingress_after.get("rules")
            or []
        )
        if not isinstance(remaining, list):
            remaining = []
        results["lucky_ingress_deleted"] = not any(
            isinstance(item, dict) and item.get("hostname") == fqdn for item in remaining
        )

        mutate(
            client,
            "DELETE",
            f"/api/cloudflared/{instance_key}/cname/delete",
            query={"hostname": fqdn},
        )
        results["lucky_cname_deleted"] = not cf.dns_records(zone_id, fqdn)
    finally:
        # First stop/delete the connector so Cloudflare can release connection
        # records before the tunnel itself is deleted.
        cleanup["lucky_test_instances_removed"] = delete_lucky_test_instances(client)

        # Fallback-clean only the unique TEST DNS name in case the Lucky CNAME
        # delete route failed part-way through the probe.
        try:
            residual_dns = cf.dns_records(zone_id, fqdn)
        except Exception:
            residual_dns = []
        fallback_dns_deleted = 0
        for record in residual_dns:
            record_id = str(record.get("id") or "")
            if record_id:
                try:
                    cf.delete_dns_record(zone_id, record_id)
                    fallback_dns_deleted += 1
                except Exception:
                    pass
        cleanup["fallback_dns_records_deleted"] = fallback_dns_deleted

        if tunnel_id:
            cleanup["cloudflare_tunnel_deleted"] = delete_cf_tunnel_with_wait(
                cf, account_id, tunnel_id
            )

        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=2)

    final_lucky = instance_rows(client)
    cleanup["lucky_key_baseline_restored"] = {
        key_of(row) for row in final_lucky if key_of(row)
    } == baseline_lucky_keys
    cleanup["leftover_lucky_test_instances"] = sum(
        1 for row in final_lucky if str(row.get("Remark", "")).startswith(TEST_PREFIX)
    )
    final_tunnels = cf.list_tunnels(account_id)
    cleanup["cloudflare_tunnel_baseline_restored"] = {
        str(row.get("id") or "") for row in final_tunnels
    } == baseline_tunnel_ids
    cleanup["cloudflare_test_dns_absent"] = not cf.dns_records(zone_id, fqdn)

    failed = sorted(key for key, value in results.items() if not value)
    for key in (
        "lucky_key_baseline_restored",
        "cloudflare_tunnel_baseline_restored",
        "cloudflare_test_dns_absent",
    ):
        if not cleanup.get(key):
            failed.append(key)
    if cleanup.get("leftover_lucky_test_instances") != 0:
        failed.append("leftover_lucky_test_instances")
    if tunnel_id and not cleanup.get("cloudflare_tunnel_deleted"):
        failed.append("cloudflare_tunnel_deleted")

    print(
        json.dumps(
            {
                "target": "Lucky Cloudflared Tunnel + ingress + CNAME behavior",
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
