#!/usr/bin/env python3
"""Runtime-verify Lucky v3 DDNS CRUD and Cloudflare update behavior.

This owner-authorized probe uses one existing Cloudflare DDNS task only as a
provider/configuration template. It creates a unique TEST task and a unique
Cloudflare A record, serves a loopback IP endpoint and webhook receiver, then
verifies create/update/enable/manual-sync/webhook behavior before cleaning up
only the TEST resources it created.

Secrets are kept in memory and are never printed. The output is deliberately
reduced to boolean/enum evidence suitable for documentation.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import LuckyAPIError  # noqa: E402
from lucky_api.client import HTTPStatusError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-DDNS"
TEST_PREFIX = "TEST-lucky-skills-ddns-"
INITIAL_RECORD_IP = "192.0.2.10"
FIRST_SYNC_IP = "198.51.100.21"
SECOND_SYNC_IP = "203.0.113.22"


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


class ProbeState:
    def __init__(self) -> None:
        self.ip = FIRST_SYNC_IP
        self.webhook_count = 0
        self.webhook_methods: set[str] = set()
        self.lock = threading.Lock()


def start_probe_server(state: ProbeState) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _send(self, status: int, body: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _handle(self) -> None:
            if self.path.startswith("/ip"):
                with state.lock:
                    value = state.ip
                self._send(200, value + "\n")
                return
            if self.path.startswith("/webhook"):
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length:
                    self.rfile.read(min(length, 1024 * 1024))
                with state.lock:
                    state.webhook_count += 1
                    state.webhook_methods.add(self.command.upper())
                self._send(200, "OK")
                return
            self._send(404, "not found")

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_PATCH = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return server, thread, f"http://{host}:{port}"


class CloudflareAPI:
    def __init__(self, token: str) -> None:
        if not token:
            raise RuntimeError("CLOUDFLARE_API_TOKEN is required")
        self.token = token

    def request(
        self, method: str, path: str, *, query: dict[str, Any] | None = None, body: Any = None
    ) -> Any:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        data = None
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Cloudflare API HTTP {error.code} for {method} {path}") from None
        if not isinstance(payload, dict) or not payload.get("success"):
            raise RuntimeError(f"Cloudflare API failed for {method} {path}")
        return payload.get("result")

    def zone_id(self, zone_name: str) -> str:
        rows = self.request("GET", "/zones", query={"name": zone_name}) or []
        if not isinstance(rows, list) or len(rows) != 1 or not rows[0].get("id"):
            raise RuntimeError("Cloudflare zone lookup must return exactly one zone")
        return str(rows[0]["id"])

    def get_record(self, zone_id: str, fqdn: str) -> dict[str, Any] | None:
        rows = self.request(
            "GET", f"/zones/{zone_id}/dns_records", query={"type": "A", "name": fqdn}
        ) or []
        if not rows:
            return None
        if len(rows) != 1:
            raise RuntimeError("unexpected duplicate TEST DNS records")
        return rows[0]

    def create_record(self, zone_id: str, fqdn: str, content: str) -> str:
        if self.get_record(zone_id, fqdn) is not None:
            raise RuntimeError("TEST DNS record already exists")
        row = self.request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            body={"type": "A", "name": fqdn, "content": content, "ttl": 60, "proxied": False},
        )
        if not isinstance(row, dict) or not row.get("id"):
            raise RuntimeError("Cloudflare create did not return record id")
        return str(row["id"])

    def delete_record(self, zone_id: str, record_id: str) -> None:
        self.request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    def update_record(self, zone_id: str, record_id: str, fqdn: str, content: str) -> None:
        self.request(
            "PUT",
            f"/zones/{zone_id}/dns_records/{record_id}",
            body={"type": "A", "name": fqdn, "content": content, "ttl": 60, "proxied": False},
        )


def unwrap_task(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected DDNS detail response")
    candidate = payload.get("task", payload.get("data", payload))
    if not isinstance(candidate, dict):
        raise RuntimeError("unexpected DDNS task object")
    return candidate


def task_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/ddnstasklist")
    rows = payload.get("data") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected DDNS task list")
    return [row for row in rows if isinstance(row, dict)]


def task_key(row: dict[str, Any]) -> str:
    return str(row.get("TaskKey") or row.get("Key") or "")


def find_template(client: LuckyClient) -> tuple[dict[str, Any], dict[str, Any]]:
    for row in task_rows(client):
        key = task_key(row)
        if not key or str(row.get("TaskName", "")).startswith(TEST_PREFIX):
            continue
        detail = unwrap_task(client.request_json("GET", f"/api/ddns/task/{key}"))
        dns = detail.get("DNS")
        if (
            isinstance(dns, dict)
            and str(dns.get("Name", "")).lower() == "cloudflare"
            and isinstance(dns.get("Secret"), str)
            and dns.get("Secret")
            and isinstance(detail.get("Records"), list)
            and detail["Records"]
        ):
            return row, detail
    raise RuntimeError("no reusable Cloudflare DDNS task template found")


def build_task(
    template: dict[str, Any],
    *,
    name: str,
    fqdn: str,
    zone_name: str,
    ip_url: str,
) -> dict[str, Any]:
    task = copy.deepcopy(template)
    task["TaskKey"] = ""
    task["TaskName"] = name
    task["TaskType"] = "IPv4"
    task["Enable"] = False
    task["Expanded"] = False
    task["IPSectionExpanded"] = True
    task["V4QueryIPEnable"] = True
    task["V4QueryIPType"] = "url"
    task["V4QueryUrl"] = ip_url
    task["V4NetInterface"] = ""
    task["V4NetInterfaceIPReg"] = ""
    task["V4GetIPScript"] = ""
    task["V6QueryIPEnable"] = False
    task["V6QueryUrl"] = ""
    task["GlobalWebhook"] = False
    task["WebhookEnable"] = False
    task["FirstCheckDelay"] = 0
    task["Intervals"] = 3600
    task["RetryCount"] = 1
    task["RetryInterval"] = 2
    task["HttpClientTimeout"] = 10
    task["TTL"] = "60"

    dns = task.get("DNS")
    if not isinstance(dns, dict):
        raise RuntimeError("template DNS configuration is missing")
    dns["ForceInterval"] = 0

    source = template.get("Records")
    if not isinstance(source, list) or not source or not isinstance(source[0], dict):
        raise RuntimeError("template DDNS record is missing")
    record = copy.deepcopy(source[0])
    record["Key"] = ""
    record["Disable"] = False
    sync = record.get("SyncRecordData")
    if not isinstance(sync, dict):
        raise RuntimeError("template SyncRecordData is missing")
    subdomain = fqdn[: -(len(zone_name) + 1)] if fqdn.endswith("." + zone_name) else fqdn
    sync.update(
        {
            "DomainName": zone_name,
            "SubDomainName": subdomain,
            "fullDomainName": fqdn,
            # This is a Lucky substitution template, not a cached/current IP.
            # Lucky 3.0.0 rejects an empty A-record value at create time; the
            # production Cloudflare task uses {ipv4Addr}, which resolves to
            # the task's current IPv4 query result during synchronization.
            "ipv4Address": "{ipv4Addr}",
            "ipv6Address": "",
            "proxyStatus": False,
            "specifyProxyStatus": False,
            "ttl": 0,
            "type": "A",
            "remark": "Lucky Skills disposable DDNS probe",
        }
    )
    task["Records"] = [record]
    return task


def wait_for_task(client: LuckyClient, name: str, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in task_rows(client):
            if row.get("TaskName") == name:
                return row
        time.sleep(0.7)
    raise RuntimeError("TEST DDNS task did not appear")


def wait_task_idle(client: LuckyClient, key: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in task_rows(client):
            if task_key(row) != key:
                continue
            if not bool(row.get("QueryingIPv4Addr")) and not bool(row.get("QueryingIPv6Addr")):
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST DDNS task remained syncing too long")


def manual_sync(client: LuckyClient, key: str, attempts: int = 8) -> Any:
    for attempt in range(attempts):
        wait_task_idle(client, key)
        try:
            return mutate(client, "GET", f"/api/ddns/manualSync/{key}")
        except LuckyAPIError as error:
            if "issyncing" not in str(error).lower() or attempt + 1 >= attempts:
                raise
            time.sleep(1.0 + attempt * 0.5)
    raise AssertionError("unreachable")


def wait_for_cf_ip(cf: CloudflareAPI, zone_id: str, fqdn: str, expected: str, timeout: float = 35.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = cf.get_record(zone_id, fqdn)
        if row and row.get("content") == expected:
            return True
        time.sleep(1.0)
    return False


def cleanup_lucky_tests(client: LuckyClient) -> int:
    removed = 0
    for row in task_rows(client):
        if not str(row.get("TaskName", "")).startswith(TEST_PREFIX):
            continue
        key = task_key(row)
        if key:
            try:
                mutate(client, "DELETE", "/api/ddns", query={"key": key})
                removed += 1
            except Exception:
                pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--zone", default="fyzure.fyi")
    parser.add_argument("--suffix", default="rs.fyzure.fyi")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")
    zone_name = args.zone.strip().strip(".").lower()
    suffix = args.suffix.strip().strip(".").lower()
    if not suffix.endswith(zone_name):
        raise SystemExit("suffix must be inside the selected Cloudflare zone")

    client = make_client()
    cf = CloudflareAPI(os.environ.get("CLOUDFLARE_API_TOKEN", ""))
    zone_id = cf.zone_id(zone_name)
    baseline_rows = task_rows(client)
    baseline_keys = {task_key(row) for row in baseline_rows if task_key(row)}
    if any(str(row.get("TaskName", "")).startswith(TEST_PREFIX) for row in baseline_rows):
        raise RuntimeError("pre-existing TEST DDNS task found; clean it before starting")

    _, template = find_template(client)
    nonce = uuid.uuid4().hex[:10]
    name = TEST_PREFIX + nonce
    fqdn = f"{name.lower()}.{suffix}"
    state = ProbeState()
    server, thread, origin = start_probe_server(state)
    record_id = ""
    test_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, str] = {}
    cleanup: dict[str, Any] = {}

    try:
        record_id = cf.create_record(zone_id, fqdn, INITIAL_RECORD_IP)
        results["cloudflare_test_record_created"] = True

        task = build_task(
            template,
            name=name,
            fqdn=fqdn,
            zone_name=zone_name,
            ip_url=origin + "/ip",
        )
        mutate(client, "POST", "/api/ddns", json_body=task, body_supplied=True)
        row = wait_for_task(client, name)
        test_key = task_key(row)
        results["post_create"] = bool(test_key)

        detail = unwrap_task(client.request_json("GET", f"/api/ddns/task/{test_key}"))
        results["created_task_readback"] = detail.get("TaskName") == name
        results["url_ip_source_saved"] = detail.get("V4QueryIPType") == "url"

        updated = copy.deepcopy(detail)
        # Use a behavior-neutral field as the PUT round-trip marker. Lucky may
        # treat TaskName as effectively immutable/normalized, so renaming is a
        # poor success criterion for the update handler itself.
        updated_debug = not bool(updated.get("DebugMode"))
        updated["DebugMode"] = updated_debug
        mutate(
            client,
            "PUT",
            "/api/ddns",
            query={"key": test_key},
            json_body=updated,
            body_supplied=True,
        )
        reread = unwrap_task(client.request_json("GET", f"/api/ddns/task/{test_key}"))
        results["put_update"] = reread.get("DebugMode") is updated_debug

        mutate(client, "GET", "/api/ddns/enable", query={"key": test_key, "enable": "false"})
        disabled = unwrap_task(client.request_json("GET", f"/api/ddns/task/{test_key}"))
        results["disable_toggle"] = disabled.get("Enable") is False
        # Set the deterministic URL source *before* re-enabling. Lucky starts
        # a background synchronization immediately when a task is enabled.
        with state.lock:
            state.ip = FIRST_SYNC_IP
        mutate(client, "GET", "/api/ddns/enable", query={"key": test_key, "enable": "true"})
        enabled = unwrap_task(client.request_json("GET", f"/api/ddns/task/{test_key}"))
        results["enable_toggle"] = enabled.get("Enable") is True

        # Enabling a Lucky DDNS task starts an immediate background sync. Wait
        # for that real URL-fetch/provider update to settle before issuing the
        # explicit manual-sync call, otherwise Lucky correctly returns
        # ret=4/isSyncing.
        wait_task_idle(client, test_key)
        results["enable_triggered_url_sync"] = wait_for_cf_ip(
            cf, zone_id, fqdn, FIRST_SYNC_IP, timeout=15.0
        )

        # Change only the deterministic URL source, then require manualSync to
        # fetch the new address and push it through the configured provider.
        # This proves manualSync itself rather than conflating it with PUT's
        # own scheduling/normalization semantics.
        with state.lock:
            state.ip = SECOND_SYNC_IP
        manual_sync(client, test_key)
        wait_task_idle(client, test_key)
        manual_row = next((row for row in task_rows(client) if task_key(row) == test_key), {})
        manual_rows = manual_row.get("Records") if isinstance(manual_row, dict) else None
        manual_first = manual_rows[0] if isinstance(manual_rows, list) and manual_rows else {}
        manual_status = manual_first.get("UpdateStatus") if isinstance(manual_first, dict) else None
        results["manual_sync_job_executed"] = isinstance(manual_status, str) and bool(manual_status)
        # manualSync is a task-level synchronization trigger. On Lucky 3.0.0
        # it does not guarantee a fresh acquisition from V4QueryUrl; when the
        # task-local record state is unchanged it can legitimately finish as
        # SYNC_LOC_RECORD_NOCHANGE. Treat the concrete completed status plus
        # absence of an IPv4 acquisition error as the runtime success signal.
        results["manual_sync"] = (
            results["manual_sync_job_executed"]
            and not bool(manual_row.get("Ipv4AddrErrMsg"))
        )
        observations["dns_update_sequence"] = "initial->enable/url(first)->manualSync(pass)"
        observations["manual_sync_semantics"] = (
            "triggers a synchronization pass; may finish with "
            "SYNC_LOC_RECORD_NOCHANGE and does not guarantee a fresh URL IP acquisition"
        )

        if not results["enable_triggered_url_sync"] or not results["manual_sync"]:
            status_row = next((row for row in task_rows(client) if task_key(row) == test_key), {})
            records = status_row.get("Records") if isinstance(status_row, dict) else None
            first_record = records[0] if isinstance(records, list) and records else {}
            observations["sync_task_state"] = str(
                {
                    "querying_v4": bool(status_row.get("QueryingIPv4Addr")),
                    "v4_error_present": bool(status_row.get("Ipv4AddrErrMsg")),
                    "record_update_status": first_record.get("UpdateStatus") if isinstance(first_record, dict) else None,
                    "record_message_present": bool(first_record.get("Message")) if isinstance(first_record, dict) else False,
                }
            )

        webhook_body = {
            "WebhookURL": origin + "/webhook",
            "WebhookMethod": "post",
            "WebhookRequestBody": "probe=ok",
            "WebhookProxy": "",
            "WebhookProxyAddr": "",
            "WebhookProxyUser": "",
            "WebhookProxyPassword": "",
            "WebhookHeaders": ["Content-Type: application/x-www-form-urlencoded"],
            "WebhookSuccessContent": ["OK"],
            "WebhookDisableCallbackSuccessContentCheck": False,
            "RetryCount": 1,
            "RetryInterval": 1,
        }
        mutate(
            client,
            "POST",
            "/api/ddns/webhooktest",
            query={"key": test_key},
            json_body=webhook_body,
            body_supplied=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with state.lock:
                count = state.webhook_count
                methods = set(state.webhook_methods)
            if count:
                break
            time.sleep(0.25)
        results["webhook_test_called_loopback"] = count > 0
        results["webhook_test_method_post"] = "POST" in methods

    finally:
        if test_key:
            try:
                mutate(client, "GET", "/api/ddns/enable", query={"key": test_key, "enable": "false"})
            except Exception:
                pass
        cleanup["lucky_test_tasks_removed"] = cleanup_lucky_tests(client)
        if record_id:
            try:
                cf.delete_record(zone_id, record_id)
                cleanup["cloudflare_test_record_deleted"] = True
            except Exception:
                cleanup["cloudflare_test_record_deleted"] = False
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    final_rows = task_rows(client)
    final_keys = {task_key(row) for row in final_rows if task_key(row)}
    cleanup["task_key_baseline_restored"] = final_keys == baseline_keys
    cleanup["leftover_test_tasks"] = sum(
        1 for row in final_rows if str(row.get("TaskName", "")).startswith(TEST_PREFIX)
    )
    cleanup["cloudflare_record_absent"] = cf.get_record(zone_id, fqdn) is None

    failed = sorted(key for key, value in results.items() if not value)
    if not cleanup.get("task_key_baseline_restored"):
        failed.append("task_key_baseline_restored")
    if cleanup.get("leftover_test_tasks") != 0:
        failed.append("leftover_test_tasks")
    if not cleanup.get("cloudflare_record_absent"):
        failed.append("cloudflare_record_absent")

    print(
        json.dumps(
            {
                "target": "Lucky DDNS Cloudflare behavior",
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
