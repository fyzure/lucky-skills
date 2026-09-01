#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Coraza + WebService WAF integration.

The probe creates one enabled TEST Coraza instance using Lucky's bundled OWASP
Core Rule Set, appends one reverse-proxy TEST subrule to an existing TLS
listener, verifies a normal request reaches a loopback origin, then sends only
harmless SQLi/XSS-shaped query strings and requires Coraza to block at least
one. It reads WAF event/log surfaces without persisting request contents and
removes only the TEST subrule/instance from the latest runtime objects.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-CORAZA-WAF"
TEST_PREFIX = "TEST-lucky-skills-waf-"
UPSTREAM_MARKER = "lucky-skills-waf-origin-ok"


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
            time.sleep(7.0 + attempt * 4.0)
    raise AssertionError("unreachable")


def unwrap_rule(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected WebService rule response")
    candidate = payload.get("rule", payload.get("ruleInfo", payload))
    if not isinstance(candidate, dict):
        raise RuntimeError("unexpected WebService rule object")
    return candidate


def coraza_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/coraza/list")
    value = payload.get("list") if isinstance(payload, dict) else None
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("unexpected Coraza list response")
    return [item for item in value if isinstance(item, dict)]


def key_of(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def wait_coraza(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in coraza_rows(client):
            if row.get("Name") == name:
                return row
        time.sleep(0.4)
    raise RuntimeError("TEST Coraza instance did not appear")


class OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = UPSTREAM_MARKER.encode("utf-8")
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


def https_request(host: str, *, resolve_ip: str, path: str) -> tuple[int, str]:
    command = [
        "curl",
        "-skS",
        "--http1.1",
        "--max-time",
        "12",
        "--max-redirs",
        "0",
        "--resolve",
        f"{host}:443:{resolve_ip}",
        "-o",
        "-",
        "-w",
        "\n%{http_code}",
        f"https://{host}{path}",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode not in {0, 22, 47}:
        raise RuntimeError(f"curl WAF probe failed with exit {result.returncode}")
    body, _, status_text = result.stdout.rpartition("\n")
    try:
        status = int(status_text.strip())
    except ValueError:
        status = 0
    return status, body


def is_test_subrule(item: Any) -> bool:
    return isinstance(item, dict) and str(item.get("Remark", "")).startswith(TEST_PREFIX)


def cleanup_webservice(client: LuckyClient, rule_path: str) -> tuple[int, bool]:
    time.sleep(5.0)
    for attempt in range(6):
        current = unwrap_rule(client.request_json("GET", rule_path))
        before = list(current.get("ProxyList") or [])
        after = [item for item in before if not is_test_subrule(item)]
        removed = len(before) - len(after)
        if not removed:
            return 0, True
        current["ProxyList"] = after
        try:
            mutate(client, "PUT", rule_path, json_body=current, body_supplied=True)
        except HTTPStatusError as error:
            if error.status != 429 or attempt == 5:
                raise
            time.sleep(8.0 + attempt * 4.0)
            continue
        verify = unwrap_rule(client.request_json("GET", rule_path))
        return removed, not any(is_test_subrule(x) for x in verify.get("ProxyList") or [])
    return 0, False


def cleanup_coraza(client: LuckyClient) -> int:
    removed = 0
    for row in coraza_rows(client):
        if not str(row.get("Name", "")).startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", f"/api/coraza/list/{key}")
            removed += 1
        except Exception:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--rule-key", default="kIzGrqLbhE1KR5QE")
    parser.add_argument("--domain-suffix", default="rs.fyzure.fyi")
    parser.add_argument("--resolve-ip", default="127.0.0.1")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    rule_path = f"/api/webservice/rule/{args.rule_key}"
    parent = unwrap_rule(client.request_json("GET", rule_path))
    original_proxy = copy.deepcopy(parent.get("ProxyList") or [])
    if any(is_test_subrule(item) for item in original_proxy):
        raise RuntimeError("pre-existing TEST WAF subrule found")
    coraza_baseline = {key_of(row) for row in coraza_rows(client) if key_of(row)}
    if any(str(row.get("Name", "")).startswith(TEST_PREFIX) for row in coraza_rows(client)):
        raise RuntimeError("pre-existing TEST Coraza instance found")

    crs_payload = client.request_json("GET", "/api/coraza/OWASPCoreRuleset")
    crs = crs_payload.get("rules") if isinstance(crs_payload, dict) else None
    if not isinstance(crs, list) or not crs:
        raise RuntimeError("Lucky bundled OWASP Core Rule Set is unavailable")
    crs_names = sorted(str(item) for item in crs if isinstance(item, str) and item)

    nonce = secrets.token_hex(5)
    name = TEST_PREFIX + nonce
    host = f"{name.lower()}.{args.domain_suffix.strip('.').lower()}"
    origin, origin_thread, origin_port = start_origin()
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {"crs_file_count": len(crs_names)}
    cleanup: dict[str, Any] = {}
    instance_key = ""
    subrule_key = ""

    try:
        mutate(
            client,
            "POST",
            "/api/coraza/list",
            json_body={
                "Key": "",
                "Name": name,
                "Enable": True,
                "InboundScoreThreshold": 1,
                "OutboundScoreThreshold": 1,
                "CorazaWAFConfigList": [
                    {
                        "Enable": True,
                        "Remark": "Lucky Skills full bundled OWASP CRS",
                        "Type": "OWASPCoreRuleset",
                        "Param": "\n".join(crs_names),
                    }
                ],
                "RuleExclusions": [],
            },
            body_supplied=True,
        )
        instance = wait_coraza(client, name)
        instance_key = key_of(instance)
        results["coraza_instance_create"] = bool(instance_key)

        detail = client.request_json("GET", f"/api/coraza/list/{instance_key}")
        cfg = detail.get("instance") if isinstance(detail, dict) else None
        results["coraza_enabled"] = isinstance(cfg, dict) and cfg.get("Enable") is True
        rules = cfg.get("CorazaWAFConfigList") if isinstance(cfg, dict) else None
        results["crs_attached"] = isinstance(rules, list) and len(rules) == 1

        if not original_proxy:
            raise RuntimeError("existing TLS listener has no reverse-proxy template")
        template = copy.deepcopy(original_proxy[0])
        template.pop("Key", None)
        template.pop("GroupKey", None)
        template.update(
            {
                "Enable": True,
                "Remark": name,
                "Domains": [host],
                "Locations": [f"http://127.0.0.1:{origin_port}"],
                "WebServiceType": "reverseproxy",
                "EnableBasicAuth": False,
                "BasicAuthUserList": "",
                "AuthSource": "local",
                "SecurityGroupKeys": [],
                "SecurityGroupAccessMode": "disabled",
                "CorazaWAFInstance": instance_key,
                "MaxCorazaInterceptionCount": 0,
                "WafLogMaxNum": 128,
                "NginxConf": "",
                "DisplayInFrontendList": False,
                "EnableAccessLog": False,
                "DisableStatistics": False,
            }
        )
        other = copy.deepcopy(template.get("OtherParams") or {})
        other["WebAuth"] = False
        other["ProxyProtocolV2"] = False
        template["OtherParams"] = other
        current = unwrap_rule(client.request_json("GET", rule_path))
        current["ProxyList"] = list(current.get("ProxyList") or []) + [template]
        mutate(client, "PUT", rule_path, json_body=current, body_supplied=True)
        time.sleep(2.0)
        attached = unwrap_rule(client.request_json("GET", rule_path))
        found = [item for item in attached.get("ProxyList") or [] if is_test_subrule(item)]
        results["webservice_subrule_create"] = len(found) == 1
        if found:
            subrule_key = str(found[0].get("Key") or "")
            results["webservice_waf_binding"] = found[0].get("CorazaWAFInstance") == instance_key

        status, body = https_request(host, resolve_ip=args.resolve_ip, path="/normal")
        results["normal_request_passes"] = status == 200 and UPSTREAM_MARKER in body

        attack_paths = [
            "/?id=1%20OR%201%3D1--",
            "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/?file=..%2F..%2Fetc%2Fpasswd",
        ]
        attack_statuses: list[int] = []
        for path in attack_paths:
            code, _ = https_request(host, resolve_ip=args.resolve_ip, path=path)
            attack_statuses.append(code)
            if code in {403, 406, 418, 429}:
                break
        observations["attack_status_classes"] = [f"{code // 100}xx" if code else "unknown" for code in attack_statuses]
        results["attack_request_blocked"] = any(code in {403, 406, 418, 429} for code in attack_statuses)

        listing = client.request_json("GET", "/api/webservice/rules")
        stats = listing.get("statistics") if isinstance(listing, dict) else None
        protected = False
        if isinstance(stats, dict):
            for value in stats.values():
                if isinstance(value, dict) and int(value.get("CorazaProtectionTimes") or 0) > 0:
                    protected = True
                    break
        results["waf_statistics_incremented"] = protected

        if subrule_key:
            try:
                waf_logs = client.request_json(
                    "GET",
                    f"/api/webservice/{args.rule_key}/{subrule_key}/corazalogs",
                    query={"page": 1, "pageSize": 20},
                )
                results["waf_log_surface"] = isinstance(waf_logs, dict) and waf_logs.get("ret") == 0
                log_items = waf_logs.get("logs") if isinstance(waf_logs, dict) else None
                observations["waf_log_count"] = len(log_items) if isinstance(log_items, list) else 0
            except Exception:
                results["waf_log_surface"] = False

        try:
            events = client.request_json(
                "GET",
                "/api/webservice/statistics/waf/events",
                query={"page": 1, "pageSize": 20},
            )
            results["waf_event_surface"] = isinstance(events, dict) and events.get("ret") == 0
            for key in ("events", "list", "data"):
                value = events.get(key) if isinstance(events, dict) else None
                if isinstance(value, list):
                    observations["waf_event_count"] = len(value)
                    break
        except Exception:
            results["waf_event_surface"] = False
    finally:
        try:
            removed, absent = cleanup_webservice(client, rule_path)
            cleanup["webservice_test_subrules_removed"] = removed
            cleanup["webservice_test_subrules_absent"] = absent
        finally:
            cleanup["coraza_test_instances_removed"] = cleanup_coraza(client)
            origin.shutdown()
            origin.server_close()
            origin_thread.join(timeout=2)

    final_parent = unwrap_rule(client.request_json("GET", rule_path))
    final_proxy = final_parent.get("ProxyList") or []
    cleanup["business_subrules_unchanged"] = final_proxy == original_proxy
    final_coraza = coraza_rows(client)
    cleanup["coraza_key_baseline_restored"] = {
        key_of(row) for row in final_coraza if key_of(row)
    } == coraza_baseline
    cleanup["leftover_test_coraza"] = sum(
        1 for row in final_coraza if str(row.get("Name", "")).startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if not value)
    for key in (
        "webservice_test_subrules_absent",
        "business_subrules_unchanged",
        "coraza_key_baseline_restored",
    ):
        if not cleanup.get(key):
            failed.append(key)
    if cleanup.get("leftover_test_coraza") != 0:
        failed.append("leftover_test_coraza")

    print(
        json.dumps(
            {
                "target": "Lucky Coraza + WebService WAF behavior",
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
