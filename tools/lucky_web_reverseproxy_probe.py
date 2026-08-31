#!/usr/bin/env python3
"""Runtime-verify Lucky v3 WebService reverse-proxy semantics.

This is an explicitly mutating integration probe for an instance owner. It
adds a small set of uniquely named TEST subrules to one existing TLS WebService
listener, exercises them through the listener, and then removes only those
TEST subrules from the latest rule object.

The probe deliberately uses one setup PUT and one cleanup PUT so it does not
hammer Lucky's write-rate limit. Cleanup retries 429 responses with backoff and
never restores a stale full-rule snapshot over concurrent business changes.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, LuckyClientError, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-WEB-REVERSE-PROXY"
TEST_PREFIX = "TEST-lucky-skills-websem-"
DEFAULT_ECHO_ORIGIN = "https://httpbin.org"


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(base_url, token, catalog=catalog, retries=0)
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(values["base_url"], values["open_token"], catalog=catalog, retries=0)


def unwrap_rule(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected WebService rule response")
    candidate = payload.get("rule", payload.get("ruleInfo", payload))
    if not isinstance(candidate, dict):
        raise RuntimeError("unexpected WebService rule object")
    return candidate


def is_test_subrule(item: Any) -> bool:
    return isinstance(item, dict) and str(item.get("Remark", "")).startswith(TEST_PREFIX)


def normalize_suffix(value: str) -> str:
    suffix = value.strip().strip(".").lower()
    if not suffix or "*" in suffix or "/" in suffix or ":" in suffix:
        raise ValueError("domain suffix must be a plain DNS suffix such as rs.example.com")
    labels = suffix.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        raise ValueError("invalid domain suffix")
    return suffix


def origin_base(value: str) -> str:
    origin = value.strip().rstrip("/")
    if not origin.startswith("https://"):
        raise ValueError("echo origin must use https://")
    return origin


def put_rule(client: LuckyClient, path: str, rule: dict[str, Any]) -> None:
    client.request_json("PUT", path, json_body=rule, allow_unsafe=True)


def cleanup_test_subrules(
    client: LuckyClient,
    path: str,
    *,
    attempts: int = 6,
    initial_delay: float = 8.0,
) -> tuple[int, bool]:
    time.sleep(initial_delay)
    removed = 0
    for attempt in range(attempts):
        current = unwrap_rule(client.request_json("GET", path))
        before = list(current.get("ProxyList") or [])
        after = [item for item in before if not is_test_subrule(item)]
        removed = len(before) - len(after)
        if removed == 0:
            return 0, True
        current["ProxyList"] = after
        try:
            put_rule(client, path, current)
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(10.0 + attempt * 4.0)
            continue
        time.sleep(3.0)
        verified = unwrap_rule(client.request_json("GET", path))
        return removed, not any(is_test_subrule(item) for item in verified.get("ProxyList") or [])
    return removed, False


def make_subrule(
    template: dict[str, Any],
    *,
    label: str,
    hostname: str,
    frontend_path: str,
    location: str,
    updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item = copy.deepcopy(template)
    item.pop("Key", None)
    item.pop("GroupKey", None)
    item.update(
        {
            "Enable": True,
            "Remark": TEST_PREFIX + label,
            "Domains": [hostname + frontend_path],
            "Locations": [location],
            "WebServiceType": "reverseproxy",
            "LocationInsecureSkipVerify": False,
            "EnableAccessLog": False,
            "DisableStatistics": True,
            "DisplayInFrontendList": False,
            "EnableBasicAuth": False,
            "SecurityGroupKeys": [],
            "SecurityGroupAccessMode": "disabled",
            "NginxConf": "",
            "AutoProxyLocation": False,
            "AutoProxyLocationWithoutSameHost": False,
            "AddProtoToHeader": False,
            "ProtoHeaderKey": "",
            "AddRemoteIPToHeader": False,
            "AddRemoteIPHeaderKey": "",
        }
    )
    if updates:
        item.update(updates)
    return item


def parse_headers(path: Path) -> tuple[int, dict[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    blocks = [block for block in text.split("\n\n") if block.strip()]
    header_block = blocks[-1] if blocks else ""
    lines = header_block.splitlines()
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status, headers


def request_via_lucky(
    hostname: str,
    frontend_path: str,
    relative_path: str,
    *,
    resolve_ip: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    if shutil.which("curl") is None:
        raise RuntimeError("curl is required for the external HTTPS behavior probe")
    url = f"https://{hostname}{frontend_path}{relative_path}"
    with tempfile.NamedTemporaryFile(prefix="lucky-probe-headers-", delete=False) as handle:
        header_path = Path(handle.name)
    try:
        command = [
            "curl",
            "-sS",
            "--http1.1",
            "--max-time",
            "15",
            "--max-redirs",
            "0",
            "--resolve",
            f"{hostname}:443:{resolve_ip}",
            "-D",
            str(header_path),
        ]
        for key, value in (headers or {}).items():
            command.extend(["-H", f"{key}: {value}"])
        command.append(url)
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        status, response_headers = parse_headers(header_path)
        if result.returncode not in {0, 47}:
            detail = result.stderr.strip()[:300]
            raise RuntimeError(f"curl probe failed with exit {result.returncode}: {detail}")
        return status, response_headers, result.stdout
    finally:
        header_path.unlink(missing_ok=True)


def json_body(body: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError("echo origin returned a non-JSON body") from error
    if not isinstance(value, dict):
        raise RuntimeError("echo origin returned a non-object JSON body")
    return value


def lower_headers(payload: dict[str, Any]) -> dict[str, str]:
    raw = payload.get("headers")
    if not isinstance(raw, dict):
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items()}


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def classify_path(value: str, frontend: str, stripped: str) -> str:
    if value == frontend:
        return "frontend-path"
    if value == stripped:
        return "stripped-path"
    return "other"


def classify_connection_upgrade(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        return "empty-or-omitted"
    if normalized in {"upgrade", "close"}:
        return normalized
    return "other"


def redact_frontend_location(value: str, hostname: str) -> str:
    return value.replace(f"https://{hostname}", "https://<frontend>").replace(
        f"http://{hostname}", "http://<frontend>"
    )


def run_probe(
    client: LuckyClient,
    *,
    rule_key: str,
    suffix: str,
    resolve_ip: str,
    echo_origin: str,
) -> dict[str, Any]:
    path = f"/api/webservice/rule/{rule_key}"
    baseline = unwrap_rule(client.request_json("GET", path))
    if any(is_test_subrule(item) for item in baseline.get("ProxyList") or []):
        raise RuntimeError("existing TEST reverse-proxy subrules found; clean them before starting a new probe")
    business_before = copy.deepcopy(list(baseline.get("ProxyList") or []))
    template = next(
        (
            item
            for item in business_before
            if isinstance(item, dict) and item.get("WebServiceType") == "reverseproxy"
        ),
        None,
    )
    if template is None:
        raise RuntimeError("target WebService listener has no reverseproxy subrule to use as a model")

    nonce = uuid.uuid4().hex[:8]

    def host(label: str) -> str:
        return f"test-{nonce}-{label}.{suffix}"

    core_conf = """# Lucky Skills semantic probe
proxy_set_header X-Literal "alpha beta";
proxy_set_header X-Host $host;
proxy_set_header X-Http-Host $http_host;
proxy_set_header X-Scheme $scheme;
proxy_set_header X-Request $request;
proxy_set_header X-Method $request_method;
proxy_set_header X-Request-Uri $request_uri;
proxy_set_header X-Uri $uri;
proxy_set_header X-Document-Uri $document_uri;
proxy_set_header X-Args $args;
proxy_set_header X-Query-String $query_string;
proxy_set_header X-Is-Args $is_args;
proxy_set_header X-Remote-Addr $remote_addr;
proxy_set_header X-Remote-Port $remote_port;
proxy_set_header X-Server-Port $server_port;
proxy_set_header X-Http-Upgrade $http_upgrade;
proxy_set_header X-Connection-Upgrade $connection_upgrade;
proxy_set_header X-Proxy-XFF $proxy_add_x_forwarded_for;
proxy_set_header X-Input $http_x_probe_input;
proxy_set_header X-Remove "";
add_header X-Base base always;
location /api/ { add_header X-Loc-Prefix yes always; }
location = /exact { add_header X-Loc-Exact yes always; }
location ~ ^/v[0-9]{1,2}/ { add_header X-Loc-Regex yes always; }
location ~* ^/CASE/ { add_header X-Loc-Regex-I yes always; }
location !~ ^/blocked/ { add_header X-Loc-Neg yes always; }
path /wild/* add_header X-Path-Wild yes always;
path regexp:^/rx[0-9]+/ add_header X-Path-Regex yes always;
path !!!/deny/* add_header X-Path-Neg yes always;
"""

    test_subrules = [
        make_subrule(
            template,
            label="core",
            hostname=host("core"),
            frontend_path="/front",
            location=echo_origin + "/anything/backend-base",
            updates={"UseTargetHost": True, "NginxConf": core_conf},
        ),
        make_subrule(
            template,
            label="resp",
            hostname=host("resp"),
            frontend_path="/resp",
            location=echo_origin,
            updates={
                "UseTargetHost": True,
                "NginxConf": (
                    "proxy_hide_header X-Upstream-Secret;\n"
                    "add_header X-Default default;\n"
                    "add_header X-Always always always;\n"
                    "proxy_redirect http://backend/ /rewritten/;\n"
                ),
            },
        ),
        make_subrule(
            template,
            label="host-target",
            hostname=host("host-target"),
            frontend_path="/h",
            location=echo_origin + "/anything/host",
            updates={"UseTargetHost": True},
        ),
        make_subrule(
            template,
            label="host-public",
            hostname=host("host-public"),
            frontend_path="/h",
            location=echo_origin + "/anything/host",
            updates={"UseTargetHost": False},
        ),
        make_subrule(
            template,
            label="helpers",
            hostname=host("helpers"),
            frontend_path="/h",
            location=echo_origin + "/anything/helpers",
            updates={
                "UseTargetHost": True,
                "AddProtoToHeader": True,
                "ProtoHeaderKey": "X-Lucky-Proto",
                "AddRemoteIPToHeader": True,
                "AddRemoteIPHeaderKey": "X-Lucky-Client-IP",
            },
        ),
        make_subrule(
            template,
            label="redirect-off",
            hostname=host("redirect-off"),
            frontend_path="/r",
            location=echo_origin,
            updates={"UseTargetHost": True},
        ),
        make_subrule(
            template,
            label="redirect-on",
            hostname=host("redirect-on"),
            frontend_path="/r",
            location=echo_origin,
            updates={"UseTargetHost": True, "AutoProxyLocation": True},
        ),
        make_subrule(
            template,
            label="redirect-diff",
            hostname=host("redirect-diff"),
            frontend_path="/r",
            location=echo_origin,
            updates={
                "UseTargetHost": True,
                "AutoProxyLocation": True,
                "AutoProxyLocationWithoutSameHost": True,
            },
        ),
        make_subrule(
            template,
            label="redir-off-conf",
            hostname=host("redir-off-conf"),
            frontend_path="/r",
            location=echo_origin,
            updates={"UseTargetHost": True, "NginxConf": "proxy_redirect off;\n"},
        ),
        make_subrule(
            template,
            label="redir-default-conf",
            hostname=host("redir-default-conf"),
            frontend_path="/r",
            location=echo_origin,
            updates={"UseTargetHost": True, "NginxConf": "proxy_redirect default;\n"},
        ),
    ]

    setup = copy.deepcopy(baseline)
    setup["ProxyList"] = business_before + test_subrules
    results: dict[str, bool] = {}
    observations: dict[str, str] = {}
    primary_error: BaseException | None = None
    cleanup_removed = 0
    cleanup_ok = False
    try:
        put_rule(client, path, setup)
        time.sleep(5.0)
        live = unwrap_rule(client.request_json("GET", path))
        live_tests = [item for item in live.get("ProxyList") or [] if is_test_subrule(item)]
        by_remark = {str(item.get("Remark")): item for item in live_tests}
        results["all_test_subrules_round_trip"] = len(live_tests) == len(test_subrules)
        results["nginxconf_round_trip"] = (
            by_remark.get(TEST_PREFIX + "core", {}).get("NginxConf") == core_conf
        )
        results["proxy_redirect_off_round_trip"] = (
            by_remark.get(TEST_PREFIX + "redir-off-conf", {}).get("NginxConf")
            == "proxy_redirect off;\n"
        )
        results["proxy_redirect_default_round_trip"] = (
            by_remark.get(TEST_PREFIX + "redir-default-conf", {}).get("NginxConf")
            == "proxy_redirect default;\n"
        )

        core_host = host("core")
        status, headers, body = request_via_lucky(
            core_host,
            "/front",
            "/api/user?x=1&y=two",
            resolve_ip=resolve_ip,
            headers={
                "X-Probe-Input": "from-client",
                "X-Remove": "remove-me",
                "X-Forwarded-For": "203.0.113.7",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
        )
        payload = json_body(body)
        upstream_headers = lower_headers(payload)
        results.update(
            {
                "core_http_200": status == 200,
                "proxy_set_header_literal": upstream_headers.get("x-literal") == "alpha beta",
                "variable_host": upstream_headers.get("x-host") == core_host,
                "variable_http_host": upstream_headers.get("x-http-host") == core_host,
                "variable_scheme": upstream_headers.get("x-scheme") == "https",
                "variable_request": str(upstream_headers.get("x-request", "")).startswith(
                    "GET /front/api/user?x=1&y=two HTTP/"
                ),
                "variable_request_method": upstream_headers.get("x-method") == "GET",
                "variable_request_uri": upstream_headers.get("x-request-uri")
                == "/front/api/user?x=1&y=two",
                "variable_args": upstream_headers.get("x-args") == "x=1&y=two",
                "variable_query_string": upstream_headers.get("x-query-string") == "x=1&y=two",
                "variable_is_args": upstream_headers.get("x-is-args") == "?",
                "variable_remote_addr": valid_ip(upstream_headers.get("x-remote-addr", "")),
                "variable_remote_port": upstream_headers.get("x-remote-port", "").isdigit(),
                "variable_server_port": upstream_headers.get("x-server-port") == "443",
                "variable_http_upgrade": upstream_headers.get("x-http-upgrade") == "websocket",
                "variable_proxy_add_x_forwarded_for": str(
                    upstream_headers.get("x-proxy-xff", "")
                ).startswith("203.0.113.7, "),
                "variable_arbitrary_http_header": upstream_headers.get("x-input") == "from-client",
                "empty_proxy_set_header_deletes": "x-remove" not in upstream_headers,
                "add_header_always_200": headers.get("x-base") == "base",
                "location_prefix_after_frontend_strip": headers.get("x-loc-prefix") == "yes",
                "backend_path_join": str(payload.get("url", "")).endswith(
                    "/anything/backend-base/api/user?x=1&y=two"
                ),
                "query_preserved": payload.get("args", {}).get("x") == "1"
                and payload.get("args", {}).get("y") == "two",
            }
        )
        observations["uri_stage"] = classify_path(
            upstream_headers.get("x-uri", ""), "/front/api/user", "/api/user"
        )
        observations["document_uri_stage"] = classify_path(
            upstream_headers.get("x-document-uri", ""), "/front/api/user", "/api/user"
        )
        observations["connection_upgrade"] = classify_connection_upgrade(
            upstream_headers.get("x-connection-upgrade", "")
        )
        results["variable_uri_observed"] = observations["uri_stage"] != "other"
        results["variable_document_uri_observed"] = observations["document_uri_stage"] != "other"
        results["variable_connection_upgrade_observed"] = (
            observations["connection_upgrade"] != "other"
        )

        path_cases = [
            ("/exact", "location_exact", "x-loc-exact", True),
            ("/v12/test", "location_regex", "x-loc-regex", True),
            ("/case/test", "location_regex_i", "x-loc-regex-i", True),
            ("/free/test", "location_negative", "x-loc-neg", True),
            ("/blocked/test", "location_negative_blocks", "x-loc-neg", False),
            ("/wild/a", "path_wildcard", "x-path-wild", True),
            ("/rx12/a", "path_regex", "x-path-regex", True),
            ("/free2/a", "path_negative", "x-path-neg", True),
            ("/deny/a", "path_negative_blocks", "x-path-neg", False),
        ]
        for relative, key, header_name, expected in path_cases:
            _, case_headers, _ = request_via_lucky(
                core_host, "/front", relative, resolve_ip=resolve_ip
            )
            results[key] = (
                case_headers.get(header_name) == "yes"
                if expected
                else header_name not in case_headers
            )

        response_host = host("resp")
        _, response_headers, _ = request_via_lucky(
            response_host,
            "/resp",
            (
                "/response-headers?X-Upstream-Secret=secret"
                "&Location=http%3A%2F%2Fbackend%2Fapp"
                "&Refresh=0%3B%20url%3Dhttp%3A%2F%2Fbackend%2Frefresh"
            ),
            resolve_ip=resolve_ip,
        )
        results["proxy_hide_header"] = "x-upstream-secret" not in response_headers
        results["proxy_redirect_location"] = response_headers.get("location") == "/rewritten/app"
        results["proxy_redirect_refresh"] = (
            response_headers.get("refresh") == "0; url=/rewritten/refresh"
        )
        results["add_header_default_200"] = response_headers.get("x-default") == "default"
        results["add_header_always_second_200"] = response_headers.get("x-always") == "always"
        status, response_headers, _ = request_via_lucky(
            response_host, "/resp", "/status/418", resolve_ip=resolve_ip
        )
        results["upstream_418"] = status == 418
        results["add_header_default_excluded_418"] = "x-default" not in response_headers
        results["add_header_always_418"] = response_headers.get("x-always") == "always"

        for label, expected_host in [
            ("host-target", "target"),
            ("host-public", "public"),
        ]:
            hostname = host(label)
            _, _, body = request_via_lucky(
                hostname, "/h", "/x", resolve_ip=resolve_ip
            )
            upstream_headers = lower_headers(json_body(body))
            if expected_host == "target":
                results["use_target_host_true"] = upstream_headers.get("host") == "httpbin.org"
            else:
                results["use_target_host_false"] = upstream_headers.get("host") == hostname

        helper_host = host("helpers")
        _, _, body = request_via_lucky(helper_host, "/h", "/x", resolve_ip=resolve_ip)
        helper_headers = lower_headers(json_body(body))
        results["add_proto_to_header"] = helper_headers.get("x-lucky-proto") == "https"
        results["add_remote_ip_to_header"] = valid_ip(
            helper_headers.get("x-lucky-client-ip", "")
        )

        auto_values: dict[str, tuple[str, str, str]] = {}
        for label in ["redirect-off", "redirect-on", "redirect-diff"]:
            hostname = host(label)
            _, same_headers, _ = request_via_lucky(
                hostname,
                "/r",
                "/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fanything%2Fsame&status_code=302",
                resolve_ip=resolve_ip,
            )
            _, different_headers, _ = request_via_lucky(
                hostname,
                "/r",
                "/redirect-to?url=https%3A%2F%2Fexample.com%2Fother&status_code=302",
                resolve_ip=resolve_ip,
            )
            auto_values[label] = (
                same_headers.get("location", ""),
                different_headers.get("location", ""),
                hostname,
            )

        off_same, off_different, _ = auto_values["redirect-off"]
        on_same, on_different, on_host = auto_values["redirect-on"]
        diff_same, diff_different, diff_host = auto_values["redirect-diff"]
        results["auto_proxy_location_off_preserves_same"] = (
            off_same == "https://httpbin.org/anything/same"
        )
        results["auto_proxy_location_off_preserves_different"] = (
            off_different == "https://example.com/other"
        )
        results["auto_proxy_location_on_rewrites_same"] = (
            on_same != off_same and on_host in on_same
        )
        results["auto_proxy_location_on_rewrites_different"] = (
            on_different != off_different and on_host in on_different
        )
        results["auto_proxy_location_only_different_preserves_same"] = diff_same == off_same
        results["auto_proxy_location_only_different_rewrites_different"] = (
            diff_different != off_different and diff_host in diff_different
        )
        observations["auto_proxy_location_on_same_shape"] = redact_frontend_location(
            on_same, on_host
        )
        observations["auto_proxy_location_on_different_shape"] = redact_frontend_location(
            on_different, on_host
        )
        observations["auto_proxy_location_only_different_shape"] = redact_frontend_location(
            diff_different, diff_host
        )

        for label, observation_key in [
            ("redir-off-conf", "proxy_redirect_off"),
            ("redir-default-conf", "proxy_redirect_default"),
        ]:
            hostname = host(label)
            _, redirect_headers, _ = request_via_lucky(
                hostname,
                "/r",
                "/redirect-to?url=http%3A%2F%2Fbackend%2Fapp&status_code=302",
                resolve_ip=resolve_ip,
            )
            location = redirect_headers.get("location", "")
            if label == "redir-off-conf":
                results["proxy_redirect_off_preserves"] = location == "http://backend/app"
            observations[observation_key] = (
                "raw"
                if location == "http://backend/app"
                else "frontend"
                if hostname in location
                else "other"
            )
        default_host = host("redir-default-conf")
        _, default_headers, _ = request_via_lucky(
            default_host,
            "/r",
            "/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fanything%2Fdefault&status_code=302",
            resolve_ip=resolve_ip,
        )
        default_same = default_headers.get("location", "")
        observations["proxy_redirect_default_same_upstream"] = (
            "raw"
            if default_same == "https://httpbin.org/anything/default"
            else "frontend"
            if default_host in default_same
            else "other"
        )
        results["proxy_redirect_default_observed"] = observations.get(
            "proxy_redirect_default_same_upstream"
        ) != "other"
    except BaseException as error:
        primary_error = error
    finally:
        try:
            cleanup_removed, cleanup_ok = cleanup_test_subrules(client, path)
        except BaseException as cleanup_error:
            if primary_error is None:
                primary_error = cleanup_error
            else:
                primary_error = RuntimeError(
                    f"probe failed with {type(primary_error).__name__}; cleanup also failed with "
                    f"{type(cleanup_error).__name__}"
                )

    final = unwrap_rule(client.request_json("GET", path))
    final_tests = [item for item in final.get("ProxyList") or [] if is_test_subrule(item)]
    business_after = [item for item in final.get("ProxyList") or [] if not is_test_subrule(item)]
    cleanup_report = {
        "removed_test_subrules": cleanup_removed,
        "leftover_test_subrules": len(final_tests),
        "business_rule_count_before": len(business_before),
        "business_rule_count_after": len(business_after),
        "business_subrules_unchanged": business_after == business_before,
        "cleanup_ok": cleanup_ok and not final_tests,
    }
    if primary_error is not None:
        raise RuntimeError(
            f"runtime probe failed ({type(primary_error).__name__}); cleanup={cleanup_report}"
        ) from primary_error
    return {
        "target": "Lucky WebService reverseproxy semantics",
        "results": results,
        "observations": observations,
        "failed": sorted(key for key, value in results.items() if value is not True),
        "cleanup": cleanup_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--rule-key", required=True, help="existing WebService listener RuleKey")
    parser.add_argument(
        "--domain-suffix",
        required=True,
        help="wildcard-covered DNS suffix used only for unique TEST hostnames",
    )
    parser.add_argument(
        "--resolve-ip",
        default="127.0.0.1",
        help="IP curl should connect to while preserving the unique TEST hostname/SNI",
    )
    parser.add_argument("--echo-origin", default=DEFAULT_ECHO_ORIGIN)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"confirmation must be exactly: {CONFIRMATION}")
    try:
        ipaddress.ip_address(args.resolve_ip)
        result = run_probe(
            make_client(),
            rule_key=args.rule_key.strip(),
            suffix=normalize_suffix(args.domain_suffix),
            resolve_ip=args.resolve_ip,
            echo_origin=origin_base(args.echo_origin),
        )
    except (CredentialError, LuckyClientError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not result["failed"] and result["cleanup"]["cleanup_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
