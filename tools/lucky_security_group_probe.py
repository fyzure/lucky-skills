#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Security Groups and WebService auth basics.

The probe creates only uniquely prefixed disposable security principals and
WebService subrules. It verifies Security Group/local-user/OAuth-user CRUD,
BasicAuth behavior through the live TLS listener, and that WebAuth produces an
authentication surface rather than reaching the upstream. Cleanup removes
only resources created by this probe and checks the original baselines.

Passwords and generated resource identifiers are never printed.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

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


CONFIRMATION = "PROBE-AND-CLEAN-SECURITY-GROUP-AUTH"
TEST_PREFIX = "TEST-lucky-skills-auth-"
UPSTREAM_MARKER = "LUCKY_SKILLS_AUTH_UPSTREAM_OK"


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
            time.sleep(6.0 + attempt * 4.0)
    raise AssertionError("unreachable")


def list_rows(client: LuckyClient, path: str) -> list[dict[str, Any]]:
    payload = client.request_json("GET", path)
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError(f"unexpected list response for {path}")
    return [row for row in rows if isinstance(row, dict)]


def row_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def grant_key(row: dict[str, Any]) -> str:
    return str(row.get("GrantKey") or row.get("grantKey") or row_key(row))


def create_key(
    client: LuckyClient,
    path: str,
    body: dict[str, Any],
    *,
    list_path: str,
    predicate,
) -> str:
    payload = mutate(client, "POST", path, json_body=body, body_supplied=True)
    if isinstance(payload, dict):
        value = payload.get("key") or payload.get("Key")
        if isinstance(value, str) and value:
            return value
    for row in list_rows(client, list_path):
        if predicate(row):
            key = row_key(row)
            if key:
                return key
    raise RuntimeError(f"created resource missing from {list_path}")


def start_upstream() -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:
            body = UPSTREAM_MARKER.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, int(server.server_address[1])


def unwrap_rule(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected WebService rule response")
    rule = payload.get("rule", payload.get("ruleInfo", payload))
    if not isinstance(rule, dict):
        raise RuntimeError("unexpected WebService rule object")
    return rule


def make_subrule(
    template: dict[str, Any],
    *,
    remark: str,
    hostname: str,
    upstream_port: int,
) -> dict[str, Any]:
    item = copy.deepcopy(template)
    item.pop("Key", None)
    item.pop("GroupKey", None)
    item.update(
        {
            "Enable": True,
            "Remark": remark,
            "Domains": [hostname],
            "Locations": [f"http://127.0.0.1:{upstream_port}"],
            "WebServiceType": "reverseproxy",
            "LocationInsecureSkipVerify": False,
            "EnableAccessLog": False,
            "DisableStatistics": True,
            "DisplayInFrontendList": False,
            "UseRuleGlobalAuthSettings": False,
            "EnableBasicAuth": False,
            "BasicAuthRegConf": "",
            "BasicAuthUser": "",
            "BasicAuthPasswd": "",
            "BasicAuthUserList": "",
            "AuthSource": "local",
            "SecurityGroupKeys": [],
            "SecurityGroupAccessMode": "disabled",
            "SecurityGroupGrantBasicAuth": False,
            "NginxConf": "",
            "CacheEnabled": False,
            "AutoProxyLocation": False,
            "AutoProxyLocationWithoutSameHost": False,
            "AddProtoToHeader": False,
            "ProtoHeaderKey": "",
            "AddRemoteIPToHeader": False,
            "AddRemoteIPHeaderKey": "",
        }
    )
    other = item.setdefault("OtherParams", {})
    if not isinstance(other, dict):
        other = {}
        item["OtherParams"] = other
    other.update(
        {
            "WebAuth": False,
            "WebAuthUseDedicatedPath": True,
            "WebAuthPathPrefix": "/__6c75636b79_webauth__",
            "WebAuthSessionScopeMode": "subrule",
            "WebAuthAllowNonBrowserReuse": False,
            "WebAuthAllowNonBrowserUserAgents": [],
        }
    )
    return item


def curl_request(
    hostname: str,
    *,
    resolve_ip: str,
    path: str = "/",
    user: str | None = None,
    password: str | None = None,
    browser: bool = False,
    cookie_jar: Path | None = None,
    form: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    if shutil.which("curl") is None:
        raise RuntimeError("curl is required for WebService behavior verification")
    with tempfile.NamedTemporaryFile(prefix="lucky-auth-head-", delete=False) as handle:
        header_path = Path(handle.name)
    try:
        command = [
            "curl",
            "-skS",
            "--http1.1",
            "--max-time",
            "10",
            "--max-redirs",
            "0",
            "--resolve",
            f"{hostname}:443:{resolve_ip}",
            "-D",
            str(header_path),
        ]
        if browser:
            command.extend(["-A", "Mozilla/5.0 lucky-skills-auth-probe"])
        if user is not None and password is not None:
            command.extend(["-u", f"{user}:{password}"])
        if cookie_jar is not None:
            command.extend(["-b", str(cookie_jar), "-c", str(cookie_jar)])
        if form is not None:
            for key, value in form.items():
                command.extend(["--data-urlencode", f"{key}={value}"])
        command.append(f"https://{hostname}{path}")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode not in {0, 47}:
            raise RuntimeError(f"curl behavior probe failed with exit {result.returncode}")
        text = header_path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        blocks = [block for block in text.split("\n\n") if block.strip()]
        lines = blocks[-1].splitlines() if blocks else []
        status = 0
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                status = 0
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return status, headers, result.stdout
    finally:
        header_path.unlink(missing_ok=True)


def curl_json_request(
    hostname: str,
    *,
    resolve_ip: str,
    path: str,
    cookie_jar: Path,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    with tempfile.NamedTemporaryFile(prefix="lucky-auth-json-head-", delete=False) as handle:
        header_path = Path(handle.name)
    try:
        command = [
            "curl",
            "-skS",
            "--http1.1",
            "--max-time",
            "10",
            "--max-redirs",
            "0",
            "--resolve",
            f"{hostname}:443:{resolve_ip}",
            "-A",
            "Mozilla/5.0 lucky-skills-auth-probe",
            "-b",
            str(cookie_jar),
            "-c",
            str(cookie_jar),
            "-D",
            str(header_path),
            "-H",
            "Accept: application/json",
        ]
        body_input = None
        if method.upper() != "GET":
            command.extend(["-X", method.upper()])
        if payload is not None:
            body_input = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            command.extend(
                [
                    "-H",
                    "Content-Type: application/json",
                    "--data-binary",
                    "@-",
                ]
            )
        command.append(f"https://{hostname}{path}")
        result = subprocess.run(
            command,
            input=body_input,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode not in {0, 47}:
            raise RuntimeError(f"curl JSON probe failed with exit {result.returncode}")
        text = header_path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        blocks = [block for block in text.split("\n\n") if block.strip()]
        lines = blocks[-1].splitlines() if blocks else []
        status = 0
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                status = 0
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError as error:
            raise RuntimeError("WebAuth API returned non-JSON") from error
        if not isinstance(data, dict):
            raise RuntimeError("WebAuth API returned non-object JSON")
        return status, headers, data
    finally:
        header_path.unlink(missing_ok=True)


def split_utf8_chunks(value: str, limit: int = 120) -> list[str]:
    chunks: list[str] = []
    current = ""
    current_bytes = 0
    for char in value:
        char_bytes = len(char.encode("utf-8"))
        if current and current_bytes + char_bytes > limit:
            chunks.append(current)
            current = ""
            current_bytes = 0
        current += char
        current_bytes += char_bytes
    if current:
        chunks.append(current)
    return chunks


def rsa_encrypt_jsencrypt(public_key_pem: str, plaintext: str) -> str:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    encoded: list[str] = []
    for chunk in split_utf8_chunks(plaintext, 120):
        cipher = key.encrypt(chunk.encode("utf-8"), asym_padding.PKCS1v15())
        encoded.append(base64.b64encode(cipher).decode("ascii"))
    return ".".join(encoded)


def cleanup_subrules(client: LuckyClient, path: str, prefix: str) -> tuple[int, bool]:
    time.sleep(5)
    for attempt in range(6):
        current = unwrap_rule(client.request_json("GET", path))
        before = list(current.get("ProxyList") or [])
        after = [
            item
            for item in before
            if not (isinstance(item, dict) and str(item.get("Remark", "")).startswith(prefix))
        ]
        removed = len(before) - len(after)
        if removed == 0:
            return 0, True
        current["ProxyList"] = after
        try:
            mutate(client, "PUT", path, json_body=current, body_supplied=True)
        except HTTPStatusError as error:
            if error.status == 429 and attempt < 5:
                time.sleep(8 + attempt * 4)
                continue
            raise
        verify = unwrap_rule(client.request_json("GET", path))
        left = sum(
            1
            for item in verify.get("ProxyList") or []
            if isinstance(item, dict) and str(item.get("Remark", "")).startswith(prefix)
        )
        return removed, left == 0
    return 0, False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--rule-key", required=True)
    parser.add_argument("--domain-suffix", default="rs.fyzure.fyi")
    parser.add_argument("--resolve-ip", default="127.0.0.1")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    nonce = secrets.token_hex(4)
    prefix = TEST_PREFIX + nonce
    path = f"/api/webservice/rule/{args.rule_key}"
    suffix = args.domain_suffix.strip().strip(".").lower()
    baseline = {
        "groups": {row_key(row) for row in list_rows(client, "/api/security-groups")},
        "users": {row_key(row) for row in list_rows(client, "/api/security-groups/users")},
        "oauth": {row_key(row) for row in list_rows(client, "/api/security-groups/oauth-users")},
        "grants": {grant_key(row) for row in list_rows(client, "/api/security-groups/grants")},
    }
    parent_before = unwrap_rule(client.request_json("GET", path))
    business_before = [
        item
        for item in parent_before.get("ProxyList") or []
        if not (isinstance(item, dict) and str(item.get("Remark", "")).startswith(TEST_PREFIX))
    ]
    if len(business_before) != len(parent_before.get("ProxyList") or []):
        raise RuntimeError("pre-existing TEST auth subrule found")

    server, thread, upstream_port = start_upstream()
    made = {"group": "", "local": "", "nogroup": "", "third": "", "oauth": ""}
    local_password = "Ls-" + secrets.token_urlsafe(18)
    local_username = "lsu-" + nonce
    nogroup_password = "Lsn-" + secrets.token_urlsafe(18)
    nogroup_username = "lsn-" + nonce
    basic_username = "lsb-" + nonce
    basic_password = "Lsb-" + secrets.token_urlsafe(18)
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        made["group"] = create_key(
            client,
            "/api/security-groups",
            {
                "Key": "",
                "Name": prefix,
                "Enable": True,
                "SessionTTLMinutes": 30,
                "AllowWebAuthIPBypass": False,
                "Description": "Lucky Skills disposable auth probe",
            },
            list_path="/api/security-groups",
            predicate=lambda row: row.get("Name") == prefix,
        )
        results["security_group_create"] = bool(made["group"])

        made["local"] = create_key(
            client,
            "/api/security-groups/users",
            {
                "Key": "",
                "Name": prefix + "-local",
                "Username": local_username,
                "PasswordHash": "",
                "Password": local_password,
                "TwoFASecret": "",
                "Enable": True,
                "GrantSecurityGroups": [made["group"]],
                "Description": "Lucky Skills disposable local user",
                "HasPassword": False,
            },
            list_path="/api/security-groups/users",
            predicate=lambda row: row.get("Name") == prefix + "-local",
        )
        results["local_user_create"] = bool(made["local"])

        made["nogroup"] = create_key(
            client,
            "/api/security-groups/users",
            {
                "Key": "",
                "Name": prefix + "-nogroup",
                "Username": nogroup_username,
                "PasswordHash": "",
                "Password": nogroup_password,
                "TwoFASecret": "",
                "Enable": True,
                "GrantSecurityGroups": [],
                "Description": "Lucky Skills disposable no-group user",
                "HasPassword": False,
            },
            list_path="/api/security-groups/users",
            predicate=lambda row: row.get("Name") == prefix + "-nogroup",
        )
        results["no_group_user_create"] = bool(made["nogroup"])

        made["third"] = create_key(
            client,
            "/api/thirdPartyAuthManager/list",
            {
                "Key": "",
                "Type": "github",
                "Enable": False,
                "Remark": prefix + "-third",
                "ID": prefix + "-id",
                "Name": prefix + "-third",
                "Avatar": "",
                "EMail": "",
                "Phone": "",
                "RefreshToken": "",
                "AccessToken": "",
                "CreateTime": 0,
                "UpdateTime": 0,
                "TwoFAKey": "",
            },
            list_path="/api/thirdPartyAuthManager/list",
            predicate=lambda row: row.get("Remark") == prefix + "-third",
        )
        results["third_party_identity_create"] = bool(made["third"])

        made["oauth"] = create_key(
            client,
            "/api/security-groups/oauth-users",
            {
                "Key": "",
                "ThirdAuthUserKey": made["third"],
                "Provider": "github",
                "SkipTwoFA": True,
                "MatchID": "",
                "MatchEmail": "",
                "MatchName": "",
                "Enable": False,
                "GrantSecurityGroups": [made["group"]],
                "Description": "Lucky Skills disposable OAuth mapping",
            },
            list_path="/api/security-groups/oauth-users",
            predicate=lambda row: row.get("ThirdAuthUserKey") == made["third"],
        )
        results["oauth_user_create"] = bool(made["oauth"])

        group_row = next(row for row in list_rows(client, "/api/security-groups") if row_key(row) == made["group"])
        group_update = copy.deepcopy(group_row)
        group_update["Description"] = "Lucky Skills disposable auth probe updated"
        mutate(
            client,
            "PUT",
            f"/api/security-groups/{made['group']}",
            json_body=group_update,
            body_supplied=True,
        )
        group_reread = next(row for row in list_rows(client, "/api/security-groups") if row_key(row) == made["group"])
        results["security_group_update"] = group_reread.get("Description", "").endswith("updated")

        parent = unwrap_rule(client.request_json("GET", path))
        template = next(
            (
                item
                for item in parent.get("ProxyList") or []
                if isinstance(item, dict) and item.get("WebServiceType") == "reverseproxy"
            ),
            parent.get("DefaultProxy"),
        )
        if not isinstance(template, dict):
            raise RuntimeError("no reverseproxy template available")

        basic_host = f"ba-{nonce}.{suffix}"
        webauth_host = f"wa-{nonce}.{suffix}"
        basic = make_subrule(
            template,
            remark=prefix + "-basic",
            hostname=basic_host,
            upstream_port=upstream_port,
        )
        basic["EnableBasicAuth"] = True
        basic["BasicAuthUserList"] = f"{basic_username}:{basic_password}"

        webauth = make_subrule(
            template,
            remark=prefix + "-webauth",
            hostname=webauth_host,
            upstream_port=upstream_port,
        )
        webauth["SecurityGroupKeys"] = [made["group"]]
        webauth["AuthSource"] = "securityGroup"
        # Current Lucky 3.0.0 frontend forces access mode=disabled whenever a
        # security group is the credential source for BasicAuth/WebAuth. The
        # strict/append modes are a separate authorization-overlay feature.
        webauth["SecurityGroupAccessMode"] = "disabled"
        webauth["OtherParams"]["WebAuth"] = True

        parent["ProxyList"] = list(parent.get("ProxyList") or []) + [basic, webauth]
        mutate(client, "PUT", path, json_body=parent, body_supplied=True)
        time.sleep(2)

        status, headers, body = curl_request(basic_host, resolve_ip=args.resolve_ip)
        results["basic_auth_rejects_unauthenticated"] = status == 401 and UPSTREAM_MARKER not in body
        observations["basic_unauth_status"] = status
        observations["basic_www_authenticate_present"] = "www-authenticate" in headers

        status, _, body = curl_request(
            basic_host,
            resolve_ip=args.resolve_ip,
            user=basic_username,
            password="wrong-" + basic_password,
        )
        results["basic_auth_rejects_wrong_password"] = status == 401 and UPSTREAM_MARKER not in body

        status, _, body = curl_request(
            basic_host,
            resolve_ip=args.resolve_ip,
            user=basic_username,
            password=basic_password,
        )
        results["basic_auth_accepts_correct_password"] = status == 200 and UPSTREAM_MARKER in body

        status, headers, body = curl_request(
            webauth_host, resolve_ip=args.resolve_ip, browser=True
        )
        body_lower = body.lower()
        results["webauth_blocks_upstream"] = UPSTREAM_MARKER not in body
        results["webauth_auth_surface_present"] = (
            status in {200, 301, 302, 303, 307, 308, 401, 403}
            and UPSTREAM_MARKER not in body
            and (
                "<form" in body_lower
                or "login" in body_lower
                or "auth" in body_lower
                or "location" in headers
            )
        )
        observations["webauth_status"] = status
        observations["webauth_has_form"] = "<form" in body_lower
        observations["webauth_redirect"] = "location" in headers
        observations["webauth_content_type"] = headers.get("content-type", "").split(";", 1)[0]
        observations["webauth_body_length_class"] = (
            "empty" if not body else "small" if len(body) < 4096 else "large"
        )
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        observations["webauth_title"] = (
            re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else ""
        )
        observations["webauth_input_count"] = len(
            re.findall(r"<input\b", body, re.IGNORECASE)
        )
        observations["webauth_button_count"] = len(
            re.findall(r"<button\b", body, re.IGNORECASE)
        )
        public_refs: list[str] = []
        for ref in re.findall(
            r"(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']",
            body,
            re.IGNORECASE,
        ):
            if ref.startswith("/") and not ref.startswith("//") and len(ref) <= 160:
                public_refs.append(ref)
        observations["webauth_relative_refs"] = sorted(set(public_refs))[:20]
        preview = body.replace(webauth_host, "<host>").replace(nonce, "<nonce>")
        preview = re.sub(
            r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])",
            "<opaque>",
            preview,
        )
        preview = re.sub(r"\s+", " ", preview).strip()
        observations["webauth_sanitized_preview"] = preview[:600]
        observations["runtime_grants_before_login"] = len(list_rows(client, "/api/security-groups/grants"))

        # Follow Lucky's JS handoff to the actual WebAuth login surface. Do
        # not guess the form contract: record only field names/types and the
        # sanitized action path so a subsequent probe revision can submit the
        # real form safely.
        target_match = re.search(r'var\s+target\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"', body)
        if target_match:
            try:
                login_target = json.loads('"' + target_match.group(1) + '"')
            except json.JSONDecodeError:
                login_target = ""
        else:
            login_target = ""
        results["webauth_login_target_discovered"] = bool(login_target.startswith("/"))
        if login_target.startswith("/"):
            login_status, _, login_body = curl_request(
                webauth_host,
                resolve_ip=args.resolve_ip,
                path=login_target,
                browser=True,
            )
            form_match = re.search(
                r"<form\b[^>]*?(?:action=[\"']([^\"']*)[\"'])?[^>]*>",
                login_body,
                re.IGNORECASE | re.DOTALL,
            )
            action = form_match.group(1) if form_match and form_match.group(1) else ""
            input_fields = []
            for tag in re.findall(r"<input\b[^>]*>", login_body, re.IGNORECASE | re.DOTALL):
                name_match = re.search(r"\bname=[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
                type_match = re.search(r"\btype=[\"']([^\"']+)[\"']", tag, re.IGNORECASE)
                if name_match:
                    input_fields.append(
                        {
                            "name": name_match.group(1),
                            "type": type_match.group(1).lower() if type_match else "text",
                        }
                    )
            observations["webauth_login_status"] = login_status
            observations["webauth_login_form_action"] = action[:160]
            observations["webauth_login_input_fields"] = input_fields
            login_preview = login_body.replace(webauth_host, "<host>").replace(nonce, "<nonce>")
            login_preview = re.sub(
                r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])",
                "<opaque>",
                login_preview,
            )
            login_preview = re.sub(r"\s+", " ", login_preview).strip()
            observations["webauth_login_sanitized_preview"] = login_preview[:2400]
            observations["webauth_login_script_srcs"] = re.findall(
                r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']",
                login_body,
                re.IGNORECASE,
            )[:20]
            request_like_refs = sorted(
                set(
                    re.findall(
                        r"[\"']([^\"']*(?:/api/|login|auth)[^\"']*)[\"']",
                        login_body,
                        re.IGNORECASE,
                    )
                )
            )
            observations["webauth_login_request_like_refs"] = [
                ref[:180] for ref in request_like_refs[:30]
            ]
            app_status, _, app_js = curl_request(
                webauth_host,
                resolve_ip=args.resolve_ip,
                path=login_target.rstrip("/") + "/assets/app.js",
                browser=True,
            )
            observations["webauth_login_app_js_status"] = app_status
            app_refs = sorted(
                set(
                    ref
                    for ref in re.findall(r"[\"']([^\"']+)[\"']", app_js)
                    if any(token in ref.lower() for token in ("login", "auth", "challenge", "verify"))
                )
            )
            observations["webauth_login_app_refs"] = [ref[:180] for ref in app_refs[:40]]
            const_match = re.search(
                r"WEB_AUTH_API_PREFIX\s*=\s*[\"']([^\"']+)[\"']",
                app_js,
            )
            observations["webauth_api_prefix"] = const_match.group(1) if const_match else ""
            for func_name in (
                "buildAuthApiUrl",
                "buildEncryptedLoginPayload",
                "encryptLoginPayloadWithPublicKey",
            ):
                match = re.search(
                    rf"(?:async\s+)?function\s+{func_name}\s*\([^)]*\)\s*\{{",
                    app_js,
                )
                if match:
                    snippet = app_js[match.start() : match.start() + 2200]
                    snippet = re.sub(r"\s+", " ", snippet).strip()
                    observations[f"webauth_{func_name}_snippet"] = snippet[:2100]
            fetch_snippets = []
            for match in re.finditer(r"fetch\s*\(", app_js):
                snippet = app_js[max(0, match.start() - 260) : match.start() + 900]
                snippet = re.sub(r"\s+", " ", snippet).strip()
                fetch_snippets.append(snippet[:1100])
            observations["webauth_login_fetch_snippets"] = fetch_snippets[:8]
            results["webauth_login_form_reached"] = login_status == 200 and bool(input_fields)

            return_url = base64.urlsafe_b64encode(
                f"https://{webauth_host}/".encode("utf-8")
            ).decode("ascii").rstrip("=")
            sep = "&" if "?" in login_target else "?"
            login_with_return = login_target + sep + "return_url=" + return_url
            with tempfile.NamedTemporaryFile(prefix="lucky-auth-cookie-", delete=False) as handle:
                cookie_path = Path(handle.name)
            try:
                # Prime the login surface/cookie context, then execute the
                # challenge + RSA-encrypted JSON protocol used by app.js.
                curl_request(
                    webauth_host,
                    resolve_ip=args.resolve_ip,
                    path=login_with_return,
                    browser=True,
                    cookie_jar=cookie_path,
                )
                api_prefix = observations.get("webauth_api_prefix") or "webauth_0xa2c2a_"
                api_base = login_target.rstrip("/") + "/" + str(api_prefix).strip("/")
                challenge_status, _, challenge = curl_json_request(
                    webauth_host,
                    resolve_ip=args.resolve_ip,
                    path=api_base + "/api/login/challenge",
                    cookie_jar=cookie_path,
                )
                results["webauth_login_challenge"] = (
                    challenge_status == 200
                    and challenge.get("ret") == 0
                    and all(challenge.get(key) for key in ("challengeId", "nonce", "publicKey"))
                )
                plaintext = json.dumps(
                    {
                        "account": local_username,
                        "password": local_password,
                        "twoFA": "",
                        "challengeId": challenge.get("challengeId", ""),
                        "nonce": challenge.get("nonce", ""),
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                encrypted = rsa_encrypt_jsencrypt(str(challenge.get("publicKey", "")), plaintext)
                submit_status, _, submit = curl_json_request(
                    webauth_host,
                    resolve_ip=args.resolve_ip,
                    path=api_base + "/api/login",
                    cookie_jar=cookie_path,
                    method="POST",
                    payload={
                        "challengeId": challenge.get("challengeId", ""),
                        "cipherText": encrypted,
                    },
                )
                observations["webauth_login_submit_status"] = submit_status
                observations["webauth_login_ret"] = submit.get("ret")
                results["webauth_local_user_login_accepted"] = submit_status == 200 and submit.get("ret") == 0

                session_status, _, session_body = curl_request(
                    webauth_host,
                    resolve_ip=args.resolve_ip,
                    browser=True,
                    cookie_jar=cookie_path,
                )
                results["webauth_session_reaches_upstream"] = (
                    session_status == 200 and UPSTREAM_MARKER in session_body
                )

                grants_after = list_rows(client, "/api/security-groups/grants")
                new_grants = [row for row in grants_after if grant_key(row) not in baseline["grants"]]
                results["security_group_runtime_grant_created"] = bool(new_grants)
                observations["runtime_grants_after_login"] = len(grants_after)
                observations["new_runtime_grant_count"] = len(new_grants)
                for grant in new_grants:
                    key = grant_key(grant)
                    if key:
                        mutate(client, "DELETE", f"/api/security-groups/grants/{key}")
                results["security_group_runtime_grant_deleted"] = not any(
                    grant_key(row) not in baseline["grants"]
                    for row in list_rows(client, "/api/security-groups/grants")
                )

                # A valid local Security Group account that is not granted to
                # this group must not obtain an authorized upstream session.
                with tempfile.NamedTemporaryFile(prefix="lucky-auth-nogroup-", delete=False) as ng_handle:
                    ng_cookie = Path(ng_handle.name)
                try:
                    _, _, ng_challenge = curl_json_request(
                        webauth_host,
                        resolve_ip=args.resolve_ip,
                        path=api_base + "/api/login/challenge",
                        cookie_jar=ng_cookie,
                    )
                    ng_plaintext = json.dumps(
                        {
                            "account": nogroup_username,
                            "password": nogroup_password,
                            "twoFA": "",
                            "challengeId": ng_challenge.get("challengeId", ""),
                            "nonce": ng_challenge.get("nonce", ""),
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    ng_cipher = rsa_encrypt_jsencrypt(
                        str(ng_challenge.get("publicKey", "")), ng_plaintext
                    )
                    ng_status, _, ng_submit = curl_json_request(
                        webauth_host,
                        resolve_ip=args.resolve_ip,
                        path=api_base + "/api/login",
                        cookie_jar=ng_cookie,
                        method="POST",
                        payload={
                            "challengeId": ng_challenge.get("challengeId", ""),
                            "cipherText": ng_cipher,
                        },
                    )
                    ng_session_status, _, ng_session_body = curl_request(
                        webauth_host,
                        resolve_ip=args.resolve_ip,
                        browser=True,
                        cookie_jar=ng_cookie,
                    )
                    results["webauth_rejects_no_group_user"] = not (
                        ng_status == 200
                        and ng_submit.get("ret") == 0
                        and ng_session_status == 200
                        and UPSTREAM_MARKER in ng_session_body
                    )
                finally:
                    ng_cookie.unlink(missing_ok=True)
            finally:
                cookie_path.unlink(missing_ok=True)

    finally:
        removed, clean_rules = cleanup_subrules(client, path, prefix)
        cleanup["webservice_test_subrules_removed"] = removed
        cleanup["webservice_test_subrules_absent"] = clean_rules

        for label, delete_path in (
            ("oauth", "/api/security-groups/oauth-users/"),
            ("nogroup", "/api/security-groups/users/"),
            ("local", "/api/security-groups/users/"),
            ("third", "/api/thirdPartyAuthManager/list/"),
            ("group", "/api/security-groups/"),
        ):
            key = made[label]
            if key:
                try:
                    mutate(client, "DELETE", delete_path + key)
                    cleanup[label + "_deleted"] = True
                except Exception:
                    cleanup[label + "_deleted"] = False

        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    final = {
        "groups": {row_key(row) for row in list_rows(client, "/api/security-groups")},
        "users": {row_key(row) for row in list_rows(client, "/api/security-groups/users")},
        "oauth": {row_key(row) for row in list_rows(client, "/api/security-groups/oauth-users")},
        "grants": {grant_key(row) for row in list_rows(client, "/api/security-groups/grants")},
    }
    cleanup["principal_baselines_restored"] = all(final[key] == baseline[key] for key in baseline)
    parent_after = unwrap_rule(client.request_json("GET", path))
    business_after = [
        item
        for item in parent_after.get("ProxyList") or []
        if not (isinstance(item, dict) and str(item.get("Remark", "")).startswith(TEST_PREFIX))
    ]
    cleanup["business_subrules_unchanged"] = business_after == business_before

    failed = sorted(key for key, value in results.items() if not value)
    for key in (
        "webservice_test_subrules_absent",
        "principal_baselines_restored",
        "business_subrules_unchanged",
    ):
        if not cleanup.get(key):
            failed.append(key)

    print(
        json.dumps(
            {
                "target": "Lucky Security Groups and WebService auth basics",
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
