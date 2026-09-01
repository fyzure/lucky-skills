#!/usr/bin/env python3
"""Exercise Lucky 3.0.0 third-party OIDC authorization on disposable CI.

The probe refuses non-GitHub execution.  It starts a pinned Lucky container on
an internal Docker bridge and a tiny owned HTTP OIDC fixture on that bridge.
All Lucky configuration changes happen through Lucky HTTP APIs after a real
default-admin challenge/RSA login.  No production OAuth client, browser
automation, public IdP, Internet route, Playwright or Chromium is used.

The first responsibility of this probe is behavioral discovery: obtain a real
tmpCode/authUrl with an authenticated administrator, follow the authorization
redirect using a stdlib HTTP client, poll Lucky's status/userinfo endpoints,
and report only response/request *shapes*.  The fixture intentionally keeps a
small standards-shaped token/userinfo surface so later iterations can fill any
Lucky-specific relay step without changing the isolation model.
"""

from __future__ import annotations

import http.server
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.error
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
    json_request,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    rsa_encrypt_with_openssl,
    run,
    wait_for_lucky,
)
from lucky_upnp_ci_probe import (
    admin_port_is_unpublished,
    container_ipv4,
    docker_network_values,
)


TEST_PREFIX = "TEST-lucky-skills-oauth-ci-"


def admin_json(
    base_url: str,
    admin_token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    require_zero: bool = True,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict[str, Any]:
    status, response = json_request(
        opener or urllib.request.build_opener(),
        base_url,
        path,
        method=method,
        payload=payload,
        admin_token=admin_token,
        timeout=20,
    )
    if require_zero:
        require_ret_zero(status, response, f"{method} {path}")
    elif status != 200:
        raise ProbeError(f"{method} {path} returned HTTP {status}")
    return response


def login_browser_admin(
    base_url: str, workdir: Path
) -> tuple[str, urllib.request.OpenerDirector, list[str]]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    status, challenge = json_request(opener, base_url, "/api/login/challenge")
    require_ret_zero(status, challenge, "login challenge")
    required = ("challengeId", "nonce", "publicKey")
    if not all(challenge.get(key) for key in required):
        raise ProbeError("login challenge missing required fields")
    plaintext = json.dumps(
        {
            "account": "666",
            "password": "666",
            "twoFA": "",
            "challengeId": challenge["challengeId"],
            "nonce": challenge["nonce"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    cipher = rsa_encrypt_with_openssl(str(challenge["publicKey"]), plaintext, workdir)
    status, response = json_request(
        opener,
        base_url,
        "/api/login",
        method="POST",
        payload={"challengeId": challenge["challengeId"], "cipherText": cipher},
    )
    require_ret_zero(status, response, "default admin login")
    token = response.get("token")
    if not isinstance(token, str) or not token.strip():
        raise ProbeError("default admin login returned no admin token")
    cookie_names = sorted({cookie.name for cookie in jar})
    return token, opener, cookie_names


def json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [json_shape(value[0])] if value else []
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"


def lucky_frontend_timestamp() -> str:
    """Reproduce Lucky 3.0.0 frontend ao() anti-replay query value."""

    raw = str(int(time.time() * 1000))
    core = raw[:-1]
    checksum = sum(int(char) for char in core) % 8
    return core + str(checksum)


def frontend_runtime_snippets(base_url: str) -> dict[str, str]:
    """Read Lucky's own served frontend and return selected runtime call vicinities."""

    origin = urllib.parse.urlsplit(base_url)
    opener = urllib.request.build_opener()
    queue = ["/"]
    seen: set[str] = set()
    fetched = 0
    targets = (
        "/api/oauth/tmpcode",
        "interceptors.request.use",
        "Authorization",
        "Lucky-Admin-Token",
        "openToken",
    )
    snippets: dict[str, str] = {}
    while queue and len(seen) < 100 and fetched < 24 * 1024 * 1024:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        request = urllib.request.Request(
            base_url + path,
            headers={"User-Agent": "lucky-skills-oauth-ci-inspector/1"},
        )
        try:
            with opener.open(request, timeout=8) as response:
                raw = response.read(min(4 * 1024 * 1024, 24 * 1024 * 1024 - fetched))
        except Exception:  # noqa: BLE001 - best-effort runtime source inspection
            continue
        fetched += len(raw)
        text = raw.decode("utf-8", errors="replace")
        for needle in targets:
            if needle in snippets:
                continue
            index = text.find(needle)
            if index >= 0:
                start = max(0, index - 1200)
                end = min(len(text), index + 1800)
                snippets[needle] = re.sub(r"\s+", " ", text[start:end])[:3000]
        candidates = set(re.findall(r"(?:src=|href=)?[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", text))
        candidates.update(re.findall(r"(?:\.\/)?(assets/[A-Za-z0-9_./-]+\.js)", text))
        for candidate in candidates:
            parsed = urllib.parse.urlsplit(candidate)
            if parsed.scheme and (parsed.scheme != origin.scheme or parsed.netloc != origin.netloc):
                continue
            candidate_path = parsed.path
            if not candidate_path.startswith("/"):
                candidate_path = "/" + candidate_path.lstrip("./")
            if candidate_path not in seen and candidate_path.endswith(".js"):
                queue.append(candidate_path)
    return snippets


def tmpcode_browser_attempt(
    base_url: str,
    admin_token: str,
    opener: urllib.request.OpenerDirector,
    *,
    include_origin: bool,
    include_referer: bool,
    include_xrw: bool,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Authorization": f"Bearer {admin_token}",
        "Lucky-Admin-Token": admin_token,
        "User-Agent": "Mozilla/5.0 lucky-skills-oauth-ci",
    }
    if include_origin:
        headers["Origin"] = base_url
    if include_referer:
        headers["Referer"] = base_url + "/#/thirdPartyAuthManager"
    if include_xrw:
        headers["X-Requested-With"] = "XMLHttpRequest"
    query = urllib.parse.urlencode({"type": "oidc", "_": lucky_frontend_timestamp()})
    request = urllib.request.Request(base_url + "/api/oauth/tmpcode?" + query, headers=headers)
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(1024 * 1024)
            status = int(response.status)
    except urllib.error.HTTPError as error:
        raw = error.read(1024 * 1024)
        status = int(error.code)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeError(f"browser-style tmpcode returned non-JSON HTTP {status}") from None
    if not isinstance(decoded, dict):
        raise ProbeError("browser-style tmpcode returned non-object JSON")
    return decoded


class FakeOidcProvider:
    def __init__(self, bind_ip: str, client_id: str) -> None:
        self.bind_ip = bind_ip
        self.client_id = client_id
        self.authorization_requests = 0
        self.callback_requests = 0
        self.token_requests = 0
        self.userinfo_requests = 0
        self.other_requests: list[dict[str, Any]] = []
        self.authorization_query_keys: list[str] = []
        self.callback_query_keys: list[str] = []
        self.callback_path = ""
        self.redirect_uri_seen = False
        self.client_id_matches = False
        self.state_seen = False
        self._code = "TEST-" + secrets.token_urlsafe(18)
        self._access_token = "TEST-" + secrets.token_urlsafe(22)
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "LuckySkillsOIDC/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _record_other(self, parsed: urllib.parse.SplitResult, method: str) -> None:
                if len(fixture.other_requests) >= 20:
                    return
                fixture.other_requests.append(
                    {
                        "method": method,
                        "path": parsed.path,
                        "query_keys": sorted(urllib.parse.parse_qs(parsed.query).keys()),
                    }
                )

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
                parsed = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/authorize":
                    fixture.authorization_requests += 1
                    fixture.authorization_query_keys = sorted(query.keys())
                    fixture.redirect_uri_seen = bool(query.get("redirect_uri", [""])[0])
                    fixture.client_id_matches = query.get("client_id", [""])[0] == fixture.client_id
                    fixture.state_seen = bool(query.get("state", [""])[0])
                    redirect_uri = query.get("redirect_uri", [""])[0]
                    if not redirect_uri:
                        self._json(400, {"error": "missing_redirect_uri"})
                        return
                    target = urllib.parse.urlsplit(redirect_uri)
                    callback_query = urllib.parse.parse_qs(target.query)
                    callback_query["code"] = [fixture._code]
                    state = query.get("state", [""])[0]
                    if state:
                        callback_query["state"] = [state]
                    location = urllib.parse.urlunsplit(
                        (
                            target.scheme,
                            target.netloc,
                            target.path,
                            urllib.parse.urlencode(callback_query, doseq=True),
                            target.fragment,
                        )
                    )
                    self.send_response(302)
                    self.send_header("Location", location)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if parsed.path == "/.well-known/openid-configuration":
                    origin = f"http://{fixture.bind_ip}:{fixture.port}"
                    self._json(
                        200,
                        {
                            "issuer": origin,
                            "authorization_endpoint": origin + "/authorize",
                            "token_endpoint": origin + "/token",
                            "userinfo_endpoint": origin + "/userinfo",
                            "jwks_uri": origin + "/jwks",
                            "response_types_supported": ["code"],
                            "subject_types_supported": ["public"],
                            "id_token_signing_alg_values_supported": ["none"],
                        },
                    )
                    return
                if parsed.path == "/jwks":
                    self._json(200, {"keys": []})
                    return
                if parsed.path == "/userinfo":
                    fixture.userinfo_requests += 1
                    self._json(
                        200,
                        {
                            "sub": "TEST-SUBJECT",
                            "name": "Lucky Skills OAuth CI",
                            "email": "test-oauth-ci@example.invalid",
                            "preferred_username": "lucky-skills-oauth-ci",
                        },
                    )
                    return
                # OIDCRedirectURI deliberately lands on this owned fixture.
                if parsed.path.startswith("/callback"):
                    fixture.callback_requests += 1
                    fixture.callback_path = parsed.path
                    fixture.callback_query_keys = sorted(query.keys())
                    self._json(200, {"ok": True})
                    return
                fixture._record_other(parsed, "GET")
                self._json(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
                parsed = urllib.parse.urlsplit(self.path)
                length = min(int(self.headers.get("Content-Length", "0") or "0"), 65536)
                body = self.rfile.read(length) if length else b""
                if parsed.path == "/token":
                    fixture.token_requests += 1
                    # Do not retain the authorization code or client values.
                    _ = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
                    self._json(
                        200,
                        {
                            "access_token": fixture._access_token,
                            "token_type": "Bearer",
                            "expires_in": 300,
                        },
                    )
                    return
                fixture._record_other(parsed, "POST")
                self._json(404, {"error": "not_found"})

        self.server = http.server.ThreadingHTTPServer((bind_ip, 0), Handler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def follow_authorization(auth_url: str, expected_host: str, expected_port: int) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(auth_url)
    if parsed.scheme != "http" or parsed.hostname != expected_host or parsed.port != expected_port:
        raise ProbeError("Lucky authorization URL escaped the owned OIDC fixture")
    opener = urllib.request.build_opener()
    request = urllib.request.Request(auth_url, headers={"User-Agent": "lucky-skills-oauth-ci-browser/1"})
    try:
        with opener.open(request, timeout=10) as response:
            response.read(65536)
            return {
                "status": int(response.status),
                "final_path": urllib.parse.urlsplit(response.geturl()).path,
            }
    except urllib.error.HTTPError as error:
        error.read(65536)
        return {"status": int(error.code), "final_path": urllib.parse.urlsplit(error.geturl()).path}


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise ProbeError("docker and openssl are required on the GitHub runner")

    nonce = secrets.token_hex(5)
    network_name = f"lucky-oauth-ci-{nonce}"
    bridge_name = f"broauth{nonce[:6]}"
    container_name = f"lucky-oauth-ci-{nonce}"
    client_id = TEST_PREFIX + nonce
    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_lucky_operations": True,
        "network_internal": False,
        "admin_port_unpublished": False,
        "default_admin_login": False,
        "browser_cookie_names": [],
        "oauth_config_baseline_empty": False,
        "oauth_user_baseline_empty": False,
        "oauth_test_client_configured": False,
        "tmpcode_ret": None,
        "tmpcode_msg": "",
        "tmpcode_response_shape": {},
        "frontend_runtime_snippets": {},
        "tmpcode_attempts": [],
        "tmpcode_available": False,
        "auth_url_owned": False,
        "auth_server_shape": "",
        "authorization_followed": False,
        "authorization_query_keys": [],
        "authorization_client_id_matches": False,
        "authorization_redirect_uri_seen": False,
        "authorization_state_seen": False,
        "callback_seen": False,
        "callback_query_keys": [],
        "provider_token_requests": 0,
        "provider_userinfo_requests": 0,
        "provider_other_requests": [],
        "oauth_status_shape": {},
        "oauth_status_ret_values": [],
        "oauth_userinfo_shape": {},
        "oauth_userinfo_ret": None,
        "third_party_user_created": False,
        "config_restored": False,
        "user_baseline_restored": False,
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-oauth-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
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
        provider: FakeOidcProvider | None = None
        base_url = ""
        admin_token = ""
        baseline_config: dict[str, Any] | None = None
        baseline_users: list[dict[str, Any]] = []
        try:
            gateway_ip, _ = docker_network_values(network_name)
            report["network_internal"] = True
            provider = FakeOidcProvider(gateway_ip, client_id)
            provider.start()
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
            if not report["admin_port_unpublished"]:
                raise ProbeError("temporary Lucky admin port was unexpectedly published")
            admin_token, browser_opener, cookie_names = login_browser_admin(base_url, tmp)
            report["default_admin_login"] = True
            report["browser_cookie_names"] = cookie_names

            info = admin_json(base_url, admin_token, "/api/info", opener=browser_opener).get("info")
            if not isinstance(info, dict):
                raise ProbeError("Lucky info response missing info object")
            report["lucky_version"] = str(info.get("Version") or "")
            if report["lucky_version"] != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {report['lucky_version']!r}")
            report["frontend_runtime_snippets"] = frontend_runtime_snippets(base_url)

            config_response = admin_json(
                base_url, admin_token, "/api/thirdPartyAuthManager/config", opener=browser_opener
            )
            baseline_config = config_response.get("config")
            if not isinstance(baseline_config, dict):
                raise ProbeError("third-party auth config missing config object")
            report["oauth_config_baseline_empty"] = all(
                not baseline_config.get(key)
                for key in ("OIDCRedirectURI", "OIDCClientID", "OIDCAuthorizationEndpoint")
            )
            users_response = admin_json(
                base_url, admin_token, "/api/thirdPartyAuthManager/list", opener=browser_opener
            )
            raw_users = users_response.get("list") or []
            if not isinstance(raw_users, list) or not all(isinstance(row, dict) for row in raw_users):
                raise ProbeError("third-party auth list has unexpected shape")
            baseline_users = list(raw_users)
            report["oauth_user_baseline_empty"] = not baseline_users
            if not report["oauth_user_baseline_empty"]:
                raise ProbeError("fresh disposable Lucky third-party auth list was not empty")

            updated = dict(baseline_config)
            provider_origin = f"http://{gateway_ip}:{provider.port}"
            updated["OIDCAuthorizationEndpoint"] = provider_origin + "/authorize"
            updated["OIDCClientID"] = client_id
            updated["OIDCRedirectURI"] = provider_origin + "/callback/oidc"
            admin_json(
                base_url,
                admin_token,
                "/api/thirdPartyAuthManager/config",
                method="PUT",
                payload=updated,
                opener=browser_opener,
            )
            live_config = admin_json(
                base_url, admin_token, "/api/thirdPartyAuthManager/config", opener=browser_opener
            ).get("config")
            report["oauth_test_client_configured"] = (
                isinstance(live_config, dict)
                and live_config.get("OIDCAuthorizationEndpoint") == updated["OIDCAuthorizationEndpoint"]
                and live_config.get("OIDCClientID") == client_id
                and live_config.get("OIDCRedirectURI") == updated["OIDCRedirectURI"]
            )

            tmpcode_query = urllib.parse.urlencode(
                {"type": "oidc", "_": lucky_frontend_timestamp()}
            )
            tmpcode = admin_json(
                base_url,
                admin_token,
                "/api/oauth/tmpcode?" + tmpcode_query,
                require_zero=False,
                opener=browser_opener,
            )
            attempts: list[dict[str, Any]] = [
                {"mode": "admin-token", "ret": tmpcode.get("ret")}
            ]
            if tmpcode.get("ret") != 0:
                for mode, values in (
                    ("origin", (True, False, False)),
                    ("origin-referer", (True, True, False)),
                    ("origin-referer-xrw", (True, True, True)),
                ):
                    candidate = tmpcode_browser_attempt(
                        base_url,
                        admin_token,
                        browser_opener,
                        include_origin=values[0],
                        include_referer=values[1],
                        include_xrw=values[2],
                    )
                    attempts.append({"mode": mode, "ret": candidate.get("ret")})
                    if candidate.get("ret") == 0:
                        tmpcode = candidate
                        break
            report["tmpcode_attempts"] = attempts
            report["tmpcode_ret"] = tmpcode.get("ret")
            report["tmpcode_msg"] = str(tmpcode.get("msg") or tmpcode.get("message") or "")[:240]
            report["tmpcode_response_shape"] = json_shape(tmpcode)
            tmp_code = tmpcode.get("tmpCode") or tmpcode.get("tmpcode") or tmpcode.get("code")
            auth_url = tmpcode.get("authUrl") or tmpcode.get("authurl")
            auth_server = tmpcode.get("authServer") or tmpcode.get("authserver")
            report["tmpcode_available"] = isinstance(tmp_code, str) and bool(tmp_code)
            if isinstance(auth_server, str):
                auth_server_parsed = urllib.parse.urlsplit(auth_server)
                report["auth_server_shape"] = (
                    f"{auth_server_parsed.scheme}://owned{auth_server_parsed.path}"
                    if auth_server_parsed.hostname == gateway_ip
                    else f"{auth_server_parsed.scheme}://external{auth_server_parsed.path}"
                )
            if isinstance(auth_url, str) and auth_url:
                parsed = urllib.parse.urlsplit(auth_url)
                report["auth_url_owned"] = parsed.hostname == gateway_ip and parsed.port == provider.port
                if report["auth_url_owned"]:
                    follow = follow_authorization(auth_url, gateway_ip, provider.port)
                    report["authorization_followed"] = follow.get("status") == 200

            # Give the fixture redirect a moment to settle, then poll exactly as
            # the frontend does.  No raw temporary code is reported.
            if report["tmpcode_available"]:
                seen_rets: list[Any] = []
                last_status: dict[str, Any] = {}
                deadline = time.time() + 12
                while time.time() < deadline:
                    status_query = urllib.parse.urlencode(
                        {
                            "code": str(tmp_code),
                            "type": "oidc",
                            "_": lucky_frontend_timestamp(),
                        }
                    )
                    last_status = admin_json(
                        base_url,
                        admin_token,
                        "/api/oauth/status?" + status_query,
                        require_zero=False,
                        opener=browser_opener,
                    )
                    ret = last_status.get("ret")
                    if ret not in seen_rets:
                        seen_rets.append(ret)
                    if ret == 0:
                        break
                    time.sleep(0.5)
                report["oauth_status_ret_values"] = seen_rets
                report["oauth_status_shape"] = json_shape(last_status)
                userinfo_query = urllib.parse.urlencode(
                    {
                        "code": str(tmp_code),
                        "type": "oidc",
                        "_": lucky_frontend_timestamp(),
                    }
                )
                userinfo = admin_json(
                    base_url,
                    admin_token,
                    "/api/oauth/userinfo?" + userinfo_query,
                    require_zero=False,
                    opener=browser_opener,
                )
                report["oauth_userinfo_ret"] = userinfo.get("ret")
                report["oauth_userinfo_shape"] = json_shape(userinfo)

            report["authorization_query_keys"] = provider.authorization_query_keys
            report["authorization_client_id_matches"] = provider.client_id_matches
            report["authorization_redirect_uri_seen"] = provider.redirect_uri_seen
            report["authorization_state_seen"] = provider.state_seen
            report["callback_seen"] = provider.callback_requests > 0
            report["callback_query_keys"] = provider.callback_query_keys
            report["provider_token_requests"] = provider.token_requests
            report["provider_userinfo_requests"] = provider.userinfo_requests
            report["provider_other_requests"] = provider.other_requests

            after_users = admin_json(
                base_url, admin_token, "/api/thirdPartyAuthManager/list", opener=browser_opener
            ).get("list") or []
            if isinstance(after_users, list):
                report["third_party_user_created"] = len(after_users) > len(baseline_users)
        finally:
            if base_url and admin_token and baseline_config is not None:
                try:
                    admin_json(
                        base_url,
                        admin_token,
                        "/api/thirdPartyAuthManager/config",
                        method="PUT",
                        payload=baseline_config,
                        opener=browser_opener if "browser_opener" in locals() else None,
                    )
                    restored = admin_json(
                        base_url,
                        admin_token,
                        "/api/thirdPartyAuthManager/config",
                        opener=browser_opener if "browser_opener" in locals() else None,
                    ).get("config")
                    report["config_restored"] = restored == baseline_config
                    restored_users = admin_json(
                        base_url,
                        admin_token,
                        "/api/thirdPartyAuthManager/list",
                        opener=browser_opener if "browser_opener" in locals() else None,
                    ).get("list") or []
                    report["user_baseline_restored"] = restored_users == baseline_users
                except Exception:  # noqa: BLE001 - cleanup must continue
                    pass
            if provider is not None:
                provider.close()
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    # Reconnaissance gate: these must already work before we claim OAuth E2E.
    required_true = (
        "api_only_lucky_operations",
        "network_internal",
        "admin_port_unpublished",
        "default_admin_login",
        "oauth_config_baseline_empty",
        "oauth_user_baseline_empty",
        "oauth_test_client_configured",
        "tmpcode_available",
        "auth_url_owned",
        "authorization_followed",
        "authorization_client_id_matches",
        "authorization_redirect_uri_seen",
        "callback_seen",
        "config_restored",
        "user_baseline_restored",
    )
    failed = [name for name in required_true if report.get(name) is not True]
    # Full E2E requires Lucky to transition the temporary authorization and
    # expose provider userinfo.  First runs may intentionally fail here while
    # preserving the precise relay/request shapes needed for the next patch.
    if report.get("oauth_status_ret_values") and 0 not in report["oauth_status_ret_values"]:
        failed.append("oauth_status_completed")
    if report.get("oauth_userinfo_ret") != 0:
        failed.append("oauth_userinfo_completed")
    report["failed"] = failed
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2), file=sys.stderr)
        raise SystemExit(2)
