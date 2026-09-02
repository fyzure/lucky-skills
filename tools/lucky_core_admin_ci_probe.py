#!/usr/bin/env python3
"""Verify Lucky 3.0.0 core-admin behavior in disposable CI.

It refuses to run outside GitHub Actions and starts a fresh pinned Lucky
container published only on runner loopback. The probe verifies password
change, global 2FA enable/key replacement/disable and reboot_program against
that disposable instance. It also retains focused frontend context used to
cross-check the dedicated configuration-restore and self-update CI probes.

No production Lucky instance is contacted. Passwords, 2FA secrets/codes,
OpenToken values, SafeURL values and configuration backup bodies are never
printed or persisted.
"""

from __future__ import annotations

import hashlib
import base64
import hmac
import json
import re
import secrets
import struct
import tempfile
import time
import urllib.parse
import urllib.error
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
    login_default_admin,
    pull_pinned_image,
    rsa_encrypt_with_openssl,
    require_github_hosted_runner,
    require_ret_zero,
    wait_for_lucky,
)
from lucky_rclone_mount_ci_probe import choose_loopback_port


MARKERS = (
    "api/2fa/setting",
    "reboot_program",
    "restoreconfigureconfirm",
    "api/update/comfire",
    "api/update/cancel",
    "AdminPassword",
    "OldPassword",
    "TwoFAEnable",
    "TwoFACode",
)


def totp(secret: str, *, at: int | None = None, digits: int = 6) -> str:
    """Generate RFC 6238 SHA-1 TOTP without external dependencies."""

    when = int(time.time()) if at is None else int(at)
    counter = when // 30
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def login_admin(
    base_url: str,
    workdir: Path,
    *,
    password: str,
    twofa: str = "",
) -> tuple[bool, str]:
    """Attempt login while returning only success + token, never credentials."""

    opener = urllib.request.build_opener()
    status, challenge = json_request(opener, base_url, "/api/login/challenge")
    require_ret_zero(status, challenge, "login challenge")
    for key in ("challengeId", "nonce", "publicKey"):
        if not challenge.get(key):
            raise ProbeError(f"login challenge missing {key}")
    plaintext = json.dumps(
        {
            "account": "666",
            "password": password,
            "twoFA": twofa,
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
    if status == 200 and response.get("ret") == 0:
        token = response.get("token")
        if not isinstance(token, str) or not token.strip():
            raise ProbeError("successful admin login returned no token")
        return True, token
    return False, ""


def read_baseconfigure(base_url: str, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    opener = urllib.request.build_opener()
    status, response = json_request(opener, base_url, "/api/baseconfigure", admin_token=token)
    require_ret_zero(status, response, "read baseconfigure")
    config = response.get("baseconfigure")
    if not isinstance(config, dict):
        raise ProbeError("baseconfigure response missing baseconfigure object")
    return response, config


def put_json_admin(
    base_url: str,
    token: str,
    path: str,
    payload: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        path,
        method="PUT",
        payload=payload,
        admin_token=token,
    )
    return require_ret_zero(status, response, label)


def wait_http_ready(base_url: str, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, response = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/login/challenge",
                timeout=2,
            )
            if status == 200 and response.get("ret") == 0:
                return
        except Exception:  # noqa: BLE001 - restart readiness loop
            pass
        time.sleep(0.5)
    raise ProbeError("Lucky did not become ready after reboot_program")


def frontend_context(base_url: str) -> dict[str, Any]:
    """Crawl served same-origin JS and return focused, non-secret contexts."""

    origin = urllib.parse.urlsplit(base_url)
    queue = ["/"]
    seen: set[str] = set()
    found: dict[str, list[dict[str, Any]]] = {marker: [] for marker in MARKERS}
    fetched = 0
    max_bytes = 28 * 1024 * 1024

    while queue and len(seen) < 180 and fetched < max_bytes:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        request = urllib.request.Request(
            base_url + path,
            headers={"User-Agent": "lucky-skills-core-admin-ci-inspector/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read(min(4 * 1024 * 1024, max_bytes - fetched))
        except Exception:  # noqa: BLE001 - discovery crawl is best effort
            continue
        fetched += len(raw)
        text = raw.decode("utf-8", errors="replace")

        for marker in MARKERS:
            if len(found[marker]) >= 8:
                continue
            for match in re.finditer(re.escape(marker), text):
                start = max(0, match.start() - 1100)
                end = min(len(text), match.end() + 2100)
                found[marker].append(
                    {
                        "path": path,
                        "position": match.start(),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "context": " ".join(text[start:end].split()),
                    }
                )
                if len(found[marker]) >= 8:
                    break

        candidates = set(
            re.findall(r"(?:src=|href=)?[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", text)
        )
        candidates.update(re.findall(r"(?:\./)?(static/js/[A-Za-z0-9_./-]+\.js)", text))
        for candidate in candidates:
            resolved = urllib.parse.urljoin(base_url + path, candidate)
            parsed = urllib.parse.urlsplit(resolved)
            if parsed.scheme != origin.scheme or parsed.netloc != origin.netloc:
                continue
            candidate_path = parsed.path
            if candidate_path.endswith(".js") and candidate_path not in seen:
                queue.append(candidate_path)

        if all(found[marker] for marker in MARKERS):
            break

    return {
        "files_seen": len(seen),
        "bytes_fetched": fetched,
        "markers": {marker: contexts for marker, contexts in found.items() if contexts},
    }


def safe_baseconfigure_summary(base_url: str, token: str) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        "/api/baseconfigure",
        admin_token=token,
    )
    require_ret_zero(status, response, "read disposable baseconfigure")
    config = response.get("baseconfigure")
    if not isinstance(config, dict):
        raise ProbeError("baseconfigure response missing baseconfigure object")

    safe_values: dict[str, Any] = {}
    for key in (
        "TwoFAEnable",
        "TwoFADigits",
        "EnableOpenToken",
        "IgnoreSafeURLCheck",
        "IgnoreAuthInfoCheck",
        "RestartAfterPanic",
        "AdminWebListenPort",
        "AdminWebListenTLS",
    ):
        value = config.get(key)
        if isinstance(value, (bool, int)) and not isinstance(value, str):
            safe_values[key] = value
        elif value is not None:
            safe_values[key] = {"type": type(value).__name__}

    sensitive_presence = {
        key: key in config
        for key in (
            "AdminPassword",
            "OldPassword",
            "TwoFAKey",
            "OpenToken",
            "SafeURL",
        )
    }
    return {
        "top_level_keys": sorted(response.keys()),
        "baseconfigure_key_count": len(config),
        "safe_values": safe_values,
        "sensitive_field_presence_only": sensitive_presence,
        "twofa_key_set_type": type(response.get("TwoFAKeySet")).__name__,
    }


def lucky_process_pid(container_name: str) -> int:
    output = docker("top", container_name, "-eo", "pid,args", timeout=30)
    for line in output.splitlines()[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid_raw, args = parts
        if "lucky" not in args.lower():
            continue
        try:
            return int(pid_raw)
        except ValueError:
            continue
    raise ProbeError("could not identify Lucky process in disposable container")


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-core-admin-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"
    new_password = "Ci!" + secrets.token_urlsafe(18) + "9aZ"
    first_2fa_secret = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
    second_2fa_secret = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
    while second_2fa_secret == first_2fa_secret:
        second_2fa_secret = base64.b32encode(secrets.token_bytes(10)).decode("ascii")

    report: dict[str, Any] = {
        "lucky_version": "",
        "network_scope": "runner-loopback",
        "baseconfigure": {},
        "frontend": {},
        "password_old_verified": False,
        "password_changed": False,
        "old_password_rejected": False,
        "new_password_login": False,
        "twofa_enabled": False,
        "login_without_twofa_rejected": False,
        "login_with_first_twofa": False,
        "twofa_key_replaced": False,
        "old_twofa_rejected_after_replace": False,
        "login_with_replaced_twofa": False,
        "twofa_disabled": False,
        "login_without_twofa_after_disable": False,
        "reboot_triggered": False,
        "reboot_process_changed": False,
        "reboot_http_recovered": False,
        "post_reboot_login": False,
    }

    with tempfile.TemporaryDirectory(prefix="lucky-core-admin-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        conf_dir.mkdir()
        try:
            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--restart",
                "always",
                "--network",
                "bridge",
                "-p",
                f"127.0.0.1:{host_port}:{ADMIN_PORT}",
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            wait_for_lucky(base_url, container_name)
            token = login_default_admin(base_url, tmp)

            opener = urllib.request.build_opener()
            status, info = json_request(opener, base_url, "/api/info", admin_token=token)
            require_ret_zero(status, info, "read Lucky info")
            info_obj = info.get("info")
            version = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {version!r}")

            report["baseconfigure"] = safe_baseconfigure_summary(base_url, token)
            report["frontend"] = frontend_context(base_url)

            missing = [
                marker
                for marker in MARKERS
                if marker not in report["frontend"].get("markers", {})
            ]
            report["missing_markers"] = missing

            # Password change: verify the existing password first, matching the
            # current frontend workflow, then update the full fresh-instance
            # baseconfigure object in memory. No credential values are logged.
            put_json_admin(
                base_url,
                token,
                "/api/password/verify",
                {"oldPassword": "666"},
                "verify disposable old password",
            )
            report["password_old_verified"] = True

            _baseline_response, baseline_config = read_baseconfigure(base_url, token)
            changed_config = dict(baseline_config)
            changed_config["AdminPassword"] = new_password
            changed_config["OldPassword"] = "666"
            # A brand-new Lucky instance starts with the default account and an
            # empty SafeURL. These flags only suppress first-save guards inside
            # this disposable runner-loopback instance.
            changed_config["IgnoreSafeURLCheck"] = True
            changed_config["IgnoreAuthInfoCheck"] = True
            put_json_admin(
                base_url,
                token,
                "/api/baseconfigure",
                changed_config,
                "change disposable admin password",
            )
            report["password_changed"] = True

            old_ok, _ = login_admin(base_url, tmp, password="666")
            report["old_password_rejected"] = not old_ok
            new_ok, token = login_admin(base_url, tmp, password=new_password)
            report["new_password_login"] = new_ok
            if not new_ok:
                raise ProbeError("new disposable admin password could not log in")

            # Enable global 2FA with an owned 16-character Base32 key. Lucky's
            # frontend requires a six-digit confirmation code generated from
            # that same key.
            first_code = totp(first_2fa_secret)
            put_json_admin(
                base_url,
                token,
                "/api/2fa/setting",
                {
                    "TwoFAEnable": True,
                    "TwoFAKey": first_2fa_secret,
                    "TwoFACode": first_code,
                },
                "enable disposable global 2FA",
            )
            # Changing login policy invalidates the current admin token. Prove
            # the new gate first, then use the newly authenticated token for
            # configuration readback.
            without_2fa_ok, _ = login_admin(base_url, tmp, password=new_password)
            report["login_without_twofa_rejected"] = not without_2fa_ok
            first_code = totp(first_2fa_secret)
            first_2fa_ok, token = login_admin(
                base_url,
                tmp,
                password=new_password,
                twofa=first_code,
            )
            report["login_with_first_twofa"] = first_2fa_ok
            if not first_2fa_ok:
                raise ProbeError("2FA-enabled login with current code failed")
            twofa_response, twofa_config = read_baseconfigure(base_url, token)
            report["twofa_enabled"] = bool(twofa_config.get("TwoFAEnable")) and bool(
                twofa_response.get("TwoFAKeySet")
            )
            if not report["twofa_enabled"]:
                raise ProbeError("global 2FA did not become enabled")

            # Replace the global 2FA key while enabled. Avoid the vanishingly
            # small case where both secrets produce the same current code so
            # the old-key rejection check stays deterministic.
            first_code = totp(first_2fa_secret)
            second_code = totp(second_2fa_secret)
            while second_code == first_code:
                second_2fa_secret = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
                second_code = totp(second_2fa_secret)
            put_json_admin(
                base_url,
                token,
                "/api/2fa/setting",
                {
                    "TwoFAEnable": True,
                    "TwoFAKey": second_2fa_secret,
                    "TwoFACode": second_code,
                },
                "replace disposable global 2FA key",
            )
            report["twofa_key_replaced"] = True

            # Key replacement invalidates the token for the same reason. The
            # old secret must fail and the replacement secret must establish a
            # fresh session.
            old_2fa_ok, _ = login_admin(
                base_url,
                tmp,
                password=new_password,
                twofa=totp(first_2fa_secret),
            )
            report["old_twofa_rejected_after_replace"] = not old_2fa_ok
            replaced_ok, token = login_admin(
                base_url,
                tmp,
                password=new_password,
                twofa=totp(second_2fa_secret),
            )
            report["login_with_replaced_twofa"] = replaced_ok
            if not replaced_ok:
                raise ProbeError("login with replaced 2FA key failed")

            # Current UI requires the current code to turn 2FA off. An empty
            # TwoFAKey means no replacement is requested during disable.
            put_json_admin(
                base_url,
                token,
                "/api/2fa/setting",
                {
                    "TwoFAEnable": False,
                    "TwoFAKey": "",
                    "TwoFACode": totp(second_2fa_secret),
                },
                "disable disposable global 2FA",
            )
            # Disabling 2FA invalidates the 2FA-authenticated token. Re-login
            # password-only, then confirm the persisted state.
            no_2fa_ok, token = login_admin(base_url, tmp, password=new_password)
            report["login_without_twofa_after_disable"] = no_2fa_ok
            if not no_2fa_ok:
                raise ProbeError("login without 2FA failed after disabling 2FA")
            _disabled_response, disabled_config = read_baseconfigure(base_url, token)
            report["twofa_disabled"] = disabled_config.get("TwoFAEnable") is False

            # reboot_program is exercised only after authentication is back to
            # password-only. Docker restart=always provides the disposable
            # supervisor; process identity must change and HTTP must recover.
            pid_before = lucky_process_pid(container_name)
            try:
                status, reboot_response = json_request(
                    urllib.request.build_opener(),
                    base_url,
                    "/api/reboot_program",
                    admin_token=token,
                    timeout=5,
                )
                report["reboot_triggered"] = status == 200 and reboot_response.get("ret") == 0
            except Exception:  # noqa: BLE001 - process may close the socket while exiting
                report["reboot_triggered"] = True

            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    if lucky_process_pid(container_name) != pid_before:
                        report["reboot_process_changed"] = True
                        break
                except Exception:  # noqa: BLE001 - container may be between restarts
                    pass
                time.sleep(0.25)
            wait_http_ready(base_url, timeout=30)
            report["reboot_http_recovered"] = True
            post_reboot_ok, _post_reboot_token = login_admin(
                base_url,
                tmp,
                password=new_password,
            )
            report["post_reboot_login"] = post_reboot_ok

            required_true = (
                "password_old_verified",
                "password_changed",
                "old_password_rejected",
                "new_password_login",
                "twofa_enabled",
                "login_without_twofa_rejected",
                "login_with_first_twofa",
                "twofa_key_replaced",
                "old_twofa_rejected_after_replace",
                "login_with_replaced_twofa",
                "twofa_disabled",
                "login_without_twofa_after_disable",
                "reboot_triggered",
                "reboot_process_changed",
                "reboot_http_recovered",
                "post_reboot_login",
            )
            failed = [name for name in required_true if report.get(name) is not True]
            report["failed"] = failed
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 1 if missing or failed else 0
        finally:
            docker("rm", "-f", container_name, timeout=45)
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
