#!/usr/bin/env python3
"""Verify Lucky 3.0.0 global configuration export/import in disposable CI.

This probe refuses non-GitHub-Actions execution. It starts a fresh pinned Lucky
container published only on runner loopback, changes only disposable global
configuration fields, exports the configuration through GET /api/configure,
changes the marker field again, uploads the exported archive through the
frontend-compatible multipart POST /api/configure, follows any returned
restore-confirmation key, and verifies the exported marker value is restored.

The configuration archive is kept only in runner memory/temporary storage and
is never printed, persisted as evidence, or uploaded anywhere except back to
the same disposable Lucky instance.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
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
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    wait_for_lucky,
)
from lucky_rclone_mount_ci_probe import choose_loopback_port


MAX_CONFIG_BYTES = 32 * 1024 * 1024


def request_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8",
        "User-Agent": "lucky-skills-config-restore-ci/1",
        "Lucky-Admin-Token": token,
        "Authorization": f"Bearer {token}",
    }


def read_baseconfigure(base_url: str, token: str) -> dict[str, Any]:
    status, response = json_request(
        urllib.request.build_opener(),
        base_url,
        "/api/baseconfigure",
        admin_token=token,
    )
    require_ret_zero(status, response, "read disposable baseconfigure")
    config = response.get("baseconfigure")
    if not isinstance(config, dict):
        raise ProbeError("baseconfigure response missing baseconfigure object")
    return config


def write_language(base_url: str, token: str, language: str) -> None:
    config = dict(read_baseconfigure(base_url, token))
    config["FrontendLanguage"] = language
    config["IgnoreSafeURLCheck"] = True
    config["IgnoreAuthInfoCheck"] = True
    status, response = json_request(
        urllib.request.build_opener(),
        base_url,
        "/api/baseconfigure",
        method="PUT",
        payload=config,
        admin_token=token,
    )
    require_ret_zero(status, response, f"set disposable FrontendLanguage={language}")


def export_config(base_url: str, token: str) -> tuple[bytes, str, str]:
    request = urllib.request.Request(
        base_url + "/api/configure",
        headers=request_headers(token),
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(MAX_CONFIG_BYTES + 1)
            content_type = str(response.headers.get("Content-Type") or "")
            content_disposition = str(response.headers.get("Content-Disposition") or "")
    except urllib.error.HTTPError as error:
        body = error.read(1024).decode("utf-8", errors="replace")
        raise ProbeError(f"configuration export HTTP {error.code}: {body[:300]!r}") from None
    if not data or len(data) > MAX_CONFIG_BYTES:
        raise ProbeError("configuration export was empty or exceeded CI safety limit")
    return data, content_type, content_disposition


def multipart_file(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = f"----lucky-skills-config-{secrets.token_hex(12)}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    return head + data + tail, f"multipart/form-data; boundary={boundary}"


def import_config(base_url: str, token: str, archive: bytes) -> dict[str, Any]:
    body, content_type = multipart_file("lucky-config.zip", archive)
    headers = request_headers(token)
    headers["Content-Type"] = content_type
    request = urllib.request.Request(
        base_url + "/api/configure",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(1024 * 1024)
            status = int(response.status)
    except urllib.error.HTTPError as error:
        raw = error.read(1024 * 1024)
        status = int(error.code)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeError(f"configuration import returned non-JSON HTTP {status}") from None
    if not isinstance(decoded, dict):
        raise ProbeError("configuration import returned non-object JSON")
    if status != 200 or decoded.get("ret") != 0:
        safe_keys = sorted(str(key) for key in decoded.keys())
        msg = str(decoded.get("msg") or decoded.get("message") or "")[:300]
        raise ProbeError(
            f"configuration import failed: HTTP {status}, ret={decoded.get('ret')}, "
            f"keys={safe_keys}, msg={msg!r}"
        )
    return decoded


def find_confirmation_key(response: dict[str, Any]) -> str:
    """Extract only an opaque confirmation key without logging the response."""

    preferred = (
        "key",
        "Key",
        "restoreKey",
        "restore_key",
        "confirmKey",
        "confirm_key",
        "tempKey",
        "temp_key",
    )
    for name in preferred:
        value = response.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # Some Lucky envelopes put the temporary key under data.
    data = response.get("data")
    if isinstance(data, dict):
        for name in preferred:
            value = data.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def wait_login_ready(base_url: str, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, challenge = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/login/challenge",
                timeout=2,
            )
            if status == 200 and challenge.get("ret") == 0:
                return
        except Exception:  # noqa: BLE001 - restore may restart the process
            pass
        time.sleep(0.5)
    raise ProbeError("Lucky did not become ready after configuration restore")


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-config-restore-ci-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"

    report: dict[str, Any] = {
        "lucky_version": "",
        "network_scope": "runner-loopback",
        "profile_a_written": False,
        "profile_b_written": False,
        "export_size": 0,
        "export_sha256_recorded": False,
        "export_content_type": "",
        "export_attachment": False,
        "import_response_keys": [],
        "confirmation_required": False,
        "confirmation_succeeded": False,
        "restore_recovered": False,
        "profile_a_restored": False,
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-config-restore-ci-", dir=runner_temp) as tmp_raw:
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

            status, info = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/info",
                admin_token=token,
            )
            require_ret_zero(status, info, "read Lucky info")
            info_obj = info.get("info")
            version = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {version!r}")

            baseline_language = str(read_baseconfigure(base_url, token).get("FrontendLanguage") or "")
            profile_a = "en_US" if baseline_language != "en_US" else "zh_TW"
            profile_b = "zh_CN" if profile_a != "zh_CN" else "en_US"

            write_language(base_url, token, profile_a)
            # Full config writes may invalidate the current session. Re-login
            # with the unchanged default credentials before protected readback.
            token = login_default_admin(base_url, tmp)
            report["profile_a_written"] = (
                read_baseconfigure(base_url, token).get("FrontendLanguage") == profile_a
            )
            if not report["profile_a_written"]:
                raise ProbeError("profile A marker did not persist before export")

            archive, content_type, disposition = export_config(base_url, token)
            report["export_size"] = len(archive)
            _archive_sha = hashlib.sha256(archive).hexdigest()
            report["export_sha256_recorded"] = len(_archive_sha) == 64
            report["export_content_type"] = content_type.split(";", 1)[0].strip().lower()
            report["export_attachment"] = "attachment" in disposition.lower()

            write_language(base_url, token, profile_b)
            token = login_default_admin(base_url, tmp)
            report["profile_b_written"] = (
                read_baseconfigure(base_url, token).get("FrontendLanguage") == profile_b
            )
            if not report["profile_b_written"]:
                raise ProbeError("profile B marker did not persist before import")

            imported = import_config(base_url, token, archive)
            report["import_response_keys"] = sorted(str(key) for key in imported.keys())
            confirmation_key = find_confirmation_key(imported)
            report["confirmation_required"] = bool(confirmation_key)

            if confirmation_key:
                status, confirmed = json_request(
                    urllib.request.build_opener(),
                    base_url,
                    "/api/restoreconfigureconfirm?"
                    + urllib.parse.urlencode({"key": confirmation_key}),
                    admin_token=token,
                    timeout=30,
                )
                require_ret_zero(status, confirmed, "confirm disposable configuration restore")
                report["confirmation_succeeded"] = True

            # Import/confirm may restart Lucky or invalidate the token.
            wait_login_ready(base_url, timeout=30)
            report["restore_recovered"] = True
            token = login_default_admin(base_url, tmp)
            restored = read_baseconfigure(base_url, token)
            report["profile_a_restored"] = restored.get("FrontendLanguage") == profile_a

            required_true = (
                "profile_a_written",
                "profile_b_written",
                "export_sha256_recorded",
                "export_attachment",
                "restore_recovered",
                "profile_a_restored",
            )
            failed = [name for name in required_true if report.get(name) is not True]
            report["failed"] = failed
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 1 if failed else 0
        finally:
            try:
                docker("rm", "-f", container_name, timeout=45)
            except Exception:
                pass
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
