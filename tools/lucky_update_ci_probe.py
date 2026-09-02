#!/usr/bin/env python3
"""Inspect and stage Lucky self-update only in disposable GitHub Actions CI.

The probe starts a fresh pinned Lucky 3.0.0 container on runner loopback,
downloads one official Lucky Linux x86_64 release tarball as a package-format
fixture, uploads it through the current /api/update file endpoint, records only
safe response shape/version metadata, then cancels any staged update. It does
not confirm replacement in this first stage.

No production instance or production binary is contacted.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import tempfile
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


MAX_UPDATE_BYTES = 128 * 1024 * 1024
FIXTURE_VERSION = "2.27.2"
FIXTURE_URL = (
    "https://github.com/gdy666/lucky/releases/download/v2.27.2/"
    "lucky_2.27.2_Linux_x86_64.tar.gz"
)


def auth_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/json, */*;q=0.8",
        "User-Agent": "lucky-skills-update-ci/1",
        "Lucky-Admin-Token": token,
        "Authorization": f"Bearer {token}",
    }


def multipart_binary(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = f"----lucky-skills-update-{secrets.token_hex(12)}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/gzip\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    return head + data + tail, f"multipart/form-data; boundary={boundary}"


def upload_update(base_url: str, token: str, package: bytes) -> tuple[int, dict[str, Any]]:
    body, content_type = multipart_binary(
        f"lucky_{FIXTURE_VERSION}_Linux_x86_64.tar.gz",
        package,
    )
    headers = auth_headers(token)
    headers["Content-Type"] = content_type
    request = urllib.request.Request(
        base_url + "/api/update",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read(2 * 1024 * 1024)
            status = int(response.status)
    except urllib.error.HTTPError as error:
        raw = error.read(2 * 1024 * 1024)
        status = int(error.code)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeError(f"update upload returned non-JSON HTTP {status}") from None
    if not isinstance(payload, dict):
        raise ProbeError("update upload returned non-object JSON")
    return status, payload


def safe_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            lowered = name.lower()
            if any(secret in lowered for secret in ("token", "password", "secret", "key")):
                result[name] = {"present": item is not None}
            elif isinstance(item, (str, int, float, bool)) or item is None:
                result[name] = item
            else:
                result[name] = {"type": type(item).__name__}
        return result
    return {"type": type(value).__name__}


def download_fixture() -> bytes:
    request = urllib.request.Request(
        FIXTURE_URL,
        headers={"User-Agent": "lucky-skills-update-ci/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_UPDATE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise ProbeError(f"official update fixture HTTP {error.code}") from None
    if not data or len(data) > MAX_UPDATE_BYTES:
        raise ProbeError("official update fixture was empty or exceeded CI safety limit")
    if not data.startswith(b"\x1f\x8b"):
        raise ProbeError("official update fixture was not gzip data")
    return data


def frontend_update_context(base_url: str) -> dict[str, Any]:
    """Return focused non-locale contexts around update upload/confirm calls."""

    origin = urllib.parse.urlsplit(base_url)
    queue = ["/"]
    seen: set[str] = set()
    fetched = 0
    max_bytes = 28 * 1024 * 1024
    markers = ("api/update/comfire", "api/update/cancel", 'vt()+"api/update"', "Yd()")
    found: dict[str, list[dict[str, Any]]] = {marker: [] for marker in markers}

    while queue and len(seen) < 180 and fetched < max_bytes:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        request = urllib.request.Request(
            base_url + path,
            headers={"User-Agent": "lucky-skills-update-ci-inspector/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read(min(4 * 1024 * 1024, max_bytes - fetched))
        except Exception:  # noqa: BLE001 - best-effort asset crawl
            continue
        fetched += len(raw)
        text = raw.decode("utf-8", errors="replace")
        is_locale = "lucky_locale-" in path
        if not is_locale:
            for marker in markers:
                for match in list(re.finditer(re.escape(marker), text))[:8]:
                    start = max(0, match.start() - 1100)
                    end = min(len(text), match.end() + 2400)
                    found[marker].append(
                        {
                            "path": path,
                            "position": match.start(),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "context": " ".join(text[start:end].split()),
                        }
                    )
        candidates = set(
            re.findall(r"(?:src=|href=)?[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", text)
        )
        candidates.update(re.findall(r"(?:\./)?(static/js/[A-Za-z0-9_./-]+\.js)", text))
        for candidate in candidates:
            resolved = urllib.parse.urljoin(base_url + path, candidate)
            parsed = urllib.parse.urlsplit(resolved)
            if parsed.scheme == origin.scheme and parsed.netloc == origin.netloc:
                candidate_path = parsed.path
                if candidate_path.endswith(".js") and candidate_path not in seen:
                    queue.append(candidate_path)

    return {
        "files_seen": len(seen),
        "bytes_fetched": fetched,
        "markers": {key: value for key, value in found.items() if value},
    }


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-update-ci-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"

    report: dict[str, Any] = {
        "lucky_version": "",
        "network_scope": "runner-loopback",
        "fixture_version": FIXTURE_VERSION,
        "fixture_downloaded": False,
        "fixture_size": 0,
        "fixture_sha256": "",
        "upload_http_status": 0,
        "upload_ret": None,
        "upload_response_keys": [],
        "upload_safe_metadata": {},
        "upload_accepted": False,
        "cancel_ret_zero": False,
        "frontend": {},
    }

    with tempfile.TemporaryDirectory(prefix="lucky-update-ci-", dir=runner_temp) as tmp_raw:
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

            report["frontend"] = frontend_update_context(base_url)
            package = download_fixture()
            report["fixture_downloaded"] = True
            report["fixture_size"] = len(package)
            report["fixture_sha256"] = hashlib.sha256(package).hexdigest()

            upload_status, upload = upload_update(base_url, token, package)
            report["upload_http_status"] = upload_status
            report["upload_ret"] = upload.get("ret")
            report["upload_response_keys"] = sorted(str(key) for key in upload.keys())
            report["upload_safe_metadata"] = {
                str(key): safe_metadata(value)
                for key, value in upload.items()
                if key not in {"file", "path"}
            }
            report["upload_accepted"] = upload_status == 200 and upload.get("ret") == 0

            # Always exercise cancellation when the upload reached the handler;
            # this keeps the first-stage inspector from confirming replacement.
            cancel_status, cancel = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/update/cancel",
                admin_token=token,
            )
            report["cancel_ret_zero"] = cancel_status == 200 and cancel.get("ret") == 0

            response_was_classified = (
                upload_status == 200
                and type(upload.get("ret")) is int
                and report["cancel_ret_zero"]
            )
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if response_was_classified else 2
        finally:
            docker("rm", "-f", container_name, timeout=45)
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
