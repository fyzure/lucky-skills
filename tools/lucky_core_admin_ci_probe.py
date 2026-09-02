#!/usr/bin/env python3
"""Inspect Lucky 3.0.0 core-admin frontend semantics in disposable CI.

This is intentionally a discovery probe for high-risk administration flows.
It refuses to run outside GitHub Actions, starts a fresh pinned Lucky container
published only on runner loopback, logs in with the disposable default account,
and records only frontend call context plus safe configuration types/booleans.

No production Lucky instance is contacted. Passwords, 2FA secrets/codes,
OpenToken values, SafeURL values and configuration backup bodies are never
printed or persisted.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import tempfile
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


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-core-admin-inspect-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"

    report: dict[str, Any] = {
        "lucky_version": "",
        "network_scope": "runner-loopback",
        "baseconfigure": {},
        "frontend": {},
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
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 1 if missing else 0
        finally:
            docker("rm", "-f", container_name, timeout=45)
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
