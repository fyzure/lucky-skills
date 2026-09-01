#!/usr/bin/env python3
"""Verify Lucky 3.0.0 Rclone SystemMount on a disposable FUSE-capable CI host.

The probe refuses to run outside GitHub Actions. It starts the repository's
pinned Lucky image with only the FUSE device plus SYS_ADMIN inside a fresh
container, publishes the admin UI only on runner loopback, and performs every
Lucky configuration/path operation through Lucky HTTP APIs.

The test creates one local Rclone remote backed by an owned /tmp source tree,
mounts it at a second owned /tmp path, verifies source -> mount visibility and
mount -> source write-through, then disables/deletes the remote and requires
the mount to disappear before restoring global Rclone/Cron/path baselines.
No production Lucky instance, remote credential, network share or host mount
is touched.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import socket
import sys
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
    run,
    wait_for_lucky,
)


TEST_PREFIX = "TEST-lucky-skills-rclone-mount-ci-"
RCLONE_CHUNK_NAME = "lucky_rclone-sFF3mpk8.js"
RCLONE_CHUNK_SHA256 = "4365a2c1a90971e77d2ec96b3a412a98246e5997c15e0dfd1932e6359013f773"


def choose_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def api(
    base_url: str,
    admin_token: str,
    method: str,
    path: str,
    *,
    payload: Any | None = None,
    label: str,
) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        path,
        method=method,
        payload=payload,
        admin_token=admin_token,
    )
    return require_ret_zero(status, response, label)


def query_path(path: str, values: dict[str, Any]) -> str:
    return path + "?" + urllib.parse.urlencode(values)


def list_rows(response: dict[str, Any], label: str) -> list[dict[str, Any]]:
    rows = response.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError(f"{label} returned an invalid list")
    return list(rows)


def remote_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    return list_rows(api(base_url, token, "GET", "/api/rclone/remotelist", label="Rclone remote list"), "Rclone remote list")


def sync_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    return list_rows(api(base_url, token, "GET", "/api/rclone/sync/list", label="Rclone sync list"), "Rclone sync list")


def cron_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    return list_rows(api(base_url, token, "GET", "/api/cron/list", label="Cron list"), "Cron list")


def cron_group_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    return list_rows(api(base_url, token, "GET", "/api/cron/groups", label="Cron groups"), "Cron groups")


def key_of(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_by_remark(rows: list[dict[str, Any]], remark: str) -> dict[str, Any] | None:
    return next((row for row in rows if str(row.get("Remark") or "") == remark), None)


def find_cron(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((row for row in rows if str(row.get("Name") or "") == name), None)


def global_config(base_url: str, token: str) -> dict[str, Any]:
    response = api(base_url, token, "GET", "/api/rclone/globalconfig", label="Rclone global config")
    value = response.get("globalConfig")
    if not isinstance(value, dict):
        raise ProbeError("Rclone global config missing globalConfig object")
    return copy.deepcopy(value)


def put_global_config(base_url: str, token: str, value: dict[str, Any]) -> None:
    api(
        base_url,
        token,
        "PUT",
        "/api/rclone/globalconfig",
        payload=value,
        label="write Rclone global config",
    )


def path_entries(base_url: str, token: str, path: str) -> list[dict[str, Any]]:
    response = api(
        base_url,
        token,
        "GET",
        query_path("/api/local-path-browser/list", {"path": path, "showFiles": "true"}),
        label="local path list",
    )
    data = response.get("data")
    rows = data.get("entries") if isinstance(data, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("local path browser returned invalid entries")
    return list(rows)


def path_has(base_url: str, token: str, parent: str, name: str) -> bool:
    target = parent.rstrip("/") + "/" + name
    return any(str(row.get("path") or "") == target for row in path_entries(base_url, token, parent))


def mkdir(base_url: str, token: str, path: str) -> None:
    api(
        base_url,
        token,
        "POST",
        "/api/local-path-browser/mkdir",
        payload={"path": path},
        label="create TEST directory",
    )


def delete_path(base_url: str, token: str, path: str) -> bool:
    name = path.rstrip("/").rsplit("/", 1)[-1]
    try:
        api(
            base_url,
            token,
            "DELETE",
            "/api/local-path-browser/path",
            payload={"path": path, "confirmName": name},
            label="delete TEST path",
        )
    except Exception:
        return False
    return not path_has(base_url, token, "/tmp", name)


def cron_payload(name: str, group_key: str, script: str) -> dict[str, Any]:
    return {
        "Key": "",
        "Name": name,
        "Enable": True,
        "OtherKey": "",
        "Type": 8,
        "TypeParams": "",
        "GroupKey": group_key,
        "ExecSecond": 0,
        "ExecMinute": 0,
        "ExecHour": 0,
        "Jobs": [
            {
                "Type": "shell_option",
                "Options": {"shell_content": script},
                "Remark": "TEST Rclone SystemMount helper",
            }
        ],
        "Parallel": False,
        "IOT_DianDeng_Enable": False,
        "IOT_DianDeng_AUTHKEY": "",
        "IOT_DianDeng_InsecureSkipVerify": False,
        "IOT_DianDengVoiceAssistantTriggerCondition": "ignore",
        "IOT_DianDengBindComponentEnable": False,
        "IOT_DianDengBindComponentTriggerCondition": "tap",
        "IOT_DianDengBindComponent": "",
        "IOT_DianDengBindComponentState": "",
        "IOT_DianDengBindComponentType": "btn",
        "IOT_Bemfa_Enable": False,
        "IOT_Bemfa_SecretKey": "",
        "IOT_Bemfa_Topic": "",
        "IOT_BemfaVoiceAssistantTriggerCondition": "on",
        "IOT_Bemfa_InsecureSkipVerify": False,
    }


def wait_for_row(getter: Any, matcher: Any, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = matcher(getter())
        if isinstance(row, dict) and key_of(row):
            return row
        time.sleep(0.25)
    raise ProbeError("TEST object did not appear")


def remote_detail(base_url: str, token: str, key: str) -> dict[str, Any]:
    response = api(base_url, token, "GET", f"/api/rclone/remote/{key}", label="Rclone remote detail")
    remote = response.get("remote")
    if not isinstance(remote, dict):
        raise ProbeError("Rclone remote detail missing remote object")
    return remote


def frontend_mount_snippets(base_url: str) -> dict[str, str]:
    """Extract public Lucky 3.0.0 Rclone UI context for mount field semantics."""

    snippets: dict[str, str] = {}
    asset_attempts: dict[str, Any] = {}
    for candidate_path in (
        f"/static/js/{RCLONE_CHUNK_NAME}",
        f"/static/{RCLONE_CHUNK_NAME}",
        f"/assets/{RCLONE_CHUNK_NAME}",
        f"/js/{RCLONE_CHUNK_NAME}",
        f"/{RCLONE_CHUNK_NAME}",
        f"/lucky/static/js/{RCLONE_CHUNK_NAME}",
    ):
        request = urllib.request.Request(
            base_url + candidate_path,
            headers={"User-Agent": "lucky-skills-rclone-mount-ci-inspector/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read(16 * 1024 * 1024)
                status = int(response.status)
        except urllib.error.HTTPError as error:
            asset_attempts[candidate_path] = {"status": int(error.code)}
            continue
        except Exception as error:  # noqa: BLE001 - failure diagnostic only
            asset_attempts[candidate_path] = {"error": type(error).__name__}
            continue
        digest = hashlib.sha256(raw).hexdigest()
        asset_attempts[candidate_path] = {
            "status": status,
            "bytes": len(raw),
            "sha256": digest,
            "expected_hash": digest == RCLONE_CHUNK_SHA256,
        }
        text = raw.decode("utf-8", errors="replace")
        for needle in ("MountType", "OnleyCreateVFS", "MountPoint", "SystemMount", "AllowOther"):
            positions = [match.start() for match in re.finditer(needle, text)]
            if not positions:
                continue
            chunks = []
            for position in positions[:6]:
                start = max(0, position - 1400)
                end = min(len(text), position + 2400)
                chunks.append(" ".join(text[start:end].split()))
            snippets[f"{candidate_path}:{needle}"] = " || ".join(chunks)[:14000]
        if digest == RCLONE_CHUNK_SHA256:
            break
    snippets["_asset_attempts"] = json.dumps(asset_attempts, sort_keys=True)

    origin = urllib.parse.urlsplit(base_url)
    # The static endpoint inventory records the 3.0.0 chunk basename.  The
    # live admin UI serves chunks below /static/js/, so probe it first and
    # retain the crawl fallback in case a future pinned artifact changes the
    # chunk hash.
    queue = [f"/static/js/{RCLONE_CHUNK_NAME}", "/"]
    seen: set[str] = set()
    fetched = 0
    max_bytes = 24 * 1024 * 1024
    needles = ("MountType", "OnleyCreateVFS", "MountPoint", "SystemMount", "AllowOther")
    while queue and len(seen) < 120 and fetched < max_bytes:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        request = urllib.request.Request(
            base_url + path,
            headers={"User-Agent": "lucky-skills-rclone-mount-ci-inspector/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read(min(4 * 1024 * 1024, max_bytes - fetched))
        except Exception:  # noqa: BLE001 - best-effort failure diagnostic
            continue
        fetched += len(raw)
        text = raw.decode("utf-8", errors="replace")
        for needle in needles:
            positions = [match.start() for match in re.finditer(needle, text)]
            if not positions:
                continue
            chunks = []
            for position in positions[:4]:
                start = max(0, position - 1000)
                end = min(len(text), position + 1800)
                chunks.append(" ".join(text[start:end].split()))
            snippets[f"{path}:{needle}"] = " || ".join(chunks)[:9000]

        candidates = set(
            re.findall(r"(?:src=|href=)?[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", text)
        )
        candidates.update(re.findall(r"(?:\.\/)?(assets/[A-Za-z0-9_./-]+\.js)", text))
        candidates.update(
            re.findall(r"(?:/)?(static/js/lucky_rclone-[A-Za-z0-9_.-]+\.js)", text)
        )
        for candidate in candidates:
            resolved = urllib.parse.urljoin(base_url + path, candidate)
            parsed = urllib.parse.urlsplit(resolved)
            if parsed.scheme != origin.scheme or parsed.netloc != origin.netloc:
                continue
            candidate_path = parsed.path
            if candidate_path.endswith(".js") and candidate_path not in seen:
                if "lucky_rclone-" in candidate_path:
                    queue.insert(0, candidate_path)
                else:
                    queue.append(candidate_path)
    if not snippets:
        snippets["crawl"] = f"no mount markers found; files={len(seen)} bytes={fetched}"
    return snippets


def wait_mount_ready(
    base_url: str,
    token: str,
    remote_key: str,
    mount_path: str,
    marker_name: str,
    timeout: float = 30.0,
) -> tuple[bool, str, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    last_msg = ""
    diagnostic: dict[str, Any] = {}
    while time.monotonic() < deadline:
        detail = remote_detail(base_url, token, remote_key)
        last_msg = str(detail.get("MountMsg") or "")
        system_mount = detail.get("SystemMount")
        if not isinstance(system_mount, dict):
            system_mount = {}
        diagnostic = {
            "remote_enable": detail.get("Enable"),
            "remote_type": detail.get("Type"),
            "remote_fields": sorted(str(key) for key in detail),
            "params_fields": sorted(str(key) for key in detail.get("Params", {}))
            if isinstance(detail.get("Params"), dict)
            else [],
            "system_mount": {
                key: system_mount.get(key)
                for key in ("Enable", "ReadOnly", "MountType", "OnleyCreateVFS")
                if key in system_mount
            },
            "system_mount_fields": sorted(str(key) for key in system_mount),
            "mount_point_present": bool(system_mount.get("MountPoint")),
        }
        try:
            if path_has(base_url, token, mount_path, marker_name):
                return True, last_msg, diagnostic
        except Exception:
            pass
        time.sleep(0.5)
    return False, last_msg, diagnostic


def wait_unmounted(base_url: str, token: str, mount_path: str, marker_name: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if not path_has(base_url, token, mount_path, marker_name):
                return True
        except Exception:
            return True
        time.sleep(0.5)
    return False


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if not Path("/dev/fuse").exists():
        raise ProbeError("GitHub-hosted runner has no /dev/fuse")

    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-rclone-mount-{nonce}"
    host_port = choose_loopback_port()
    root = f"/tmp/{TEST_PREFIX}{nonce}"
    source = root + "/source"
    mount_path = root + "/mount"
    cache_path = root + "/cache"
    upload_path = root + "/upload"
    source_marker = f"source-{nonce}.txt"
    writeback_marker = f"writeback-{nonce}.txt"
    marker_value = secrets.token_hex(16)
    remark = TEST_PREFIX + nonce
    cron_group_name = TEST_PREFIX + "group-" + nonce
    cron_task_name = TEST_PREFIX + "task-" + nonce

    report: dict[str, Any] = {
        "lucky_version": "",
        "runner_fuse_present": True,
        "container_sys_admin": False,
        "container_fuse_device": False,
        "baseline_remote_empty": False,
        "baseline_sync_empty": False,
        "baseline_cron_empty": False,
        "baseline_cron_groups_empty": False,
        "global_config_restored": False,
        "remote_created": False,
        "mount_visible": False,
        "mount_msg_empty": False,
        "write_through": False,
        "remote_disabled": False,
        "unmounted": False,
        "remote_deleted": False,
        "path_removed": False,
        "remote_baseline_restored": False,
        "sync_baseline_restored": False,
        "cron_baseline_restored": False,
        "cron_group_baseline_restored": False,
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-rclone-mount-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        conf_dir.mkdir()
        base_url = f"http://127.0.0.1:{host_port}"
        token = ""
        admin_token = ""
        baseline_global: dict[str, Any] | None = None
        remote_key = ""
        cron_group_key = ""
        cron_task_key = ""
        helper: dict[str, Any] | None = None
        try:
            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--cap-add",
                "SYS_ADMIN",
                "--device",
                "/dev/fuse:/dev/fuse",
                "--security-opt",
                "apparmor=unconfined",
                "-p",
                f"127.0.0.1:{host_port}:{ADMIN_PORT}",
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            inspect = json.loads(docker("inspect", container_name, timeout=30))[0]
            host_config = inspect.get("HostConfig") if isinstance(inspect, dict) else {}
            cap_add = host_config.get("CapAdd") if isinstance(host_config, dict) else []
            devices = host_config.get("Devices") if isinstance(host_config, dict) else []
            report["container_sys_admin"] = isinstance(cap_add, list) and "SYS_ADMIN" in cap_add
            report["container_fuse_device"] = isinstance(devices, list) and any(
                isinstance(device, dict) and device.get("PathInContainer") == "/dev/fuse"
                for device in devices
            )

            wait_for_lucky(base_url, container_name)
            admin_token = login_default_admin(base_url, tmp)
            # This disposable CI instance uses its in-memory administrator
            # session token for the API calls below.  There is no need to
            # mutate global OpenToken configuration merely to exercise
            # SystemMount, and every Lucky operation still goes through HTTP
            # APIs rather than container-side config edits.
            token = admin_token

            info = api(base_url, token, "GET", "/api/info", label="Lucky info")
            info_obj = info.get("info")
            report["lucky_version"] = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            if report["lucky_version"] != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {report['lucky_version']!r}")

            baseline_remotes = remote_rows(base_url, token)
            baseline_sync = sync_rows(base_url, token)
            baseline_cron = cron_rows(base_url, token)
            baseline_groups = cron_group_rows(base_url, token)
            report["baseline_remote_empty"] = not baseline_remotes
            report["baseline_sync_empty"] = not baseline_sync
            report["baseline_cron_empty"] = not baseline_cron
            report["baseline_cron_groups_empty"] = not baseline_groups
            if not all(
                (
                    report["baseline_remote_empty"],
                    report["baseline_sync_empty"],
                    report["baseline_cron_empty"],
                    report["baseline_cron_groups_empty"],
                )
            ):
                raise ProbeError("fresh Lucky Rclone/Cron baseline was not empty")
            baseline_global = global_config(base_url, token)

            for path in (root, source, mount_path, cache_path, upload_path):
                mkdir(base_url, token, path)

            updated_global = copy.deepcopy(baseline_global)
            updated_global["DefaultCaCheDir"] = cache_path
            updated_global["UploadFileTmpDir"] = upload_path
            put_global_config(base_url, token, updated_global)

            api(
                base_url,
                token,
                "POST",
                "/api/cron/groups",
                payload={"Name": cron_group_name},
                label="create Cron helper group",
            )
            group = wait_for_row(
                lambda: cron_group_rows(base_url, token),
                lambda rows: find_cron(rows, cron_group_name),
            )
            cron_group_key = key_of(group)
            helper = cron_payload(
                cron_task_name,
                cron_group_key,
                f"printf '%s' '{marker_value}' > '{source}/{source_marker}'",
            )
            api(
                base_url,
                token,
                "POST",
                "/api/cron/list",
                payload=helper,
                label="create Cron helper task",
            )
            task = wait_for_row(
                lambda: cron_rows(base_url, token),
                lambda rows: find_cron(rows, cron_task_name),
            )
            cron_task_key = key_of(task)
            api(
                base_url,
                token,
                "GET",
                query_path("/api/cron/dojobs", {"key": cron_task_key}),
                label="create source marker",
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not path_has(base_url, token, source, source_marker):
                time.sleep(0.2)
            if not path_has(base_url, token, source, source_marker):
                raise ProbeError("Cron helper did not create source marker")

            remote_payload = {
                "Key": "",
                "Type": "local",
                "Enable": True,
                "Remark": remark,
                "Root": "",
                "Params": {"LocalPath": source},
                "HttpClienInsecureSkipVerify": False,
                "HttpClientProxyType": "",
                "HttpClientProxyAddr": "",
                "HttpClientProxyUser": "",
                "HttpClientProxyPassword": "",
                "SystemMount": {
                    "Enable": True,
                    "ReadOnly": False,
                    "MountType": "network",
                    "MountPoint": mount_path,
                    "Label": "",
                    "OnleyCreateVFS": False,
                },
            }
            created = api(
                base_url,
                token,
                "POST",
                "/api/rclone/remotelist",
                payload=remote_payload,
                label="create mounted local Rclone remote",
            )
            report["remote_created"] = created.get("ret") == 0
            remote = wait_for_row(
                lambda: remote_rows(base_url, token),
                lambda rows: find_by_remark(rows, remark),
            )
            remote_key = key_of(remote)
            mounted, mount_msg, mount_diagnostic = wait_mount_ready(
                base_url,
                token,
                remote_key,
                mount_path,
                source_marker,
            )
            report["mount_visible"] = mounted
            report["mount_msg_empty"] = not mount_msg
            if not mounted:
                frontend_diagnostic = frontend_mount_snippets(base_url)
                raise ProbeError(
                    "Rclone SystemMount did not become visible; "
                    f"MountMsg={mount_msg[:240]!r}; "
                    f"readback={json.dumps(mount_diagnostic, ensure_ascii=False, sort_keys=True)}; "
                    f"frontend={json.dumps(frontend_diagnostic, ensure_ascii=False, sort_keys=True)[:18000]}"
                )

            if helper is None:
                raise ProbeError("Cron helper payload missing")
            writeback = copy.deepcopy(helper)
            writeback["Key"] = cron_task_key
            writeback["Jobs"][0]["Options"]["shell_content"] = (
                f"printf '%s' '{marker_value}' > '{mount_path}/{writeback_marker}'"
            )
            api(
                base_url,
                token,
                "PUT",
                "/api/cron/list",
                payload=writeback,
                label="update Cron helper for mount write-through",
            )
            api(
                base_url,
                token,
                "GET",
                query_path("/api/cron/dojobs", {"key": cron_task_key}),
                label="write through mounted Rclone path",
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not path_has(base_url, token, source, writeback_marker):
                time.sleep(0.2)
            report["write_through"] = path_has(base_url, token, source, writeback_marker)
            if not report["write_through"]:
                raise ProbeError("write through SystemMount did not appear in source")

            disabled = api(
                base_url,
                token,
                "GET",
                query_path("/api/rclone/remotelist/option", {"key": remote_key, "enable": "false"}),
                label="disable mounted Rclone remote",
            )
            report["remote_disabled"] = disabled.get("ret") == 0
            report["unmounted"] = wait_unmounted(base_url, token, mount_path, source_marker)
            if not report["unmounted"]:
                raise ProbeError("Rclone SystemMount remained visible after disable")

            deleted = api(
                base_url,
                token,
                "DELETE",
                query_path("/api/rclone/remotelist", {"key": remote_key}),
                label="delete mounted Rclone remote",
            )
            report["remote_deleted"] = deleted.get("ret") == 0
            remote_key = ""

            api(
                base_url,
                token,
                "GET",
                query_path("/api/cron/enable", {"enable": "false", "key": cron_task_key}),
                label="disable Cron helper",
            )
            api(
                base_url,
                token,
                "DELETE",
                query_path("/api/cron/list", {"key": cron_task_key}),
                label="delete Cron helper",
            )
            cron_task_key = ""
            api(
                base_url,
                token,
                "DELETE",
                query_path("/api/cron/groups", {"key": cron_group_key}),
                label="delete Cron helper group",
            )
            cron_group_key = ""
            put_global_config(base_url, token, baseline_global)
            report["global_config_restored"] = global_config(base_url, token) == baseline_global
            report["path_removed"] = delete_path(base_url, token, root)
        finally:
            if token:
                if remote_key:
                    try:
                        api(
                            base_url,
                            token,
                            "GET",
                            query_path("/api/rclone/remotelist/option", {"key": remote_key, "enable": "false"}),
                            label="cleanup disable Rclone remote",
                        )
                    except Exception:
                        pass
                    try:
                        api(
                            base_url,
                            token,
                            "DELETE",
                            query_path("/api/rclone/remotelist", {"key": remote_key}),
                            label="cleanup delete Rclone remote",
                        )
                    except Exception:
                        pass
                if cron_task_key:
                    try:
                        api(
                            base_url,
                            token,
                            "GET",
                            query_path("/api/cron/enable", {"enable": "false", "key": cron_task_key}),
                            label="cleanup disable Cron helper",
                        )
                    except Exception:
                        pass
                    try:
                        api(
                            base_url,
                            token,
                            "DELETE",
                            query_path("/api/cron/list", {"key": cron_task_key}),
                            label="cleanup delete Cron helper",
                        )
                    except Exception:
                        pass
                if cron_group_key:
                    try:
                        api(
                            base_url,
                            token,
                            "DELETE",
                            query_path("/api/cron/groups", {"key": cron_group_key}),
                            label="cleanup delete Cron helper group",
                        )
                    except Exception:
                        pass
                if baseline_global is not None:
                    try:
                        current_global = global_config(base_url, token)
                        if (
                            current_global == baseline_global
                            or str(current_global.get("DefaultCaCheDir") or "").startswith(root)
                            or str(current_global.get("UploadFileTmpDir") or "").startswith(root)
                        ):
                            put_global_config(base_url, token, baseline_global)
                    except Exception:
                        pass
                try:
                    delete_path(base_url, token, root)
                except Exception:
                    pass
                try:
                    report["remote_baseline_restored"] = not remote_rows(base_url, token)
                    report["sync_baseline_restored"] = not sync_rows(base_url, token)
                    report["cron_baseline_restored"] = not cron_rows(base_url, token)
                    report["cron_group_baseline_restored"] = not cron_group_rows(base_url, token)
                    if baseline_global is not None:
                        report["global_config_restored"] = global_config(base_url, token) == baseline_global
                    report["path_removed"] = not path_has(
                        base_url, token, "/tmp", root.rsplit("/", 1)[-1]
                    )
                except Exception:
                    pass
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "runner_fuse_present",
        "container_sys_admin",
        "container_fuse_device",
        "baseline_remote_empty",
        "baseline_sync_empty",
        "baseline_cron_empty",
        "baseline_cron_groups_empty",
        "remote_created",
        "mount_visible",
        "mount_msg_empty",
        "write_through",
        "remote_disabled",
        "unmounted",
        "remote_deleted",
        "global_config_restored",
        "path_removed",
        "remote_baseline_restored",
        "sync_baseline_restored",
        "cron_baseline_restored",
        "cron_group_baseline_restored",
    )
    report["failed"] = [name for name in required_true if report.get(name) is not True]
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2), file=sys.stderr)
        raise SystemExit(2)
