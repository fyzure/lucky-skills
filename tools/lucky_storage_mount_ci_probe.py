#!/usr/bin/env python3
"""Verify Lucky 3.0.0 StorageManagement SystemMount in disposable CI.

This probe refuses to run outside GitHub Actions. It starts the repository's
pinned Lucky 3.0.0 image with only the FUSE requirements inside a disposable
container. Every Lucky configuration, path and helper operation still goes
through Lucky HTTP APIs.

The probe creates one owned local StorageManagement item, mounts that item's
local source path at a second owned TEST path, verifies source -> mount
visibility plus mount -> source write-through, disables the item and requires
the mount to disappear, then deletes the TEST item/helper/path and restores all
fresh-instance baselines. No production Lucky instance or business storage is
touched.
"""

from __future__ import annotations

import copy
import json
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from lucky_docker_build_ci_probe import (
    ADMIN_PORT,
    EXPECTED_LUCKY_VERSION,
    PINNED_LUCKY_IMAGE,
    ProbeError,
    cleanup_root_owned_conf,
    docker,
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    wait_for_lucky,
)
from lucky_rclone_mount_ci_probe import (
    api,
    choose_loopback_port,
    cron_group_rows,
    cron_payload,
    cron_rows,
    delete_path,
    find_cron,
    key_of,
    mkdir,
    path_has,
    query_path,
    wait_for_row,
)


TEST_PREFIX = "TEST-lucky-skills-storage-mount-ci-"


def storage_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    response = api(
        base_url,
        token,
        "GET",
        "/api/storagemanagement/list",
        label="StorageManagement list",
    )
    rows = response.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("StorageManagement list returned invalid rows")
    return list(rows)


def storage_lite_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    response = api(
        base_url,
        token,
        "GET",
        "/api/storagemanagement/litelist",
        label="StorageManagement lite list",
    )
    rows = response.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("StorageManagement lite list returned invalid rows")
    return list(rows)


def find_storage(rows: list[dict[str, Any]], remark: str) -> dict[str, Any] | None:
    return next((row for row in rows if str(row.get("Remark") or "") == remark), None)


def wait_mount_ready(
    base_url: str,
    token: str,
    remark: str,
    mount_path: str,
    marker_name: str,
    *,
    timeout: float,
) -> tuple[bool, str, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    last_msg = ""
    diagnostic: dict[str, Any] = {}
    while time.monotonic() < deadline:
        row = find_storage(storage_rows(base_url, token), remark)
        if row is not None:
            last_msg = str(row.get("MountMsg") or "")
            system_mount = row.get("SystemMount")
            if not isinstance(system_mount, dict):
                system_mount = {}
            params = row.get("Params")
            if not isinstance(params, dict):
                params = {}
            diagnostic = {
                "enable": row.get("Enable"),
                "type": row.get("Type"),
                "item_fields": sorted(str(key) for key in row),
                "params_fields": sorted(str(key) for key in params),
                "system_mount": {
                    key: system_mount.get(key)
                    for key in ("Enable", "MountType", "OnleyCreateVFS")
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
        time.sleep(0.4)
    return False, last_msg, diagnostic


def wait_unmounted(
    base_url: str,
    token: str,
    mount_path: str,
    marker_name: str,
    timeout: float = 20.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if not path_has(base_url, token, mount_path, marker_name):
                return True
        except Exception:
            return True
        time.sleep(0.4)
    return False


def storage_log_diagnostics(base_url: str, token: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for label, path in (
        ("lastlogs", "/api/storagemanagement/lastlogs"),
        ("logs", query_path("/api/storagemanagement/logs", {"page": 1, "pageSize": 50})),
    ):
        try:
            response = api(base_url, token, "GET", path, label=f"StorageManagement {label}")
            result[label] = json.dumps(response, ensure_ascii=False, sort_keys=True)[:12000]
        except Exception as error:  # noqa: BLE001 - failure diagnostics only
            result[label] = {"error": type(error).__name__, "message": str(error)[:500]}
    return result


def remove_test_storage(base_url: str, token: str) -> int:
    removed = 0
    for row in storage_rows(base_url, token):
        if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if not key:
            continue
        try:
            api(
                base_url,
                token,
                "GET",
                query_path("/api/storagemanagement/enable", {"key": key, "enable": "false"}),
                label="cleanup disable StorageManagement item",
            )
        except Exception:
            pass
        try:
            api(
                base_url,
                token,
                "DELETE",
                query_path("/api/storagemanagement/list", {"key": key}),
                label="cleanup delete StorageManagement item",
            )
            removed += 1
        except Exception:
            pass
    return removed


def remove_test_cron(base_url: str, token: str) -> tuple[int, int]:
    removed_tasks = 0
    removed_groups = 0
    for row in cron_rows(base_url, token):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if not key:
            continue
        try:
            api(
                base_url,
                token,
                "GET",
                query_path("/api/cron/enable", {"enable": "false", "key": key}),
                label="cleanup disable Cron helper",
            )
        except Exception:
            pass
        try:
            api(
                base_url,
                token,
                "DELETE",
                query_path("/api/cron/list", {"key": key}),
                label="cleanup delete Cron helper",
            )
            removed_tasks += 1
        except Exception:
            pass
    for row in cron_group_rows(base_url, token):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if not key:
            continue
        try:
            api(
                base_url,
                token,
                "DELETE",
                query_path("/api/cron/groups", {"key": key}),
                label="cleanup delete Cron helper group",
            )
            removed_groups += 1
        except Exception:
            pass
    return removed_tasks, removed_groups


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if not Path("/dev/fuse").exists():
        raise ProbeError("GitHub-hosted runner has no /dev/fuse")

    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-storage-mount-{nonce}"
    host_port = choose_loopback_port()
    root = f"/tmp/{TEST_PREFIX}{nonce}"
    source = root + "/source"
    mount_path = root + "/mount"
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
        "baseline_storage_empty": False,
        "baseline_lite_empty": False,
        "baseline_cron_empty": False,
        "baseline_cron_groups_empty": False,
        "storage_created": False,
        "mount_enable_retry_used": False,
        "mount_visible": False,
        "mount_msg_empty": False,
        "write_through": False,
        "storage_disabled": False,
        "unmounted": False,
        "storage_deleted": False,
        "path_removed": False,
        "storage_baseline_restored": False,
        "lite_baseline_restored": False,
        "cron_baseline_restored": False,
        "cron_group_baseline_restored": False,
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-storage-mount-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        conf_dir.mkdir()
        base_url = f"http://127.0.0.1:{host_port}"
        token = ""
        storage_key = ""
        cron_task_key = ""
        cron_group_key = ""
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
            normalized_caps = {
                str(cap).upper().removeprefix("CAP_")
                for cap in cap_add
            } if isinstance(cap_add, list) else set()
            report["container_sys_admin"] = "SYS_ADMIN" in normalized_caps
            report["container_fuse_device"] = isinstance(devices, list) and any(
                isinstance(device, dict) and device.get("PathInContainer") == "/dev/fuse"
                for device in devices
            )

            wait_for_lucky(base_url, container_name)
            token = login_default_admin(base_url, tmp)
            info = api(base_url, token, "GET", "/api/info", label="Lucky info")
            info_obj = info.get("info")
            report["lucky_version"] = (
                str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            )
            if report["lucky_version"] != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {report['lucky_version']!r}")

            baseline_storage = storage_rows(base_url, token)
            baseline_lite = storage_lite_rows(base_url, token)
            baseline_cron = cron_rows(base_url, token)
            baseline_groups = cron_group_rows(base_url, token)
            report["baseline_storage_empty"] = not baseline_storage
            report["baseline_lite_empty"] = not baseline_lite
            report["baseline_cron_empty"] = not baseline_cron
            report["baseline_cron_groups_empty"] = not baseline_groups
            if not all(
                report[name]
                for name in (
                    "baseline_storage_empty",
                    "baseline_lite_empty",
                    "baseline_cron_empty",
                    "baseline_cron_groups_empty",
                )
            ):
                raise ProbeError("fresh StorageManagement/Cron baseline was not empty")

            for path in (root, source, mount_path):
                mkdir(base_url, token, path)

            api(
                base_url,
                token,
                "POST",
                "/api/cron/groups",
                payload={"Name": cron_group_name},
                label="create Cron helper group",
            )
            cron_group = wait_for_row(
                lambda: cron_group_rows(base_url, token),
                lambda rows: find_cron(rows, cron_group_name),
            )
            cron_group_key = key_of(cron_group)
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
            cron_task = wait_for_row(
                lambda: cron_rows(base_url, token),
                lambda rows: find_cron(rows, cron_task_name),
            )
            cron_task_key = key_of(cron_task)
            api(
                base_url,
                token,
                "GET",
                query_path("/api/cron/dojobs", {"key": cron_task_key}),
                label="create source marker",
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not path_has(
                base_url, token, source, source_marker
            ):
                time.sleep(0.2)
            if not path_has(base_url, token, source, source_marker):
                raise ProbeError("Cron helper did not create source marker")

            candidate = {
                "Type": "local",
                "Enable": True,
                "Key": "",
                "Remark": remark,
                "Writable": True,
                "Log": True,
                "Params": {
                    "Proxy": "",
                    "ProxyAddr": "",
                    "ProxyUser": "",
                    "ProxyPasswd": "",
                    "LocalPath": source,
                },
                "SystemMount": {
                    "Enable": True,
                    "MountType": "local",
                    "MountPoint": mount_path,
                    "Label": "",
                    "OnleyCreateVFS": False,
                },
            }
            created = api(
                base_url,
                token,
                "POST",
                "/api/storagemanagement/list",
                payload=candidate,
                label="create mounted StorageManagement item",
            )
            report["storage_created"] = created.get("ret") == 0
            item = wait_for_row(
                lambda: storage_rows(base_url, token),
                lambda rows: find_storage(rows, remark),
            )
            storage_key = key_of(item)
            mounted, mount_msg, mount_diag = wait_mount_ready(
                base_url,
                token,
                remark,
                mount_path,
                source_marker,
                timeout=8,
            )
            if not mounted:
                report["mount_enable_retry_used"] = True
                api(
                    base_url,
                    token,
                    "GET",
                    query_path(
                        "/api/storagemanagement/enable",
                        {"key": storage_key, "enable": "false"},
                    ),
                    label="disable StorageManagement item before retry",
                )
                api(
                    base_url,
                    token,
                    "GET",
                    query_path(
                        "/api/storagemanagement/enable",
                        {"key": storage_key, "enable": "true"},
                    ),
                    label="re-enable StorageManagement item for mount retry",
                )
                mounted, mount_msg, mount_diag = wait_mount_ready(
                    base_url,
                    token,
                    remark,
                    mount_path,
                    source_marker,
                    timeout=25,
                )
            report["mount_visible"] = mounted
            report["mount_msg_empty"] = not mount_msg
            if not mounted:
                raise ProbeError(
                    "StorageManagement SystemMount did not become visible; "
                    f"MountMsg={mount_msg[:300]!r}; "
                    f"readback={json.dumps(mount_diag, ensure_ascii=False, sort_keys=True)}; "
                    f"logs={json.dumps(storage_log_diagnostics(base_url, token), ensure_ascii=False, sort_keys=True)[:16000]}"
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
                label="write through StorageManagement mount",
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not path_has(
                base_url, token, source, writeback_marker
            ):
                time.sleep(0.2)
            report["write_through"] = path_has(base_url, token, source, writeback_marker)
            if not report["write_through"]:
                raise ProbeError("StorageManagement mount write-through did not reach source")

            disabled = api(
                base_url,
                token,
                "GET",
                query_path(
                    "/api/storagemanagement/enable",
                    {"key": storage_key, "enable": "false"},
                ),
                label="disable mounted StorageManagement item",
            )
            report["storage_disabled"] = disabled.get("ret") == 0
            report["unmounted"] = wait_unmounted(
                base_url, token, mount_path, source_marker
            )
            if not report["unmounted"]:
                raise ProbeError("StorageManagement SystemMount remained after disable")

            deleted = api(
                base_url,
                token,
                "DELETE",
                query_path("/api/storagemanagement/list", {"key": storage_key}),
                label="delete mounted StorageManagement item",
            )
            report["storage_deleted"] = deleted.get("ret") == 0
            storage_key = ""

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
            report["path_removed"] = delete_path(base_url, token, root)
        finally:
            if token:
                remove_test_storage(base_url, token)
                remove_test_cron(base_url, token)
                if not report["path_removed"]:
                    report["path_removed"] = delete_path(base_url, token, root)

                report["storage_baseline_restored"] = not storage_rows(base_url, token)
                report["lite_baseline_restored"] = not storage_lite_rows(base_url, token)
                report["cron_baseline_restored"] = not cron_rows(base_url, token)
                report["cron_group_baseline_restored"] = not cron_group_rows(base_url, token)

            docker("rm", "-f", container_name, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "runner_fuse_present",
        "container_sys_admin",
        "container_fuse_device",
        "baseline_storage_empty",
        "baseline_lite_empty",
        "baseline_cron_empty",
        "baseline_cron_groups_empty",
        "storage_created",
        "mount_visible",
        "mount_msg_empty",
        "write_through",
        "storage_disabled",
        "unmounted",
        "storage_deleted",
        "path_removed",
        "storage_baseline_restored",
        "lite_baseline_restored",
        "cron_baseline_restored",
        "cron_group_baseline_restored",
    )
    failed = [name for name in required_true if report.get(name) is not True]
    report["failed"] = failed
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
