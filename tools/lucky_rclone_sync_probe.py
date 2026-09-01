#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Rclone local-to-local sync behavior.

The probe creates only Lucky-visible /tmp TEST directories, one Rclone sync
task, and one short-lived Cron helper task/group. The helper writes a random
marker file only inside the owned source tree. A real non-dry-run sync must
copy that file byte-for-byte and propagate an empty directory. The helper is
then reused once to verify source/destination contents and is deleted before a
DryRun=true pass checks that a second source-only directory/file is not created
on the destination. No remote credentials, system mounts, network listeners,
or business Rclone/Cron objects are used.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import sys
import time
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


CONFIRMATION = "PROBE-AND-CLEAN-RCLONE-SYNC"
TEST_PREFIX = "TEST-lucky-skills-rclone-sync-"


def credentials() -> tuple[str, str]:
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return base_url, token
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return values["base_url"], values["open_token"]


def make_client() -> LuckyClient:
    base_url, token = credentials()
    return LuckyClient(
        base_url,
        token,
        catalog=RouteCatalog.load_default(),
        retries=0,
        timeout=20,
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    body: Any = None,
    body_supplied: bool = False,
    attempts: int = 5,
) -> dict[str, Any]:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {"allow_unsafe": True}
        if query is not None:
            kwargs["query"] = query
        if body_supplied:
            kwargs["json_body"] = body
        try:
            value = client.request_json(method, path, **kwargs)
            if not isinstance(value, dict):
                raise RuntimeError(f"unexpected Lucky response for {method} {path}")
            return value
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(4.0 + attempt * 2.0)
    raise AssertionError("unreachable")


def sync_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/rclone/sync/list")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Rclone sync list type")
    return [row for row in rows if isinstance(row, dict)]


def task_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_task(client: LuckyClient, remark: str) -> dict[str, Any] | None:
    return next(
        (row for row in sync_rows(client) if str(row.get("Remark") or "") == remark),
        None,
    )


def wait_task(client: LuckyClient, remark: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_task(client, remark)
        if row is not None and task_key(row):
            return row
        time.sleep(0.3)
    raise RuntimeError("TEST Rclone sync task did not appear")


def task_detail(client: LuckyClient, key: str) -> dict[str, Any]:
    value = client.request_json("GET", f"/api/rclone/sync/{key}")
    task = value.get("task") if isinstance(value, dict) else None
    if not isinstance(task, dict):
        raise RuntimeError("unexpected Rclone sync task detail response")
    return task


def task_status(row: dict[str, Any]) -> str:
    state = row.get("State")
    if isinstance(state, dict):
        return str(state.get("Status") or "")
    return ""


def wait_run_finished(
    client: LuckyClient,
    remark: str,
    *,
    timeout: float = 40.0,
) -> tuple[dict[str, Any], bool]:
    deadline = time.monotonic() + timeout
    saw_running = False
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        row = find_task(client, remark)
        if row is None:
            time.sleep(0.25)
            continue
        latest = row
        status = task_status(row)
        if status == "running":
            saw_running = True
        if status in {"success", "failed"}:
            return row, saw_running
        time.sleep(0.25)
    return latest, saw_running


def cron_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/cron/list")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Cron task list type")
    return [row for row in rows if isinstance(row, dict)]


def cron_group_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/cron/groups")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Cron group list type")
    return [row for row in rows if isinstance(row, dict)]


def cron_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_cron_task(client: LuckyClient, name: str) -> dict[str, Any] | None:
    return next(
        (row for row in cron_rows(client) if str(row.get("Name") or "") == name),
        None,
    )


def find_cron_group(client: LuckyClient, name: str) -> dict[str, Any] | None:
    return next(
        (row for row in cron_group_rows(client) if str(row.get("Name") or "") == name),
        None,
    )


def wait_cron_task(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_cron_task(client, name)
        if row is not None and cron_key(row):
            return row
        time.sleep(0.25)
    raise RuntimeError("TEST Cron helper task did not appear")


def wait_cron_group(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_cron_group(client, name)
        if row is not None and cron_key(row):
            return row
        time.sleep(0.25)
    raise RuntimeError("TEST Cron helper group did not appear")


def cron_task_payload(name: str, group_key: str, script: str) -> dict[str, Any]:
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
                "Remark": "TEST Rclone file helper",
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


def remove_test_cron_tasks(client: LuckyClient) -> int:
    removed = 0
    for row in cron_rows(client):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = cron_key(row)
        if not key:
            continue
        try:
            mutate(client, "GET", "/api/cron/enable", query={"enable": "false", "key": key})
        except Exception:
            pass
        try:
            mutate(client, "DELETE", "/api/cron/list", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def remove_test_cron_groups(client: LuckyClient) -> int:
    removed = 0
    for row in cron_group_rows(client):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = cron_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/cron/groups", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def path_entries(client: LuckyClient, path: str) -> list[dict[str, Any]]:
    value = client.request_json(
        "GET",
        "/api/local-path-browser/list",
        query={"path": path, "showFiles": "true"},
    )
    data = value.get("data") if isinstance(value, dict) else None
    rows = data.get("entries") if isinstance(data, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected local path listing")
    return [row for row in rows if isinstance(row, dict)]


def path_exists(client: LuckyClient, parent: str, name: str) -> bool:
    target = parent.rstrip("/") + "/" + name
    return any(str(row.get("path") or "") == target for row in path_entries(client, parent))


def mkdir(client: LuckyClient, path: str) -> None:
    mutate(
        client,
        "POST",
        "/api/local-path-browser/mkdir",
        body={"path": path},
        body_supplied=True,
    )


def delete_path(client: LuckyClient, path: str) -> bool:
    name = path.rstrip("/").rsplit("/", 1)[-1]
    try:
        mutate(
            client,
            "DELETE",
            "/api/local-path-browser/path",
            body={"path": path, "confirmName": name},
            body_supplied=True,
        )
    except Exception:
        return False
    return all(str(row.get("path") or "") != path for row in path_entries(client, "/tmp"))


def remove_test_tasks(client: LuckyClient) -> int:
    removed = 0
    for row in sync_rows(client):
        if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
            continue
        key = task_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/rclone/sync/list", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline_rows = sync_rows(client)
    baseline_keys = {task_key(row) for row in baseline_rows if task_key(row)}
    baseline_cron_task_keys = {cron_key(row) for row in cron_rows(client) if cron_key(row)}
    baseline_cron_group_keys = {
        cron_key(row) for row in cron_group_rows(client) if cron_key(row)
    }
    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in baseline_rows):
        raise RuntimeError("pre-existing TEST Rclone sync task found")
    if any(str(row.get("Name") or "").startswith(TEST_PREFIX) for row in cron_rows(client)):
        raise RuntimeError("pre-existing TEST Cron helper task found")
    if any(
        str(row.get("Name") or "").startswith(TEST_PREFIX)
        for row in cron_group_rows(client)
    ):
        raise RuntimeError("pre-existing TEST Cron helper group found")

    nonce = secrets.token_hex(5)
    remark = TEST_PREFIX + nonce
    src = f"/tmp/{TEST_PREFIX}src-{nonce}"
    dst = f"/tmp/{TEST_PREFIX}dst-{nonce}"
    real_child = "real-empty-dir"
    dry_child = "dryrun-empty-dir"
    source_file = f"copy-{nonce}.txt"
    verify_marker = f"copy-verified-{nonce}.ok"
    file_marker = secrets.token_hex(16)
    cron_group_name = f"{TEST_PREFIX}helper-group-{nonce}"
    cron_task_name = f"{TEST_PREFIX}helper-task-{nonce}"

    task = {
        "Key": "",
        "Enable": True,
        "Remark": remark,
        "SourceType": "local",
        "SourceRemoteKey": "",
        "SourcePath": src,
        "DestType": "local",
        "DestRemoteKey": "",
        "DestPath": dst,
        "SyncMode": "sync",
        "DeleteOnDest": False,
        "DryRun": False,
        "CreateEmptyDirs": True,
        "IgnoreExisting": False,
        "IgnoreErrors": False,
        "CheckFirst": False,
        "Transfers": 4,
        "Checkers": 8,
        "BandwidthLimit": "",
        "MinAge": "",
        "MaxAge": "",
        "MinSize": "",
        "MaxSize": "",
        "IncludePatterns": "",
        "ExcludePatterns": "",
        "ExtraArgs": "",
        "ScheduleEnable": False,
        "ScheduleCron": "",
        "ScheduleInterval": 0,
        "BisyncResync": False,
        "BisyncCheckAccess": False,
        "BisyncForce": False,
    }

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    key = ""
    cron_group_key = ""
    cron_task_key = ""
    helper_payload: dict[str, Any] | None = None

    try:
        mkdir(client, src)
        mkdir(client, dst)
        mkdir(client, src + "/" + real_child)
        results["test_paths_created"] = (
            path_exists(client, "/tmp", src.rsplit("/", 1)[-1])
            and path_exists(client, "/tmp", dst.rsplit("/", 1)[-1])
            and path_exists(client, src, real_child)
        )

        created_group = mutate(
            client,
            "POST",
            "/api/cron/groups",
            body={"Name": cron_group_name},
            body_supplied=True,
        )
        results["cron_helper_group_created"] = created_group.get("ret") == 0
        cron_group_key = cron_key(wait_cron_group(client, cron_group_name))
        write_script = f"printf '%s' '{file_marker}' > '{src}/{source_file}'"
        helper_payload = cron_task_payload(cron_task_name, cron_group_key, write_script)
        created_helper = mutate(
            client,
            "POST",
            "/api/cron/list",
            body=helper_payload,
            body_supplied=True,
        )
        results["cron_helper_task_created"] = created_helper.get("ret") == 0
        cron_task_key = cron_key(wait_cron_task(client, cron_task_name))
        helper_trigger = mutate(
            client,
            "GET",
            "/api/cron/dojobs",
            query={"key": cron_task_key},
        )
        results["source_file_helper_triggered"] = helper_trigger.get("ret") == 0
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not path_exists(client, src, source_file):
            time.sleep(0.2)
        results["source_file_created"] = path_exists(client, src, source_file)

        created = mutate(
            client,
            "POST",
            "/api/rclone/sync/list",
            body=task,
            body_supplied=True,
        )
        results["task_created"] = created.get("ret") == 0
        row = wait_task(client, remark)
        key = task_key(row)
        detail = task_detail(client, key)
        results["task_readback"] = (
            bool(key)
            and detail.get("SourceType") == "local"
            and detail.get("DestType") == "local"
            and detail.get("SyncMode") == "sync"
            and detail.get("DryRun") is False
            and detail.get("CreateEmptyDirs") is True
        )
        observations["task_fields"] = sorted(row.keys())
        observations["task_detail_fields"] = sorted(detail.keys())

        started = mutate(
            client,
            "POST",
            f"/api/rclone/sync/run/{key}",
            query={"resync": "false"},
        )
        results["real_run_started"] = started.get("ret") == 0
        finished, saw_running = wait_run_finished(client, remark)
        observations["real_run_status"] = task_status(finished)
        observations["real_run_saw_running"] = saw_running
        state = finished.get("State") if isinstance(finished.get("State"), dict) else {}
        observations["real_run_state_fields"] = sorted(state.keys()) if isinstance(state, dict) else []
        results["real_run_success"] = task_status(finished) == "success"
        results["real_empty_dir_synced"] = path_exists(client, dst, real_child)
        results["real_file_copied"] = path_exists(client, dst, source_file)

        if helper_payload is None:
            raise RuntimeError("Cron helper payload was not initialized")
        verify_payload = copy.deepcopy(helper_payload)
        verify_payload["Key"] = cron_task_key
        verify_payload["Jobs"][0]["Options"]["shell_content"] = (
            f"test \"$(cat '{src}/{source_file}')\" = '{file_marker}' "
            f"&& test \"$(cat '{dst}/{source_file}')\" = '{file_marker}' "
            f"&& : > '{src}/{verify_marker}'"
        )
        helper_put = mutate(
            client,
            "PUT",
            "/api/cron/list",
            body=verify_payload,
            body_supplied=True,
        )
        results["cron_helper_verify_put"] = helper_put.get("ret") == 0
        verify_trigger = mutate(
            client,
            "GET",
            "/api/cron/dojobs",
            query={"key": cron_task_key},
        )
        results["copy_content_verify_triggered"] = verify_trigger.get("ret") == 0
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not path_exists(client, src, verify_marker):
            time.sleep(0.2)
        results["copied_file_content_verified"] = path_exists(client, src, verify_marker)

        helper_disabled = mutate(
            client,
            "GET",
            "/api/cron/enable",
            query={"enable": "false", "key": cron_task_key},
        )
        results["cron_helper_disabled"] = helper_disabled.get("ret") == 0
        helper_deleted = mutate(
            client,
            "DELETE",
            "/api/cron/list",
            query={"key": cron_task_key},
        )
        results["cron_helper_task_deleted"] = helper_deleted.get("ret") == 0
        cron_task_key = ""
        group_deleted = mutate(
            client,
            "DELETE",
            "/api/cron/groups",
            query={"key": cron_group_key},
        )
        results["cron_helper_group_deleted"] = group_deleted.get("ret") == 0
        cron_group_key = ""

        mkdir(client, src + "/" + dry_child)
        results["dryrun_source_dir_created"] = path_exists(client, src, dry_child)
        current = find_task(client, remark)
        if current is None:
            raise RuntimeError("TEST Rclone sync task disappeared before DryRun update")
        updated = copy.deepcopy(current)
        updated["DryRun"] = True
        put = mutate(
            client,
            "PUT",
            "/api/rclone/sync/list",
            body=updated,
            body_supplied=True,
        )
        results["dryrun_put_update"] = put.get("ret") == 0
        row = wait_task(client, remark)
        detail = task_detail(client, key)
        results["dryrun_readback"] = detail.get("DryRun") is True

        dry_started = mutate(
            client,
            "POST",
            f"/api/rclone/sync/run/{key}",
            query={"resync": "false"},
        )
        results["dryrun_started"] = dry_started.get("ret") == 0
        dry_finished, dry_saw_running = wait_run_finished(client, remark)
        observations["dryrun_status"] = task_status(dry_finished)
        observations["dryrun_saw_running"] = dry_saw_running
        results["dryrun_success"] = task_status(dry_finished) == "success"
        results["dryrun_did_not_create_dest"] = not path_exists(client, dst, dry_child)
        results["dryrun_did_not_copy_verify_marker"] = not path_exists(
            client, dst, verify_marker
        )

        logs = client.request_json(
            "GET", "/api/rclone/logs", query={"page": 1, "pageSize": 100}
        )
        log_rows = logs.get("logs") if isinstance(logs, dict) else None
        results["logs_read"] = isinstance(log_rows, list)
        observations["log_row_count"] = len(log_rows) if isinstance(log_rows, list) else 0

        deleted = mutate(client, "DELETE", "/api/rclone/sync/list", query={"key": key})
        results["task_deleted"] = deleted.get("ret") == 0
        results["task_absent_after_delete"] = all(task_key(item) != key for item in sync_rows(client))
        key = ""
    finally:
        cleanup["test_tasks_removed"] = remove_test_tasks(client)
        cleanup["test_cron_tasks_removed"] = remove_test_cron_tasks(client)
        cleanup["test_cron_groups_removed"] = remove_test_cron_groups(client)
        cleanup["src_removed"] = delete_path(client, src)
        cleanup["dst_removed"] = delete_path(client, dst)

    final_rows = sync_rows(client)
    cleanup["sync_key_baseline_restored"] = {
        task_key(row) for row in final_rows if task_key(row)
    } == baseline_keys
    final_cron_tasks = cron_rows(client)
    final_cron_groups = cron_group_rows(client)
    cleanup["cron_task_key_baseline_restored"] = {
        cron_key(row) for row in final_cron_tasks if cron_key(row)
    } == baseline_cron_task_keys
    cleanup["cron_group_key_baseline_restored"] = {
        cron_key(row) for row in final_cron_groups if cron_key(row)
    } == baseline_cron_group_keys
    cleanup["leftover_test_tasks"] = sum(
        1 for row in final_rows if str(row.get("Remark") or "").startswith(TEST_PREFIX)
    )
    cleanup["leftover_test_cron_tasks"] = sum(
        1
        for row in final_cron_tasks
        if str(row.get("Name") or "").startswith(TEST_PREFIX)
    )
    cleanup["leftover_test_cron_groups"] = sum(
        1
        for row in final_cron_groups
        if str(row.get("Name") or "").startswith(TEST_PREFIX)
    )

    failed = sorted(key_name for key_name, value in results.items() if not value)
    for key_name in (
        "src_removed",
        "dst_removed",
        "sync_key_baseline_restored",
        "cron_task_key_baseline_restored",
        "cron_group_key_baseline_restored",
    ):
        if not cleanup.get(key_name):
            failed.append(key_name)
    if cleanup.get("leftover_test_tasks") != 0:
        failed.append("leftover_test_tasks")
    if cleanup.get("leftover_test_cron_tasks") != 0:
        failed.append("leftover_test_cron_tasks")
    if cleanup.get("leftover_test_cron_groups") != 0:
        failed.append("leftover_test_cron_groups")

    print(
        json.dumps(
            {
                "target": "Lucky Rclone local-to-local file sync and DryRun behavior",
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
