#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Rclone stop behavior on an owned local task.

The probe creates two unique Lucky-visible /tmp directories, uses one
short-lived manual-only Cron helper to write exactly 1 MiB of zeros into the
owned source tree, then creates one local-to-local Rclone sync task with
Transfers=1 and BandwidthLimit=32K. It waits until State.Status is running,
calls POST /api/rclone/sync/stop/{Key}, requires the task to leave running
state, and immediately cleans all TEST resources.

No remotes, credentials, schedules, system mounts, network listeners or
business Rclone/Cron objects are used. The intentionally small file plus rate
limit exists only to make the running state observable without manufacturing
a large workload.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from tools.lucky_rclone_sync_probe import (  # noqa: E402
    TEST_PREFIX,
    cron_group_rows,
    cron_key,
    cron_rows,
    cron_task_payload,
    delete_path,
    find_task,
    make_client,
    mkdir,
    mutate,
    path_exists,
    remove_test_cron_groups,
    remove_test_cron_tasks,
    remove_test_tasks,
    sync_rows,
    task_detail,
    task_key,
    task_status,
    wait_cron_group,
    wait_cron_task,
    wait_task,
)


CONFIRMATION = "PROBE-AND-CLEAN-RCLONE-STOP"


def run_probe() -> dict[str, Any]:
    client = make_client()
    baseline_sync_keys = {task_key(row) for row in sync_rows(client) if task_key(row)}
    baseline_cron_task_keys = {cron_key(row) for row in cron_rows(client) if cron_key(row)}
    baseline_cron_group_keys = {
        cron_key(row) for row in cron_group_rows(client) if cron_key(row)
    }

    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in sync_rows(client)):
        raise RuntimeError("pre-existing TEST Rclone task found")
    if any(str(row.get("Name") or "").startswith(TEST_PREFIX) for row in cron_rows(client)):
        raise RuntimeError("pre-existing TEST Cron helper task found")
    if any(
        str(row.get("Name") or "").startswith(TEST_PREFIX)
        for row in cron_group_rows(client)
    ):
        raise RuntimeError("pre-existing TEST Cron helper group found")

    nonce = secrets.token_hex(5)
    remark = f"{TEST_PREFIX}stop-{nonce}"
    src = f"/tmp/{TEST_PREFIX}stop-src-{nonce}"
    dst = f"/tmp/{TEST_PREFIX}stop-dst-{nonce}"
    filename = f"slow-{nonce}.bin"
    cron_group_name = f"{TEST_PREFIX}stop-helper-group-{nonce}"
    cron_task_name = f"{TEST_PREFIX}stop-helper-task-{nonce}"

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    sync_key = ""
    helper_task_key = ""
    helper_group_key = ""

    try:
        mkdir(client, src)
        mkdir(client, dst)
        results["paths_created"] = (
            path_exists(client, "/tmp", src.rsplit("/", 1)[-1])
            and path_exists(client, "/tmp", dst.rsplit("/", 1)[-1])
        )

        created_group = mutate(
            client,
            "POST",
            "/api/cron/groups",
            body={"Name": cron_group_name},
            body_supplied=True,
        )
        results["helper_group_created"] = created_group.get("ret") == 0
        helper_group_key = cron_key(wait_cron_group(client, cron_group_name))

        helper_payload = cron_task_payload(
            cron_task_name,
            helper_group_key,
            f"head -c 1048576 /dev/zero > '{src}/{filename}'",
        )
        created_helper = mutate(
            client,
            "POST",
            "/api/cron/list",
            body=helper_payload,
            body_supplied=True,
        )
        results["helper_task_created"] = created_helper.get("ret") == 0
        helper_task_key = cron_key(wait_cron_task(client, cron_task_name))
        helper_trigger = mutate(
            client,
            "GET",
            "/api/cron/dojobs",
            query={"key": helper_task_key},
        )
        results["helper_triggered"] = helper_trigger.get("ret") == 0
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not path_exists(client, src, filename):
            time.sleep(0.15)
        results["source_file_created"] = path_exists(client, src, filename)

        mutate(
            client,
            "GET",
            "/api/cron/enable",
            query={"enable": "false", "key": helper_task_key},
        )
        results["helper_task_deleted"] = (
            mutate(client, "DELETE", "/api/cron/list", query={"key": helper_task_key}).get(
                "ret"
            )
            == 0
        )
        helper_task_key = ""
        results["helper_group_deleted"] = (
            mutate(
                client,
                "DELETE",
                "/api/cron/groups",
                query={"key": helper_group_key},
            ).get("ret")
            == 0
        )
        helper_group_key = ""

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
            "CreateEmptyDirs": False,
            "IgnoreExisting": False,
            "IgnoreErrors": False,
            "CheckFirst": False,
            "Transfers": 1,
            "Checkers": 1,
            "BandwidthLimit": "32K",
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
        created = mutate(
            client,
            "POST",
            "/api/rclone/sync/list",
            body=task,
            body_supplied=True,
        )
        results["task_created"] = created.get("ret") == 0
        row = wait_task(client, remark)
        sync_key = task_key(row)
        detail = task_detail(client, sync_key)
        results["throttle_readback"] = (
            detail.get("BandwidthLimit") == "32K"
            and detail.get("Transfers") == 1
            and detail.get("Checkers") == 1
        )

        started = mutate(
            client,
            "POST",
            f"/api/rclone/sync/run/{sync_key}",
            query={"resync": "false"},
        )
        results["run_started"] = started.get("ret") == 0
        deadline = time.monotonic() + 8.0
        running: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            running = find_task(client, remark)
            if running is not None and task_status(running) == "running":
                break
            time.sleep(0.1)
        results["running_observed"] = (
            running is not None and task_status(running) == "running"
        )
        if not results["running_observed"]:
            raise RuntimeError("TEST task never entered running state")

        running_state = (
            running.get("State") if isinstance(running.get("State"), dict) else {}
        )
        observations["running_progress_nonempty"] = bool(running_state.get("Progress"))
        observations["running_transfer_bytes"] = running_state.get("TransferBytes")

        stopped = mutate(client, "POST", f"/api/rclone/sync/stop/{sync_key}")
        results["stop_ret_zero"] = stopped.get("ret") == 0
        observations["stop_response_keys"] = sorted(stopped.keys())

        deadline = time.monotonic() + 8.0
        latest: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            latest = find_task(client, remark)
            if latest is not None and task_status(latest) != "running":
                break
            time.sleep(0.15)
        post_stop_status = task_status(latest or {})
        results["left_running_state"] = post_stop_status != "running"
        observations["post_stop_status"] = post_stop_status
        observations["dest_file_present_after_stop"] = path_exists(client, dst, filename)
        state = latest.get("State") if latest and isinstance(latest.get("State"), dict) else {}
        observations["post_stop_last_error_present"] = bool(state.get("LastError"))
        observations["post_stop_state_fields"] = sorted(state.keys()) if state else []

        deleted = mutate(
            client,
            "DELETE",
            "/api/rclone/sync/list",
            query={"key": sync_key},
        )
        results["task_deleted"] = deleted.get("ret") == 0
        sync_key = ""
    finally:
        cleanup["rclone_tasks_removed"] = remove_test_tasks(client)
        cleanup["cron_tasks_removed"] = remove_test_cron_tasks(client)
        cleanup["cron_groups_removed"] = remove_test_cron_groups(client)
        cleanup["src_removed"] = delete_path(client, src)
        cleanup["dst_removed"] = delete_path(client, dst)

        final_sync = sync_rows(client)
        final_cron_tasks = cron_rows(client)
        final_cron_groups = cron_group_rows(client)
        cleanup["sync_baseline_restored"] = {
            task_key(row) for row in final_sync if task_key(row)
        } == baseline_sync_keys
        cleanup["cron_task_baseline_restored"] = {
            cron_key(row) for row in final_cron_tasks if cron_key(row)
        } == baseline_cron_task_keys
        cleanup["cron_group_baseline_restored"] = {
            cron_key(row) for row in final_cron_groups if cron_key(row)
        } == baseline_cron_group_keys
        cleanup["leftover_test_sync"] = sum(
            str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in final_sync
        )
        cleanup["leftover_test_cron_tasks"] = sum(
            str(row.get("Name") or "").startswith(TEST_PREFIX)
            for row in final_cron_tasks
        )
        cleanup["leftover_test_cron_groups"] = sum(
            str(row.get("Name") or "").startswith(TEST_PREFIX)
            for row in final_cron_groups
        )

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in (
        "src_removed",
        "dst_removed",
        "sync_baseline_restored",
        "cron_task_baseline_restored",
        "cron_group_baseline_restored",
    ):
        if cleanup.get(key) is not True:
            failed.append(f"cleanup:{key}")
    for key in (
        "leftover_test_sync",
        "leftover_test_cron_tasks",
        "leftover_test_cron_groups",
    ):
        if cleanup.get(key) != 0:
            failed.append(f"cleanup:{key}")

    return {
        "target": "Lucky Rclone running-task stop behavior",
        "results": results,
        "observations": observations,
        "cleanup": cleanup,
        "failed": sorted(set(failed)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"confirmation must be exactly {CONFIRMATION}")

    report = run_probe()
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
