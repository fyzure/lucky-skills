#!/usr/bin/env python3
"""Runtime-verify Lucky v3 Cron manual, scheduled, and failure behavior.

The probe creates only uniquely prefixed TEST Cron resources and one Lucky-
visible /tmp directory.  The success task first runs manually and creates a
marker file, then the same task is PUT-updated to run every two seconds with a
different marker.  A second manual-only task exits with status 7 so the probe
can verify failure logging.  No network calls, business tasks, service toggles,
or host files outside the TEST directory are used.
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


CONFIRMATION = "PROBE-AND-CLEAN-CRON"
TEST_PREFIX = "TEST-lucky-skills-cron-"


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


def cron_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/cron/list")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Cron task list type")
    return [row for row in rows if isinstance(row, dict)]


def group_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/cron/groups")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Cron group list type")
    return [row for row in rows if isinstance(row, dict)]


def row_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_task(client: LuckyClient, name: str) -> dict[str, Any] | None:
    return next((row for row in cron_rows(client) if str(row.get("Name") or "") == name), None)


def find_group(client: LuckyClient, name: str) -> dict[str, Any] | None:
    return next((row for row in group_rows(client) if str(row.get("Name") or "") == name), None)


def wait_task(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_task(client, name)
        if row is not None and row_key(row):
            return row
        time.sleep(0.25)
    raise RuntimeError("TEST Cron task did not appear")


def wait_group(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_group(client, name)
        if row is not None and row_key(row):
            return row
        time.sleep(0.25)
    raise RuntimeError("TEST Cron group did not appear")


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


def wait_path(client: LuckyClient, parent: str, name: str, timeout: float = 12.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path_exists(client, parent, name):
            return True
        time.sleep(0.25)
    return False


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


def cron_logs(client: LuckyClient, page_size: int = 100) -> list[dict[str, Any]]:
    value = client.request_json(
        "GET",
        "/api/cron/logs",
        query={"page": 1, "pageSize": page_size},
    )
    rows = value.get("logs") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Cron logs type")
    return [row for row in rows if isinstance(row, dict)]


def log_text(row: dict[str, Any]) -> str:
    return str(row.get("LogContent") or "")


def wait_failure_log(client: LuckyClient, task_name: str, timeout: float = 12.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in cron_logs(client):
            text = log_text(row)
            low = text.lower()
            if task_name in text and any(token in low for token in ("error", "fail", "exit", "错误", "失败")):
                return True
        time.sleep(0.3)
    return False


def base_task(name: str, group_key: str, script: str) -> dict[str, Any]:
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
                "Remark": "TEST shell",
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


def remove_test_tasks(client: LuckyClient) -> int:
    removed = 0
    for row in cron_rows(client):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = row_key(row)
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


def remove_test_groups(client: LuckyClient) -> int:
    removed = 0
    for row in group_rows(client):
        if not str(row.get("Name") or "").startswith(TEST_PREFIX):
            continue
        key = row_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/cron/groups", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def run_probe() -> dict[str, Any]:
    client = make_client()
    suffix = secrets.token_hex(5)
    group_name = f"{TEST_PREFIX}group-{suffix}"
    success_name = f"{TEST_PREFIX}success-{suffix}"
    failure_name = f"{TEST_PREFIX}failure-{suffix}"
    test_dir = f"/tmp/{TEST_PREFIX}{suffix}"
    manual_marker = "manual.ok"
    scheduled_marker = "scheduled.ok"

    baseline_task_keys = {row_key(row) for row in cron_rows(client) if row_key(row)}
    baseline_group_keys = {row_key(row) for row in group_rows(client) if row_key(row)}
    if any(str(row.get("Name") or "").startswith(TEST_PREFIX) for row in cron_rows(client)):
        raise RuntimeError("pre-existing TEST Cron task found; refusing to mix probe ownership")
    if any(str(row.get("Name") or "").startswith(TEST_PREFIX) for row in group_rows(client)):
        raise RuntimeError("pre-existing TEST Cron group found; refusing to mix probe ownership")

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_task_count": len(baseline_task_keys),
        "baseline_group_count": len(baseline_group_keys),
    }
    cleanup: dict[str, Any] = {}
    success_key = ""
    failure_key = ""
    group_key = ""

    try:
        mkdir(client, test_dir)
        results["test_path_created"] = path_exists(client, "/tmp", test_dir.rsplit("/", 1)[-1])

        created_group = mutate(
            client,
            "POST",
            "/api/cron/groups",
            body={"Name": group_name},
            body_supplied=True,
        )
        results["group_created"] = created_group.get("ret") == 0
        group = wait_group(client, group_name)
        group_key = row_key(group)
        observations["group_fields"] = sorted(group.keys())
        updated_group = mutate(
            client,
            "PUT",
            "/api/cron/groups",
            body={"Key": group_key, "Name": group_name},
            body_supplied=True,
        )
        results["group_put"] = updated_group.get("ret") == 0

        manual_script = f": > {test_dir}/{manual_marker}"
        success_payload = base_task(success_name, group_key, manual_script)
        created_task = mutate(
            client,
            "POST",
            "/api/cron/list",
            body=success_payload,
            body_supplied=True,
        )
        results["success_task_created"] = created_task.get("ret") == 0
        success_row = wait_task(client, success_name)
        success_key = row_key(success_row)
        observations["task_fields"] = sorted(success_row.keys())
        observations["job_fields"] = sorted(
            success_row.get("Jobs", [{}])[0].keys()
            if isinstance(success_row.get("Jobs"), list)
            and success_row.get("Jobs")
            and isinstance(success_row.get("Jobs")[0], dict)
            else []
        )

        manual_trigger = mutate(client, "GET", "/api/cron/dojobs", query={"key": success_key})
        results["manual_trigger_started"] = manual_trigger.get("ret") == 0
        results["manual_marker_created"] = wait_path(client, test_dir, manual_marker)

        scheduled_payload = copy.deepcopy(success_payload)
        scheduled_payload["Key"] = success_key
        scheduled_payload["Type"] = 4
        scheduled_payload["TypeParams"] = "2"
        scheduled_payload["Jobs"][0]["Options"]["shell_content"] = f": > {test_dir}/{scheduled_marker}"
        put_task = mutate(
            client,
            "PUT",
            "/api/cron/list",
            body=scheduled_payload,
            body_supplied=True,
        )
        results["scheduled_put"] = put_task.get("ret") == 0
        results["scheduled_marker_created"] = wait_path(client, test_dir, scheduled_marker, timeout=12.0)
        disabled = mutate(
            client,
            "GET",
            "/api/cron/enable",
            query={"enable": "false", "key": success_key},
        )
        results["scheduled_task_disabled"] = disabled.get("ret") == 0

        failure_payload = base_task(failure_name, group_key, "exit 7")
        failure_created = mutate(
            client,
            "POST",
            "/api/cron/list",
            body=failure_payload,
            body_supplied=True,
        )
        results["failure_task_created"] = failure_created.get("ret") == 0
        failure_row = wait_task(client, failure_name)
        failure_key = row_key(failure_row)
        failure_trigger = mutate(
            client,
            "POST",
            "/api/cron/jobs/trigger",
            body={"cronKey": failure_key, "jobIndex": 0},
            body_supplied=True,
        )
        results["failure_job_trigger_started"] = failure_trigger.get("ret") == 0
        results["failure_log_observed"] = wait_failure_log(client, failure_name)

        logs = cron_logs(client)
        observations["log_row_count"] = len(logs)
        observations["failure_log_fields"] = sorted(logs[0].keys()) if logs else []
    finally:
        cleanup["test_tasks_removed"] = remove_test_tasks(client)
        cleanup["test_groups_removed"] = remove_test_groups(client)
        cleanup["test_path_removed"] = delete_path(client, test_dir)
        remaining_tasks = cron_rows(client)
        remaining_groups = group_rows(client)
        cleanup["leftover_test_tasks"] = sum(
            str(row.get("Name") or "").startswith(TEST_PREFIX) for row in remaining_tasks
        )
        cleanup["leftover_test_groups"] = sum(
            str(row.get("Name") or "").startswith(TEST_PREFIX) for row in remaining_groups
        )
        cleanup["task_key_baseline_restored"] = {
            row_key(row) for row in remaining_tasks if row_key(row)
        } == baseline_task_keys
        cleanup["group_key_baseline_restored"] = {
            row_key(row) for row in remaining_groups if row_key(row)
        } == baseline_group_keys

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in (
        "test_path_removed",
        "task_key_baseline_restored",
        "group_key_baseline_restored",
    ):
        if cleanup.get(key) is not True:
            failed.append(f"cleanup:{key}")
    if cleanup.get("leftover_test_tasks") != 0:
        failed.append("cleanup:leftover_test_tasks")
    if cleanup.get("leftover_test_groups") != 0:
        failed.append("cleanup:leftover_test_groups")

    return {
        "target": "Lucky Cron manual trigger, scheduled execution, and failure logging",
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
