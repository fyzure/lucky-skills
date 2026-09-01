#!/usr/bin/env python3
"""Runtime-verify Lucky v3 StorageManagement local-storage lifecycle.

The probe creates one unique Lucky-visible /tmp directory through the
local-path-browser API, registers it as a disabled local storage item, verifies
POST/PUT/readback/enable/litelist/log/delete semantics, and restores the
original storage-item baseline. SystemMount remains disabled throughout: this
probe intentionally verifies the storage registry lifecycle without creating
an OS mount.
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


CONFIRMATION = "PROBE-AND-CLEAN-STORAGE"
TEST_PREFIX = "TEST-lucky-skills-storage-"


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


def storage_payload(client: LuckyClient) -> dict[str, Any]:
    # GET /api/storagemanagement/list has a current Lucky 3.0.0 frontend call
    # site but was historically absent from the extracted route catalog, so
    # allow_unsafe is explicit until runtime evidence promotes it into the
    # merged catalog.
    value = client.request_json(
        "GET", "/api/storagemanagement/list", allow_unsafe=True
    )
    if not isinstance(value, dict):
        raise RuntimeError("unexpected StorageManagement list response")
    return value


def storage_rows(client: LuckyClient) -> list[dict[str, Any]]:
    rows = storage_payload(client).get("list")
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected StorageManagement list type")
    return [row for row in rows if isinstance(row, dict)]


def lite_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json("GET", "/api/storagemanagement/litelist")
    rows = value.get("list") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected StorageManagement litelist type")
    return [row for row in rows if isinstance(row, dict)]


def item_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_by_remark(client: LuckyClient, remark: str) -> dict[str, Any] | None:
    for row in storage_rows(client):
        if str(row.get("Remark") or "") == remark:
            return row
    return None


def wait_item(client: LuckyClient, remark: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_by_remark(client, remark)
        if row is not None and item_key(row):
            return row
        time.sleep(0.4)
    raise RuntimeError("TEST storage item did not appear")


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


def create_test_path(client: LuckyClient, path: str) -> None:
    mutate(
        client,
        "POST",
        "/api/local-path-browser/mkdir",
        body={"path": path},
        body_supplied=True,
    )


def delete_test_path(client: LuckyClient, path: str) -> bool:
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


def remove_test_items(client: LuckyClient) -> int:
    removed = 0
    for row in storage_rows(client):
        if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
            continue
        key = item_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/storagemanagement/list", query={"key": key})
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
    baseline_payload = storage_payload(client)
    baseline_rows = storage_rows(client)
    baseline_keys = {item_key(row) for row in baseline_rows if item_key(row)}
    baseline_lite_keys = {item_key(row) for row in lite_rows(client) if item_key(row)}
    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in baseline_rows):
        raise RuntimeError("pre-existing TEST StorageManagement item found")

    nonce = secrets.token_hex(5)
    remark = TEST_PREFIX + nonce
    updated_remark = remark + "-updated"
    test_path = f"/tmp/{TEST_PREFIX}{nonce}"
    if any(str(row.get("path") or "") == test_path for row in path_entries(client, "/tmp")):
        raise RuntimeError("pre-existing TEST storage path found")

    candidate = {
        "Type": "local",
        "Enable": False,
        "Key": "",
        "Remark": remark,
        "Writable": True,
        "Log": True,
        "Params": {
            "Proxy": "",
            "ProxyAddr": "",
            "ProxyUser": "",
            "ProxyPasswd": "",
            "LocalPath": test_path,
        },
        "SystemMount": {
            "Enable": False,
            "MountType": "network",
            "MountPoint": "",
            "Label": "",
            "OnleyCreateVFS": False,
        },
    }

    test_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_os": str(baseline_payload.get("os") or ""),
        "system_mount_exercised": False,
    }
    cleanup: dict[str, Any] = {}

    try:
        create_test_path(client, test_path)
        results["test_path_created"] = any(
            str(row.get("path") or "") == test_path for row in path_entries(client, "/tmp")
        )

        created = mutate(
            client,
            "POST",
            "/api/storagemanagement/list",
            body=candidate,
            body_supplied=True,
        )
        results["post_create"] = created.get("ret") == 0
        row = wait_item(client, remark)
        test_key = item_key(row)
        params = row.get("Params") if isinstance(row.get("Params"), dict) else {}
        system_mount = (
            row.get("SystemMount") if isinstance(row.get("SystemMount"), dict) else {}
        )
        observations["create_readback_shape"] = {
            "fields": sorted(row.keys()),
            "type": str(row.get("Type") or ""),
            "enable": row.get("Enable"),
            "writable": row.get("Writable"),
            "params_fields": sorted(params.keys()),
            "local_path_matches": params.get("LocalPath") == test_path,
            "system_mount_fields": sorted(system_mount.keys()),
            "system_mount_enable": system_mount.get("Enable"),
        }
        results["create_readback"] = (
            bool(test_key)
            and row.get("Type") == "local"
            and row.get("Enable") is True
            and row.get("Writable") is True
            and params.get("LocalPath") == test_path
            and system_mount.get("Enable") is False
        )
        observations["create_forces_enable_true"] = row.get("Enable") is True

        disabled_after_create = mutate(
            client,
            "GET",
            "/api/storagemanagement/enable",
            query={"key": test_key, "enable": "false"},
        )
        results["disable_after_create"] = disabled_after_create.get("ret") == 0
        row = wait_item(client, remark)
        results["disabled_after_create_readback"] = row.get("Enable") is False

        lite_before_enable = lite_rows(client)
        observations["disabled_item_in_litelist"] = any(
            item_key(item) == test_key for item in lite_before_enable
        )

        updated = copy.deepcopy(row)
        updated["Remark"] = updated_remark
        updated["Writable"] = False
        put = mutate(
            client,
            "PUT",
            "/api/storagemanagement/list",
            body=updated,
            body_supplied=True,
        )
        results["put_update"] = put.get("ret") == 0
        row = wait_item(client, updated_remark)
        observations["update_readback_shape"] = {
            "fields": sorted(row.keys()),
            "enable": row.get("Enable"),
            "writable": row.get("Writable"),
        }
        results["update_readback"] = (
            item_key(row) == test_key
            and row.get("Writable") is False
            and row.get("Enable") is False
        )

        enabled = mutate(
            client,
            "GET",
            "/api/storagemanagement/enable",
            query={"key": test_key, "enable": "true"},
        )
        results["enable_route"] = enabled.get("ret") == 0
        row = wait_item(client, updated_remark)
        results["enabled_readback"] = row.get("Enable") is True
        lite_enabled = lite_rows(client)
        lite_match = next((item for item in lite_enabled if item_key(item) == test_key), None)
        results["litelist_after_enable"] = isinstance(lite_match, dict)
        observations["litelist_item_fields"] = (
            sorted(lite_match.keys()) if isinstance(lite_match, dict) else []
        )

        disabled = mutate(
            client,
            "GET",
            "/api/storagemanagement/enable",
            query={"key": test_key, "enable": "false"},
        )
        results["disable_route"] = disabled.get("ret") == 0
        row = wait_item(client, updated_remark)
        results["disabled_readback"] = row.get("Enable") is False

        logs = client.request_json(
            "GET", "/api/storagemanagement/logs", query={"page": 1, "pageSize": 50}
        )
        results["logs_read"] = isinstance(logs, dict) and logs.get("ret") == 0
        log_rows = logs.get("list") or logs.get("logs") if isinstance(logs, dict) else []
        observations["log_row_count"] = len(log_rows) if isinstance(log_rows, list) else 0

        deleted = mutate(
            client,
            "DELETE",
            "/api/storagemanagement/list",
            query={"key": test_key},
        )
        results["delete_item"] = deleted.get("ret") == 0
        results["item_absent_after_delete"] = all(
            item_key(item) != test_key for item in storage_rows(client)
        )
        test_key = ""
    finally:
        cleanup["test_items_removed"] = remove_test_items(client)
        cleanup["test_path_removed"] = delete_test_path(client, test_path)

    final_rows = storage_rows(client)
    final_lite_rows = lite_rows(client)
    cleanup["storage_key_baseline_restored"] = {
        item_key(row) for row in final_rows if item_key(row)
    } == baseline_keys
    cleanup["litelist_key_baseline_restored"] = {
        item_key(row) for row in final_lite_rows if item_key(row)
    } == baseline_lite_keys
    cleanup["leftover_test_items"] = sum(
        1 for row in final_rows if str(row.get("Remark") or "").startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if not value)
    for key in ("test_path_removed", "storage_key_baseline_restored", "litelist_key_baseline_restored"):
        if not cleanup.get(key):
            failed.append(key)
    if cleanup.get("leftover_test_items") != 0:
        failed.append("leftover_test_items")

    print(
        json.dumps(
            {
                "target": "Lucky StorageManagement local storage lifecycle",
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
