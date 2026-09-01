#!/usr/bin/env python3
"""Runtime-verify Lucky v3 WebDAV and StorageManagement consumer permissions.

The probe requires the existing WebDAV service to be stopped and have no
configured users. It creates two unique local StorageManagement items backed
by Lucky-visible /tmp directories (one writable, one read-only), temporarily
starts WebDAV on 127.0.0.1 with one disposable Basic-auth user, mounts both
storage items, and verifies real WebDAV read/write behavior. It then stops and
restores the original WebDAV configuration and removes only its TEST resources.

Passwords, file contents, OpenToken values and existing configuration values
are never emitted in the JSON result.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
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


CONFIRMATION = "PROBE-AND-CLEAN-WEBDAV"
TEST_PREFIX = "TEST-lucky-skills-webdav-"


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


def get_webdav_config(client: LuckyClient) -> dict[str, Any]:
    value = client.request_json("GET", "/api/webdav/configure")
    config = value.get("configure") if isinstance(value, dict) else None
    if not isinstance(config, dict):
        raise RuntimeError("unexpected WebDAV configure response")
    return copy.deepcopy(config)


def get_webdav_status(client: LuckyClient) -> bool:
    value = client.request_json("GET", "/api/webdav/status")
    return bool(value.get("status")) if isinstance(value, dict) else False


def wait_webdav_status(client: LuckyClient, expected: bool, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if get_webdav_status(client) is expected:
            return True
        time.sleep(0.4)
    return False


def storage_payload(client: LuckyClient) -> dict[str, Any]:
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


def storage_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def find_storage(client: LuckyClient, remark: str) -> dict[str, Any] | None:
    return next(
        (row for row in storage_rows(client) if str(row.get("Remark") or "") == remark),
        None,
    )


def wait_storage(client: LuckyClient, remark: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = find_storage(client, remark)
        if row is not None and storage_key(row):
            return row
        time.sleep(0.3)
    raise RuntimeError("TEST storage did not appear")


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


def create_path(client: LuckyClient, path: str) -> None:
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


def delete_child_if_present(client: LuckyClient, parent: str, name: str) -> None:
    target = parent.rstrip("/") + "/" + name
    if not any(str(row.get("path") or "") == target for row in path_entries(client, parent)):
        return
    mutate(
        client,
        "DELETE",
        "/api/local-path-browser/path",
        body={"path": target, "confirmName": name},
        body_supplied=True,
    )


def create_storage(
    client: LuckyClient, *, remark: str, local_path: str, writable: bool
) -> dict[str, Any]:
    candidate = {
        "Type": "local",
        "Enable": True,
        "Key": "",
        "Remark": remark,
        "Writable": writable,
        "Log": True,
        "Params": {"LocalPath": local_path},
        "SystemMount": {
            "Enable": False,
            "MountType": "network",
            "MountPoint": "",
            "Label": "",
            "OnleyCreateVFS": False,
        },
    }
    created = mutate(
        client,
        "POST",
        "/api/storagemanagement/list",
        body=candidate,
        body_supplied=True,
    )
    if created.get("ret") != 0:
        raise RuntimeError("TEST StorageManagement create failed")
    row = wait_storage(client, remark)
    key = storage_key(row)
    mutate(
        client,
        "GET",
        "/api/storagemanagement/enable",
        query={"key": key, "enable": "true"},
    )
    return wait_storage(client, remark)


def remove_test_storages(client: LuckyClient) -> int:
    removed = 0
    for row in storage_rows(client):
        if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
            continue
        key = storage_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/storagemanagement/list", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def choose_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def wait_tcp(port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            sock.close()
        time.sleep(0.25)
    return False


def webdav_request(
    port: int,
    username: str,
    password: str,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes, dict[str, str]]:
    url = f"http://127.0.0.1:{port}/{path.lstrip('/')}"
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request_headers = {
        "Authorization": "Basic " + credential,
        "User-Agent": "lucky-skills-webdav-probe/1",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                int(response.status),
                response.read(1024 * 1024),
                {str(k).lower(): str(v) for k, v in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        return (
            int(error.code),
            error.read(1024 * 1024),
            {str(k).lower(): str(v) for k, v in error.headers.items()},
        )


def config_owned_by_probe(config: dict[str, Any], username: str, port: int) -> bool:
    users = config.get("Users")
    if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
        return False
    return (
        str(users[0].get("Username") or "") == username
        and int(config.get("ListenPort") or 0) == port
        and str(config.get("ListenIP") or "") == "127.0.0.1"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline_config = get_webdav_config(client)
    baseline_status = get_webdav_status(client)
    baseline_users = baseline_config.get("Users")
    if baseline_status or (isinstance(baseline_users, list) and baseline_users):
        raise RuntimeError(
            "refusing WebDAV behavior probe: existing service is active or has configured users"
        )

    baseline_storage_keys = {storage_key(row) for row in storage_rows(client) if storage_key(row)}
    nonce = secrets.token_hex(5)
    username = TEST_PREFIX + nonce
    password = secrets.token_urlsafe(24)
    rw_remark = TEST_PREFIX + "rw-" + nonce
    ro_remark = TEST_PREFIX + "ro-" + nonce
    rw_path = f"/tmp/{TEST_PREFIX}rw-{nonce}"
    ro_path = f"/tmp/{TEST_PREFIX}ro-{nonce}"
    port = choose_port()
    filename = "probe.txt"
    blocked_name = "blocked.txt"
    content = ("webdav-" + nonce).encode("utf-8")

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_status": baseline_status,
        "baseline_user_count": len(baseline_users) if isinstance(baseline_users, list) else 0,
        "system_mount_exercised": False,
    }
    cleanup: dict[str, Any] = {}
    test_config_applied = False

    try:
        create_path(client, rw_path)
        create_path(client, ro_path)
        results["test_paths_created"] = all(
            any(str(row.get("path") or "") == path for row in path_entries(client, "/tmp"))
            for path in (rw_path, ro_path)
        )

        rw_storage = create_storage(
            client, remark=rw_remark, local_path=rw_path, writable=True
        )
        ro_storage = create_storage(
            client, remark=ro_remark, local_path=ro_path, writable=False
        )
        rw_key = storage_key(rw_storage)
        ro_key = storage_key(ro_storage)
        results["storage_items_created"] = (
            bool(rw_key)
            and bool(ro_key)
            and rw_storage.get("Writable") is True
            and ro_storage.get("Writable") is False
        )

        test_config = copy.deepcopy(baseline_config)
        test_config.update(
            {
                "Enable": True,
                "ListenIP": "127.0.0.1",
                "ListenPort": port,
                "ListenNetwork": "tcp4",
                "TLSEnable": False,
                "HTTPEnable": True,
                "AutoFirewall": False,
                "TrustHostList": "",
                "Users": [
                    {
                        "Username": username,
                        "Password": password,
                        "Prefix": "",
                        "FrontType": 0,
                        "Modify": True,
                        "DownloadLimitKBps": 0,
                        "UploadLimitKBps": 0,
                        "MountList": [
                            {
                                "Type": "store",
                                "Param": rw_key,
                                "DisplayName": "rw",
                                "Writable": True,
                                "DisableChangeWriteTable": False,
                            },
                            {
                                "Type": "store",
                                "Param": ro_key,
                                "DisplayName": "ro",
                                "Writable": False,
                                "DisableChangeWriteTable": True,
                            },
                        ],
                    }
                ],
            }
        )
        saved = mutate(
            client,
            "PUT",
            "/api/webdav/configure",
            body=test_config,
            body_supplied=True,
        )
        results["webdav_config_saved"] = saved.get("ret") == 0
        test_config_applied = True
        results["webdav_status_running"] = wait_webdav_status(client, True)
        results["webdav_tcp_listening"] = wait_tcp(port)

        current = get_webdav_config(client)
        results["webdav_config_readback"] = config_owned_by_probe(current, username, port)
        users = current.get("Users")
        observations["user_readback_fields"] = (
            sorted(users[0].keys())
            if isinstance(users, list) and users and isinstance(users[0], dict)
            else []
        )
        mounts = (
            users[0].get("MountList")
            if isinstance(users, list) and users and isinstance(users[0], dict)
            else None
        )
        observations["mount_readback_fields"] = (
            sorted(mounts[0].keys())
            if isinstance(mounts, list) and mounts and isinstance(mounts[0], dict)
            else []
        )

        options_status, _, options_headers = webdav_request(
            port, username, password, "OPTIONS", "/"
        )
        results["webdav_options"] = 200 <= options_status < 300
        observations["dav_header_present"] = bool(options_headers.get("dav"))

        propfind_status, propfind_body, _ = webdav_request(
            port,
            username,
            password,
            "PROPFIND",
            "/",
            body=b'<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>',
            headers={"Depth": "1", "Content-Type": "application/xml"},
        )
        results["webdav_propfind"] = propfind_status in {200, 207}
        lower_propfind = propfind_body.lower()
        results["mounts_visible"] = b"rw" in lower_propfind and b"ro" in lower_propfind

        put_status, _, _ = webdav_request(
            port,
            username,
            password,
            "PUT",
            "/rw/" + filename,
            body=content,
            headers={"Content-Type": "application/octet-stream"},
        )
        results["writable_put"] = 200 <= put_status < 300
        results["writable_file_created"] = any(
            str(row.get("name") or "") == filename for row in path_entries(client, rw_path)
        )
        get_status, get_body, _ = webdav_request(
            port, username, password, "GET", "/rw/" + filename
        )
        results["writable_get"] = get_status == 200 and get_body == content

        blocked_status, _, _ = webdav_request(
            port,
            username,
            password,
            "PUT",
            "/ro/" + blocked_name,
            body=b"blocked",
            headers={"Content-Type": "application/octet-stream"},
        )
        observations["readonly_put_status"] = blocked_status
        results["readonly_put_rejected"] = blocked_status >= 400
        results["readonly_file_absent"] = not any(
            str(row.get("name") or "") == blocked_name for row in path_entries(client, ro_path)
        )

        delete_status, _, _ = webdav_request(
            port, username, password, "DELETE", "/rw/" + filename
        )
        results["writable_delete"] = 200 <= delete_status < 300
        results["writable_file_removed"] = not any(
            str(row.get("name") or "") == filename for row in path_entries(client, rw_path)
        )

        logs = client.request_json(
            "GET", "/api/webdav/logs", query={"page": 1, "pageSize": 100}
        )
        log_rows = logs.get("logs") if isinstance(logs, dict) else None
        results["webdav_logs_read"] = isinstance(log_rows, list)
        observations["webdav_log_count"] = len(log_rows) if isinstance(log_rows, list) else 0
    finally:
        # If a partial run left TEST files, remove only those unique filenames.
        for parent, child in ((rw_path, filename), (ro_path, blocked_name)):
            try:
                delete_child_if_present(client, parent, child)
            except Exception:
                pass

        if test_config_applied:
            try:
                current = get_webdav_config(client)
                if config_owned_by_probe(current, username, port):
                    mutate(
                        client,
                        "PUT",
                        "/api/webdav/configure",
                        body=baseline_config,
                        body_supplied=True,
                    )
                    cleanup["webdav_config_restored"] = True
                else:
                    cleanup["webdav_config_restored"] = False
                    cleanup["restore_refused_due_concurrent_change"] = True
            except Exception:
                cleanup["webdav_config_restored"] = False
        else:
            cleanup["webdav_config_restored"] = True

        cleanup["webdav_status_restored"] = wait_webdav_status(client, baseline_status)
        cleanup["test_storages_removed"] = remove_test_storages(client)
        cleanup["rw_path_removed"] = delete_path(client, rw_path)
        cleanup["ro_path_removed"] = delete_path(client, ro_path)

    final_storage_keys = {storage_key(row) for row in storage_rows(client) if storage_key(row)}
    cleanup["storage_key_baseline_restored"] = final_storage_keys == baseline_storage_keys
    final_config = get_webdav_config(client)
    cleanup["webdav_user_baseline_restored"] = (
        final_config.get("Users") == baseline_config.get("Users")
    )

    failed = sorted(key for key, value in results.items() if not value)
    for key in (
        "webdav_config_restored",
        "webdav_status_restored",
        "rw_path_removed",
        "ro_path_removed",
        "storage_key_baseline_restored",
        "webdav_user_baseline_restored",
    ):
        if not cleanup.get(key):
            failed.append(key)

    print(
        json.dumps(
            {
                "target": "Lucky WebDAV + StorageManagement read/write enforcement",
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
