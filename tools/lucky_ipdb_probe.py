#!/usr/bin/env python3
"""Runtime-verify Lucky v3 IPDB CRUD, upload, query, and download behavior.

The probe uses a uniquely named TEST item and two uniquely named copies of a
small public GeoCN MMDB. It uploads the files through Lucky's own multipart
endpoint, creates and updates one IPDB item, enables it, performs real IP
queries, downloads the active DB through Lucky, switches the item to the
second uploaded file, then removes the item and both TEST database files.

No geolocation result values are printed. Evidence records only structural
keys, byte/hash equality, booleans, and cleanup state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError, LuckyAPIError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-IPDB"
TEST_PREFIX = "TEST-lucky-skills-ipdb-"
DEFAULT_DATABASE_URL = (
    "https://github.com/ljxi/GeoCN/releases/download/v26.4.19/GeoCN.mmdb"
)


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(
            base_url,
            token,
            catalog=catalog,
            retries=0,
            timeout=180,
            max_response_bytes=32 * 1024 * 1024,
        )
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(
        values["base_url"],
        values["open_token"],
        catalog=catalog,
        retries=0,
        timeout=180,
        max_response_bytes=32 * 1024 * 1024,
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    body_supplied: bool = False,
    attempts: int = 5,
) -> Any:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {"allow_unsafe": True}
        if query is not None:
            kwargs["query"] = query
        if body_supplied:
            kwargs["json_body"] = json_body
        try:
            return client.request_json(method, path, **kwargs)
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(5.0 + attempt * 3.0)
    raise AssertionError("unreachable")


def item_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/ipdb/items")
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected IPDB list response")
    return [row for row in rows if isinstance(row, dict)]


def item_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or "")


def wait_item(client: LuckyClient, remark: str, timeout: float = 25.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in item_rows(client):
            if row.get("Remark") == remark:
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST IPDB item did not appear")


def wait_ready(client: LuckyClient, key: str, timeout: float = 35.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        for row in item_rows(client):
            if item_key(row) == key:
                last = row
                if row.get("Enable") is True and row.get("Ready") is True:
                    return row
        time.sleep(0.6)
    return last


def download_source(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "lucky-skills-ipdb-probe/1"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(24 * 1024 * 1024)
    if len(data) < 1024:
        raise RuntimeError("IPDB source download was unexpectedly small")
    return data


def multipart_file(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = "----lucky-skills-" + secrets.token_hex(12)
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    body = header + data + b"\r\n" + f"--{boundary}--\r\n".encode("ascii")
    return body, f"multipart/form-data; boundary={boundary}"


def upload_database(client: LuckyClient, filename: str, data: bytes) -> str:
    body, content_type = multipart_file(filename, data)
    response = client.request(
        "POST",
        "/api/ipdb/upload",
        raw_body=body,
        content_type=content_type,
        allow_unsafe=True,
    )
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("ret") != 0:
        raise RuntimeError("Lucky IPDB upload failed")
    file_path = str(payload.get("file") or "")
    if not file_path:
        raise RuntimeError("Lucky IPDB upload returned no file path")
    return file_path


def available_files(client: LuckyClient, key: str) -> list[str]:
    payload = client.request_json("GET", "/api/ipdb/avalidDBFiles", query={"key": key})
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected IPDB available-file response")
    return [str(value) for value in rows]


def delete_dbfile(client: LuckyClient, key: str, file_path: str) -> bool:
    if not file_path:
        return True
    try:
        mutate(
            client,
            "DELETE",
            "/api/ipdb/dbfile",
            query={"key": key, "file": file_path},
        )
    except LuckyAPIError:
        pass
    try:
        return file_path not in available_files(client, key)
    except Exception:
        return True


def delete_test_items(client: LuckyClient) -> int:
    removed = 0
    for row in item_rows(client):
        if not str(row.get("Remark") or "").startswith(TEST_PREFIX):
            continue
        key = item_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", "/api/ipdb/item", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def query_ip(client: LuckyClient, address: str) -> tuple[bool, list[str]]:
    try:
        payload = client.request_json("GET", "/api/ipdb/query", query={"ip": address})
    except LuckyAPIError:
        return False, []
    if not isinstance(payload, dict) or payload.get("ret") != 0:
        return False, []
    safe_keys = sorted(key for key in payload if key not in {"ret"})
    return True, safe_keys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--database-url", default=DEFAULT_DATABASE_URL)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline = item_rows(client)
    baseline_keys = {item_key(row) for row in baseline if item_key(row)}
    if any(str(row.get("Remark") or "").startswith(TEST_PREFIX) for row in baseline):
        raise RuntimeError("pre-existing TEST IPDB item found")

    nonce = secrets.token_hex(5)
    remark = TEST_PREFIX + nonce
    file_one_name = f"{remark}-a.mmdb"
    file_two_name = f"{remark}-b.mmdb"
    source = download_source(args.database_url)
    source_hash = hashlib.sha256(source).hexdigest()

    key = ""
    file_one = ""
    file_two = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "source_size_bytes": len(source),
        "source_sha256_recorded": bool(source_hash),
    }
    cleanup: dict[str, Any] = {}

    try:
        file_one = upload_database(client, file_one_name, source)
        file_two = upload_database(client, file_two_name, source)
        results["upload_first_database"] = bool(file_one)
        results["upload_second_database"] = bool(file_two and file_two != file_one)

        create_payload = {
            "Key": "",
            "Remark": remark,
            "Enable": False,
            "Format": "geocn",
            "FilePath": file_one,
            "SupportTypes": 3,
            "BufferType": 0,
            "DBParam1": "",
        }
        mutate(
            client,
            "POST",
            "/api/ipdb/item",
            json_body=create_payload,
            body_supplied=True,
        )
        row = wait_item(client, remark)
        key = item_key(row)
        results["item_created"] = bool(key)
        results["item_created_disabled"] = row.get("Enable") is False

        files_after_upload = available_files(client, key)
        results["uploaded_files_listed"] = file_one in files_after_upload and file_two in files_after_upload
        observations["available_file_count_after_upload"] = len(files_after_upload)

        update_payload = {
            "Key": key,
            "Remark": remark,
            "Enable": False,
            "Format": "geocn",
            "FilePath": file_one,
            "SupportTypes": 3,
            "BufferType": 1,
            "DBParam1": "",
        }
        mutate(
            client,
            "PUT",
            "/api/ipdb/item",
            json_body=update_payload,
            body_supplied=True,
        )
        row = wait_item(client, remark)
        results["item_updated"] = row.get("BufferType") == 1

        # Although the route is a GET in Lucky 3.0.0, the second path segment
        # is an enable boolean and this call mutates runtime state.
        mutate(client, "GET", f"/api/ipdb/item/{key}/true")
        row = wait_ready(client, key)
        results["item_enabled_and_ready"] = row.get("Enable") is True and row.get("Ready") is True

        v4_ok, v4_keys = query_ip(client, "114.114.114.114")
        results["ipv4_query"] = v4_ok
        observations["ipv4_query_response_keys"] = v4_keys

        # Try several well-known Chinese IPv6 prefixes and record only whether
        # at least one was recognized; never retain returned geography values.
        ipv6_keys: list[str] = []
        ipv6_ok = False
        for candidate in ("240e::1", "2408:4000::1", "2409:8a00::1"):
            ipv6_ok, ipv6_keys = query_ip(client, candidate)
            if ipv6_ok:
                break
        results["ipv6_query"] = ipv6_ok
        observations["ipv6_query_response_keys"] = ipv6_keys

        downloaded = client.request(
            "GET",
            "/api/ipdb/download",
            query={"key": key},
            allow_unsafe=True,
            raise_for_lucky=False,
        )
        results["database_download"] = len(downloaded.body) == len(source)
        results["database_download_hash_match"] = (
            hashlib.sha256(downloaded.body).hexdigest() == source_hash
        )
        observations["download_content_type_present"] = bool(downloaded.content_type)

        # Switch the active item to the second uploaded copy to exercise a
        # database-file update/reload without touching a business DB file.
        switch_payload = dict(update_payload)
        switch_payload["Enable"] = True
        switch_payload["FilePath"] = file_two
        switch_payload["BufferType"] = 0
        mutate(
            client,
            "PUT",
            "/api/ipdb/item",
            json_body=switch_payload,
            body_supplied=True,
        )
        row = wait_ready(client, key)
        results["database_file_switched"] = row.get("FilePath") == file_two and row.get("Ready") is True
        results["query_after_file_switch"] = query_ip(client, "114.114.114.114")[0]

        mutate(client, "GET", f"/api/ipdb/item/{key}/false")
        row = wait_item(client, remark)
        results["item_disabled"] = row.get("Enable") is False

        mutate(client, "DELETE", "/api/ipdb/item", query={"key": key})
        results["item_deleted"] = all(item_key(row) != key for row in item_rows(client))
    finally:
        cleanup["leftover_test_items_removed"] = delete_test_items(client)
        cleanup["first_database_deleted"] = delete_dbfile(client, key, file_one)
        cleanup["second_database_deleted"] = delete_dbfile(client, key, file_two)

    final = item_rows(client)
    cleanup["item_key_baseline_restored"] = {
        item_key(row) for row in final if item_key(row)
    } == baseline_keys
    cleanup["leftover_test_items"] = sum(
        1 for row in final if str(row.get("Remark") or "").startswith(TEST_PREFIX)
    )
    try:
        final_files = available_files(client, key)
    except Exception:
        final_files = []
    cleanup["test_database_files_absent"] = file_one not in final_files and file_two not in final_files

    failed = sorted(key for key, value in results.items() if not value)
    for key_name in (
        "first_database_deleted",
        "second_database_deleted",
        "item_key_baseline_restored",
        "test_database_files_absent",
    ):
        if not cleanup.get(key_name):
            failed.append(key_name)
    if cleanup.get("leftover_test_items") != 0:
        failed.append("leftover_test_items")

    print(
        json.dumps(
            {
                "target": "Lucky IPDB upload + item CRUD + query + download behavior",
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
