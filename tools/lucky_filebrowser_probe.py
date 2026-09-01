#!/usr/bin/env python3
"""Runtime-verify Lucky v3 FileBrowser loopback file behavior.

The probe refuses to run when the existing FileBrowser service is enabled or
running.  It creates a unique Lucky-visible /tmp tree, points FileBrowser at a
fresh TEST database/cache and one writable local mount, then starts HTTP on a
random 127.0.0.1 tcp4 port with firewall automation and TLS disabled.

A fresh TEST database is expected to accept FileBrowser's documented reset
default account/password (666/666); the dangerous Lucky ``resetadmin`` route
is never called.  The returned FileBrowser JWT remains only in process memory.
The probe uploads a tiny TEST file through FileBrowser's own resource API,
reads it back, renames it, deletes it, and cross-checks the corresponding
Lucky-visible filesystem state.  Finally it restores the exact pre-probe
FileBrowser configuration only after an ownership guard confirms the live
configuration still belongs to this TEST run, then removes the TEST tree.

No password, JWT, file body, existing path, Redis URL, or OpenToken value is
emitted in the JSON result.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.parse
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


CONFIRMATION = "PROBE-AND-CLEAN-FILEBROWSER"
TEST_PREFIX = "TEST-lucky-skills-filebrowser-"
TEST_LOGIN = "666"


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
        timeout=25,
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


def get_config(client: LuckyClient) -> tuple[dict[str, Any], bool]:
    value = client.request_json("GET", "/api/third/filebrowser/configure")
    config = value.get("configure") if isinstance(value, dict) else None
    if not isinstance(config, dict):
        raise RuntimeError("unexpected FileBrowser configure response")
    return copy.deepcopy(config), bool(value.get("status"))


def get_status(client: LuckyClient) -> dict[str, Any]:
    value = client.request_json("GET", "/api/third/filebrowser/status")
    if not isinstance(value, dict):
        raise RuntimeError("unexpected FileBrowser status response")
    return value


def wait_status(client: LuckyClient, expected: bool, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bool(get_status(client).get("status")) is expected:
            return True
        time.sleep(0.25)
    return False


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
        raise RuntimeError("unexpected local-path-browser list response")
    return [row for row in rows if isinstance(row, dict)]


def path_exists(client: LuckyClient, parent: str, name: str) -> bool:
    target = parent.rstrip("/") + "/" + name
    return any(str(row.get("path") or "") == target for row in path_entries(client, parent))


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


def pick_loopback_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def http_request(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            return response.status, dict(response.headers.items()), response.read(2_000_000)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read(2_000_000)


def wait_child(client: LuckyClient, parent: str, name: str, expected: bool) -> bool:
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        if path_exists(client, parent, name) is expected:
            return True
        time.sleep(0.15)
    return path_exists(client, parent, name) is expected


def run_probe() -> dict[str, Any]:
    client = make_client()
    nonce = secrets.token_hex(5)
    test_dir = f"/tmp/{TEST_PREFIX}{nonce}"
    mount_dir = f"{test_dir}/root"
    cache_dir = f"{test_dir}/cache"
    db_file = f"{test_dir}/filebrowser.db"
    filename = f"probe-{nonce}.txt"
    renamed = f"renamed-{nonce}.txt"
    marker = f"lucky-filebrowser-{nonce}"
    port = pick_loopback_port()

    baseline, baseline_status = get_config(client)
    if baseline_status or bool(baseline.get("Enable")):
        raise RuntimeError("FileBrowser baseline is running/enabled; refusing probe")
    if any(
        str(row.get("Param") or "").startswith(f"/tmp/{TEST_PREFIX}")
        for row in (baseline.get("MountList") or [])
        if isinstance(row, dict)
    ):
        raise RuntimeError("pre-existing TEST FileBrowser mount found")

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_status": baseline_status,
        "listener": "127.0.0.1",
        "network": "tcp4",
        "firewall_auto": False,
        "tls_enabled": False,
        "resetadmin_called": False,
    }
    cleanup: dict[str, Any] = {}
    failure: str | None = None
    jwt = ""

    def auth_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "X-Auth": jwt,
            "User-Agent": "lucky-skills-filebrowser-probe/1",
        }
        if extra:
            headers.update(extra)
        return headers

    try:
        for path in (test_dir, mount_dir, cache_dir):
            create_path(client, path)
        results["test_paths_created"] = path_exists(
            client, "/tmp", test_dir.rsplit("/", 1)[-1]
        )

        candidate = copy.deepcopy(baseline)
        candidate.update(
            {
                "Enable": True,
                "Address": "127.0.0.1",
                "Port": str(port),
                "ListenNetwork": "tcp4",
                "TLSEnable": False,
                "HTTPEnable": True,
                "AutoFirewall": False,
                "TrustHostList": "",
                "DBFile": db_file,
                "CacheDir": cache_dir,
                "RedisCacheUrl": "",
                "DisableExec": True,
                "MountList": [
                    {
                        "Type": "local",
                        "Param": mount_dir,
                        "DisplayName": "TEST",
                        "Writable": True,
                        "DisableChangeWriteTable": False,
                    }
                ],
            }
        )
        updated = mutate(
            client,
            "PUT",
            "/api/third/filebrowser/configure",
            body=candidate,
            body_supplied=True,
        )
        results["configure_put_ret_zero"] = updated.get("ret") == 0
        results["service_started"] = wait_status(client, True)
        if not results["service_started"]:
            raise RuntimeError("TEST FileBrowser service did not start")

        live, _ = get_config(client)
        mounts = live.get("MountList") or []
        results["isolated_config_readback"] = (
            str(live.get("Address")) == "127.0.0.1"
            and str(live.get("Port")) == str(port)
            and live.get("AutoFirewall") is False
            and str(live.get("DBFile")) == db_file
            and len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Type") == "local"
            and mounts[0].get("Param") == mount_dir
            and mounts[0].get("Writable") is True
        )
        observations["mount_fields"] = (
            sorted(mounts[0].keys()) if mounts and isinstance(mounts[0], dict) else []
        )

        base_url = f"http://127.0.0.1:{port}"
        root_status, _, root_body = http_request(
            "GET",
            base_url + "/",
            headers={"User-Agent": "lucky-skills-filebrowser-probe/1"},
        )
        results["http_root_reachable"] = root_status == 200 and b"<html" in root_body.lower()
        if not results["http_root_reachable"]:
            raise RuntimeError("TEST FileBrowser HTTP root is unavailable")

        login_body = json.dumps(
            {"username": TEST_LOGIN, "password": TEST_LOGIN, "recaptcha": ""}
        ).encode()
        login_status, _, raw_login = http_request(
            "POST",
            base_url + "/api/login",
            body=login_body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "lucky-skills-filebrowser-probe/1",
            },
        )
        jwt = raw_login.decode("utf-8", "replace").strip().strip('"') if login_status == 200 else ""
        results["fresh_db_default_login"] = bool(jwt)
        if not jwt:
            raise RuntimeError("fresh TEST FileBrowser database default login failed")

        resource_status, _, resource_body = http_request(
            "GET", base_url + "/api/resources/", headers=auth_headers()
        )
        results["resource_root_get"] = resource_status == 200
        root_resource = (
            json.loads(resource_body.decode("utf-8", "replace"))
            if resource_status == 200
            else {}
        )
        items = root_resource.get("items") if isinstance(root_resource, dict) else None
        observations["initial_root_item_count"] = len(items) if isinstance(items, list) else None
        results["single_local_mount_is_resource_root"] = (
            resource_status == 200 and isinstance(items, list) and len(items) == 0
        )

        target = "/" + urllib.parse.quote(filename, safe="")
        upload_status, _, _ = http_request(
            "POST",
            base_url + "/api/resources" + target + "?override=false",
            body=marker.encode(),
            headers=auth_headers({"Content-Type": "application/octet-stream"}),
        )
        observations["upload_status"] = upload_status
        results["upload_succeeded"] = upload_status == 200
        results["underlying_file_created"] = wait_child(
            client, mount_dir, filename, True
        )

        get_status_code, get_headers, get_body = http_request(
            "GET", base_url + "/api/resources" + target, headers=auth_headers()
        )
        content_type = get_headers.get("Content-Type", "").split(";", 1)[0]
        observations["file_get_status"] = get_status_code
        observations["file_get_content_type"] = content_type
        readback = False
        if get_status_code == 200:
            if content_type == "application/octet-stream":
                readback = get_body.decode("utf-8", "replace") == marker
            else:
                try:
                    payload = json.loads(get_body.decode("utf-8", "replace"))
                    readback = isinstance(payload, dict) and payload.get("content") == marker
                except (UnicodeDecodeError, json.JSONDecodeError):
                    readback = False
        results["file_content_readback"] = readback

        destination = "/" + urllib.parse.quote(renamed, safe="")
        rename_url = (
            base_url
            + "/api/resources"
            + target
            + "?action=rename&destination="
            + urllib.parse.quote(destination, safe="")
            + "&override=false&rename=false"
        )
        rename_status, _, _ = http_request("PATCH", rename_url, headers=auth_headers())
        observations["rename_status"] = rename_status
        results["rename_succeeded"] = rename_status == 200
        results["underlying_rename_visible"] = (
            wait_child(client, mount_dir, renamed, True)
            and not path_exists(client, mount_dir, filename)
        )

        delete_status_code, _, _ = http_request(
            "DELETE",
            base_url + "/api/resources/" + urllib.parse.quote(renamed, safe=""),
            headers=auth_headers(),
        )
        observations["delete_status"] = delete_status_code
        results["delete_succeeded"] = delete_status_code in {200, 204}
        results["underlying_file_removed"] = wait_child(
            client, mount_dir, renamed, False
        )

        logs = client.request_json(
            "GET",
            "/api/third/filebrowser/lastlogs",
            query={"page": 1, "pageSize": 50},
        )
        log_rows = logs.get("logs") if isinstance(logs, dict) else None
        results["lastlogs_read"] = isinstance(log_rows, (list, type(None)))
        observations["lastlog_count"] = len(log_rows) if isinstance(log_rows, list) else 0
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        try:
            live, _ = get_config(client)
            mounts = live.get("MountList") or []
            owned = (
                str(live.get("Address")) == "127.0.0.1"
                and str(live.get("Port")) == str(port)
                and str(live.get("DBFile")) == db_file
                and len(mounts) == 1
                and isinstance(mounts[0], dict)
                and mounts[0].get("Param") == mount_dir
            )
            cleanup["ownership_guard_passed"] = owned
            if owned:
                restored = mutate(
                    client,
                    "PUT",
                    "/api/third/filebrowser/configure",
                    body=baseline,
                    body_supplied=True,
                )
                cleanup["baseline_put_ret_zero"] = restored.get("ret") == 0
                wait_status(client, baseline_status, timeout=12.0)
            else:
                cleanup["baseline_put_ret_zero"] = False
        except Exception:
            cleanup["ownership_guard_passed"] = False
            cleanup["baseline_put_ret_zero"] = False

        try:
            current, current_status = get_config(client)
            cleanup["status_baseline_restored"] = current_status is baseline_status
            cleanup["config_baseline_restored"] = current == baseline
        except Exception:
            cleanup["status_baseline_restored"] = False
            cleanup["config_baseline_restored"] = False
        cleanup["test_path_removed"] = delete_path(client, test_dir)

    failed = [name for name, value in results.items() if not value]
    if failure:
        observations["failure"] = failure
        failed.append("probe_exception")
    if any(value is False for value in cleanup.values() if isinstance(value, bool)):
        failed.append("cleanup")
    return {
        "target": "Lucky FileBrowser loopback local-mount lifecycle",
        "results": results,
        "observations": observations,
        "cleanup": cleanup,
        "failed": sorted(set(failed)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        print(
            json.dumps(
                {
                    "error": "confirmation required",
                    "required_confirmation": CONFIRMATION,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2
    try:
        report = run_probe()
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
