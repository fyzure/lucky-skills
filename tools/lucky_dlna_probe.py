#!/usr/bin/env python3
"""Runtime-verify Lucky v3 DLNA HTTP/UPnP behavior on an isolated host bridge.

The probe refuses physical/LAN interfaces. It selects only a Docker-style
``br-*`` interface that is UP + MULTICAST, has a private IPv4 address, and has
no attached veth. Lucky is then configured with one unique local TEST media
root and a random high HTTP port on that empty bridge. The probe verifies the
UPnP device description and ContentDirectory Browse action, then restores the
exact stopped baseline and removes the TEST tree.

SSDP M-SEARCH is attempted only as an observation. Linux bridge multicast
loopback may suppress a response to the host sender even while the DLNA HTTP
and SOAP control plane works, so SSDP response is not a success requirement.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-DLNA"
TEST_PREFIX = "TEST-lucky-skills-dlna-"


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
    body: Any = None,
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"allow_unsafe": True}
    if body is not None:
        kwargs["json_body"] = body
    if query is not None:
        kwargs["query"] = query
    value = client.request_json(method, path, **kwargs)
    if not isinstance(value, dict):
        raise RuntimeError(f"unexpected Lucky response for {method} {path}")
    return value


def configure(client: LuckyClient) -> dict[str, Any]:
    value = client.request_json("GET", "/api/dlnaservice/configure")
    if not isinstance(value, dict) or not isinstance(value.get("configure"), dict):
        raise RuntimeError("unexpected DLNA configure response")
    return value


def service_status(client: LuckyClient) -> bool:
    value = client.request_json("GET", "/api/dlnaservice/status")
    return bool(value.get("status")) if isinstance(value, dict) else False


def wait_status(client: LuckyClient, wanted: bool, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service_status(client) is wanted:
            return True
        time.sleep(0.2)
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
        raise RuntimeError("unexpected local path listing")
    return [row for row in rows if isinstance(row, dict)]


def path_exists(client: LuckyClient, parent: str, path: str) -> bool:
    return any(str(row.get("path") or "") == path for row in path_entries(client, parent))


def mkdir(client: LuckyClient, path: str) -> None:
    response = mutate(client, "POST", "/api/local-path-browser/mkdir", body={"path": path})
    if response.get("ret") != 0:
        raise RuntimeError("Lucky local-path mkdir failed")


def delete_path(client: LuckyClient, path: str) -> bool:
    name = path.rstrip("/").rsplit("/", 1)[-1]
    try:
        mutate(
            client,
            "DELETE",
            "/api/local-path-browser/path",
            body={"path": path, "confirmName": name},
        )
    except Exception:
        return False
    return not path_exists(client, "/tmp", path)


def empty_bridge(name: str) -> bool:
    if not name.startswith("br-"):
        return False
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show", "master", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and not result.stdout.strip()


def select_isolated_bridge(config_response: dict[str, Any]) -> tuple[str, str]:
    rows = config_response.get("netinterfaces")
    if not isinstance(rows, list):
        raise RuntimeError("DLNA configure response has no interface list")
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        flags = {str(value) for value in row.get("flags") or []}
        if not {"up", "multicast"}.issubset(flags) or not empty_bridge(name):
            continue
        for addr in row.get("addrs") or []:
            if not isinstance(addr, dict):
                continue
            raw = str(addr.get("addr") or "").split("/", 1)[0]
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if parsed.version == 4 and parsed.is_private:
                return name, raw
    raise RuntimeError(
        "no empty UP+MULTICAST Docker bridge with private IPv4; refusing DLNA probe"
    )


def free_port(ip: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ip, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def wait_tcp(ip: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection((ip, port), timeout=0.5)
        except OSError:
            time.sleep(0.15)
            continue
        sock.close()
        return True
    return False


def fetch(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            return response.status, dict(response.headers.items()), response.read(262144)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read(262144)


def ssdp_search(ip: str, timeout: float = 3.0) -> int:
    message = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.bind((ip, 0))
        sock.settimeout(0.4)
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout
        count = 0
        while time.monotonic() < deadline:
            try:
                _data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if address[0] == ip:
                count += 1
        return count
    finally:
        sock.close()


def normalize_baseline(config: dict[str, Any]) -> dict[str, Any]:
    result = {
        key: copy.deepcopy(config.get(key))
        for key in (
            "Enable",
            "ListenIP",
            "ListenPort",
            "NetInterfaceList",
            "FriendlyName",
            "DeviceUUID",
            "MountList",
        )
    }
    result["NetInterfaceList"] = result.get("NetInterfaceList") or []
    result["MountList"] = result.get("MountList") or []
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"confirmation must be exactly {CONFIRMATION}")

    client = make_client()
    baseline_response = configure(client)
    baseline = baseline_response["configure"]
    baseline_status = bool(baseline_response.get("status"))
    if baseline_status or baseline.get("Enable") or (baseline.get("MountList") or []):
        raise RuntimeError("DLNA baseline is not stopped with an empty MountList")

    interface, ip = select_isolated_bridge(baseline_response)
    nonce = secrets.token_hex(5)
    root = f"/tmp/{TEST_PREFIX}{nonce}"
    child = "album"
    friendly_name = f"{TEST_PREFIX}{nonce}"
    port = free_port(ip)

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        mkdir(client, root)
        mkdir(client, f"{root}/{child}")
        results["test_tree_created"] = path_exists(client, "/tmp", root) and path_exists(
            client, root, f"{root}/{child}"
        )

        payload = {
            "Enable": True,
            "ListenIP": ip,
            "ListenPort": port,
            "NetInterfaceList": [interface],
            "FriendlyName": friendly_name,
            "DeviceUUID": str(baseline.get("DeviceUUID") or ""),
            "MountList": [
                {
                    "Type": "local",
                    "Param": root,
                    "DisplayName": "TEST Media",
                    "Writable": False,
                    "DisableChangeWriteTable": False,
                }
            ],
        }
        saved = mutate(client, "PUT", "/api/dlnaservice/configure", body=payload)
        results["configure_put"] = saved.get("ret") == 0
        results["service_started"] = wait_status(client, True)

        live_response = configure(client)
        live = live_response["configure"]
        mounts = live.get("MountList")
        results["isolated_config_readback"] = (
            live.get("ListenIP") == ip
            and int(live.get("ListenPort") or 0) == port
            and live.get("NetInterfaceList") == [interface]
            and live.get("FriendlyName") == friendly_name
            and isinstance(mounts, list)
            and len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Type") == "local"
            and mounts[0].get("Param") == root
        )
        observations["mount_readback_fields"] = (
            sorted(mounts[0].keys()) if isinstance(mounts, list) and mounts and isinstance(mounts[0], dict) else []
        )
        results["http_listener_reachable"] = wait_tcp(ip, port)

        base_url = f"http://{ip}:{port}"
        code, headers, description = fetch(base_url + "/rootDesc.xml")
        observations["description_status"] = code
        observations["description_content_type"] = headers.get("Content-Type", "")
        results["device_description_http"] = code == 200 and bool(description)

        content_type = ""
        control_url = ""
        friendly_matches = False
        if code == 200:
            root_xml = ET.fromstring(description)
            for element in root_xml.iter():
                if element.tag.rsplit("}", 1)[-1] == "friendlyName":
                    friendly_matches = (element.text or "") == friendly_name
            for service in root_xml.iter():
                if service.tag.rsplit("}", 1)[-1] != "service":
                    continue
                values = {
                    child_node.tag.rsplit("}", 1)[-1]: child_node.text or ""
                    for child_node in list(service)
                }
                if "ContentDirectory" in values.get("serviceType", ""):
                    content_type = values.get("serviceType", "")
                    control_url = values.get("controlURL", "")
                    break
        observations["description_friendly_name_matches_config"] = friendly_matches
        results["content_directory_advertised"] = bool(content_type and control_url)

        if content_type and control_url:
            target = urllib.parse.urljoin(base_url + "/rootDesc.xml", control_url)
            soap = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:Browse xmlns:u="{content_type}">'
                "<ObjectID>0</ObjectID><BrowseFlag>BrowseDirectChildren</BrowseFlag>"
                "<Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>0</RequestedCount>"
                "<SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>"
            ).encode()
            browse_code, browse_headers, browse_body = fetch(
                target,
                method="POST",
                body=soap,
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPACTION": f'"{content_type}#Browse"',
                },
            )
            observations["browse_status"] = browse_code
            observations["browse_content_type"] = browse_headers.get("Content-Type", "")
            results["content_directory_browse"] = browse_code == 200 and b"result" in browse_body.lower()
            results["browse_exposes_test_child"] = child.encode() in browse_body

        observations["ssdp_response_count"] = ssdp_search(ip)
        observations["ssdp_host_search_observed"] = observations["ssdp_response_count"] > 0

        logs = client.request_json("GET", "/api/dlnaservice/logs", query={"page": 1, "pageSize": 100})
        log_rows = logs.get("logs") if isinstance(logs, dict) else None
        results["logs_read"] = isinstance(log_rows, list)
        observations["log_row_count"] = len(log_rows) if isinstance(log_rows, list) else 0
    finally:
        live_response = configure(client)
        live = live_response["configure"]
        mounts = live.get("MountList")
        owned = (
            live.get("FriendlyName") == friendly_name
            and live.get("ListenIP") == ip
            and int(live.get("ListenPort") or 0) == port
            and live.get("NetInterfaceList") == [interface]
            and isinstance(mounts, list)
            and len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Param") == root
        )
        cleanup["ownership_guard"] = owned
        if owned:
            restored = mutate(
                client,
                "PUT",
                "/api/dlnaservice/configure",
                body=normalize_baseline(baseline),
            )
            cleanup["restore_ret_zero"] = restored.get("ret") == 0
            cleanup["status_restored"] = wait_status(client, baseline_status)
        else:
            cleanup["restore_ret_zero"] = False
            cleanup["status_restored"] = False
        cleanup["test_tree_removed"] = delete_path(client, root)

    after = configure(client)
    after_config = after["configure"]
    baseline_normalized = normalize_baseline(baseline)
    after_normalized = normalize_baseline(after_config)
    cleanup["baseline_config_restored"] = after_normalized == baseline_normalized

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in (
        "ownership_guard",
        "restore_ret_zero",
        "status_restored",
        "test_tree_removed",
        "baseline_config_restored",
    ):
        if cleanup.get(key) is not True:
            failed.append(f"cleanup:{key}")

    report = {
        "target": "Lucky DLNA isolated HTTP and ContentDirectory behavior",
        "results": results,
        "observations": observations,
        "cleanup": cleanup,
        "failed": sorted(set(failed)),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
