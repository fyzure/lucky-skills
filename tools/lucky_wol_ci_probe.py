#!/usr/bin/env python3
"""Runtime-verify Lucky 3.0.0 Wake-on-LAN on an isolated CI network.

The probe refuses to run outside GitHub Actions. It starts a fresh pinned Lucky
container on a Docker ``--internal`` bridge, creates one disposable WOL device
through Lucky's HTTP API, and points that device at a UDP receiver bound only to
the internal bridge gateway. A real wakeup API call must produce the standard
magic packet for a locally administered TEST MAC. The device is then deleted
through the API and the whole disposable network/container is removed.

No production Lucky instance, physical NIC, real machine, shutdown endpoint or
host firewall is touched. The generated MAC and captured packet bytes are never
printed or persisted in repository evidence.
"""

from __future__ import annotations

import json
import ipaddress
import secrets
import shutil
import socket
import sys
import tempfile
import time
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
    enable_open_token,
    json_request,
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    run,
    wait_for_lucky,
)


TEST_PREFIX = "TEST-lucky-skills-wol-ci-"


def network_addresses(network_name: str) -> tuple[str, str]:
    raw = docker("network", "inspect", network_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker network inspect response")
    configs = rows[0].get("IPAM", {}).get("Config", [])
    if not isinstance(configs, list):
        raise ProbeError("Docker network inspect missing IPAM config")
    for config in configs:
        if (
            isinstance(config, dict)
            and isinstance(config.get("Gateway"), str)
            and isinstance(config.get("Subnet"), str)
        ):
            gateway = config["Gateway"]
            try:
                network = ipaddress.ip_network(config["Subnet"], strict=False)
                gateway_ip = ipaddress.ip_address(gateway)
            except ValueError as exc:
                raise ProbeError("Docker internal bridge IPAM values are invalid") from exc
            if isinstance(network, ipaddress.IPv4Network) and gateway_ip in network and network.is_private:
                return gateway, str(network.broadcast_address)
    raise ProbeError("Docker internal bridge did not expose a private IPv4 subnet/gateway")


def receive_magic_packet(
    capture: socket.socket,
    expected_packet: bytes,
    destination_port: int,
    timeout: float = 10.0,
) -> bytes:
    deadline = time.time() + timeout
    while time.time() < deadline:
        capture.settimeout(max(0.1, deadline - time.time()))
        try:
            frame = capture.recv(65535)
        except socket.timeout:
            break
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            continue
        ip_start = 14
        ihl = (frame[ip_start] & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_start + ihl + 8:
            continue
        if frame[ip_start + 9] != 17:
            continue
        udp_start = ip_start + ihl
        udp_destination = int.from_bytes(frame[udp_start + 2 : udp_start + 4], "big")
        udp_length = int.from_bytes(frame[udp_start + 4 : udp_start + 6], "big")
        if udp_destination != destination_port or udp_length < 8:
            continue
        payload = frame[udp_start + 8 : udp_start + udp_length]
        if payload == expected_packet:
            return payload
    return b""


def container_ipv4(container_name: str, network_name: str) -> str:
    raw = docker("inspect", container_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    networks = rows[0].get("NetworkSettings", {}).get("Networks", {})
    item = networks.get(network_name) if isinstance(networks, dict) else None
    value = item.get("IPAddress") if isinstance(item, dict) else None
    if not isinstance(value, str) or not value:
        raise ProbeError("temporary Lucky container has no internal-network IPv4")
    try:
        socket.inet_aton(value)
    except OSError as exc:
        raise ProbeError("temporary Lucky internal address is not IPv4") from exc
    return value


def admin_port_is_unpublished(container_name: str) -> bool:
    raw = docker("inspect", container_name, timeout=30)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError("unexpected Docker container inspect response")
    bindings = rows[0].get("HostConfig", {}).get("PortBindings", {})
    if not isinstance(bindings, dict):
        raise ProbeError("Docker inspect missing HostConfig.PortBindings")
    return not bindings.get(f"{ADMIN_PORT}/tcp")


def api_json(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        path,
        method=method,
        payload=payload,
        open_token=token,
        timeout=30,
    )
    return require_ret_zero(status, response, f"{method} {path}")


def get_devices(base_url: str, token: str) -> list[dict[str, Any]]:
    response = api_json(base_url, token, "/api/wol/devices")
    rows = response.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("WOL devices response has unexpected list shape")
    return rows


def device_key(row: dict[str, Any]) -> str:
    value = row.get("Key")
    return value if isinstance(value, str) else ""


def test_mac() -> tuple[str, bytes]:
    tail = secrets.token_bytes(3)
    raw = bytes((0x02, 0x00, 0x00)) + tail
    text = ":".join(f"{byte:02x}" for byte in raw)
    return text, raw


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise ProbeError("docker and openssl are required on the GitHub runner")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-wol-ci-{nonce}"
    network_name = f"lucky-wol-ci-{nonce}"
    bridge_name = f"lwol-{nonce[:8]}"
    open_token = secrets.token_hex(16)
    device_name = TEST_PREFIX + nonce
    mac_text, mac_bytes = test_mac()
    expected_packet = b"\xff" * 6 + mac_bytes * 16

    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_lucky_operations": True,
        "network_internal": False,
        "capture_bridge_only": False,
        "admin_port_unpublished": False,
        "admin_reachable_on_internal_bridge": False,
        "baseline_empty": False,
        "device_created": False,
        "broadcast_ip_item_is_string": False,
        "wakeup_ret_zero": False,
        "magic_packet_received": False,
        "magic_packet_exact": False,
        "magic_packet_size": 0,
        "device_deleted": False,
        "baseline_restored": False,
        "shutdown_exercised": False,
    }

    with tempfile.TemporaryDirectory(prefix="lucky-wol-ci-", dir=runner_temp) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        conf_dir = temp_dir / "conf"
        conf_dir.mkdir()

        pull_pinned_image()
        run(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--opt",
                f"com.docker.network.bridge.name={bridge_name}",
                network_name,
            ],
            timeout=45,
        )
        created_key = ""
        capture: socket.socket | None = None

        try:
            gateway, broadcast = network_addresses(network_name)
            report["network_internal"] = True
            wol_port = 20000 + secrets.randbelow(30000)
            if not hasattr(socket, "AF_PACKET"):
                raise ProbeError("runner Python lacks AF_PACKET support")
            capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            capture.bind((bridge_name, 0))
            report["capture_bridge_only"] = True

            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                network_name,
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            lucky_ip = container_ipv4(container_name, network_name)
            base_url = f"http://{lucky_ip}:{ADMIN_PORT}"
            wait_for_lucky(base_url, container_name)
            report["admin_port_unpublished"] = admin_port_is_unpublished(container_name)
            report["admin_reachable_on_internal_bridge"] = True
            if not report["admin_port_unpublished"]:
                raise ProbeError("temporary Lucky admin port was unexpectedly published")

            admin_token = login_default_admin(base_url, temp_dir)
            enable_open_token(base_url, admin_token, open_token)
            info = api_json(base_url, open_token, "/api/info")
            info_object = info.get("info")
            if not isinstance(info_object, dict):
                raise ProbeError("Lucky info response missing info object")
            version = str(info_object.get("Version") or "")
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {version!r}")

            baseline_keys = {device_key(row) for row in get_devices(base_url, open_token) if device_key(row)}
            report["baseline_empty"] = not baseline_keys
            if not report["baseline_empty"]:
                raise ProbeError("fresh Lucky WOL device baseline was not empty")

            payload = {
                "Key": "",
                "DeviceName": device_name,
                "MacList": [mac_text],
                "BroadcastIPs": [broadcast],
                "ProbeTargets": [],
                "Port": wol_port,
                "Relay": False,
                "Repeat": 1,
                "IOT_DianDeng_Enable": False,
                "IOT_DianDeng_AUTHKEY": "",
                "IOT_DianDeng_InsecureSkipVerify": False,
                "IOT_DianDengBindComponentEnable": False,
                "IOT_DianDengBindComponent": "",
                "IOT_Bemfa_Enable": False,
                "IOT_Bemfa_SecretKey": "",
                "IOT_Bemfa_Topic": "",
                "IOT_Bemfa_InsecureSkipVerify": False,
            }
            api_json(base_url, open_token, "/api/wol/device", method="POST", payload=payload)

            matches = [
                row
                for row in get_devices(base_url, open_token)
                if row.get("DeviceName") == device_name and row.get("MacList") == [mac_text]
            ]
            if len(matches) != 1:
                raise ProbeError(f"expected exactly one disposable WOL device, got {len(matches)}")
            created_key = device_key(matches[0])
            if not created_key or created_key in baseline_keys:
                raise ProbeError("disposable WOL device did not receive a unique Key")
            report["device_created"] = True
            broadcast_ips = matches[0].get("BroadcastIPs")
            report["broadcast_ip_item_is_string"] = (
                isinstance(broadcast_ips, list)
                and len(broadcast_ips) == 1
                and isinstance(broadcast_ips[0], str)
            )

            query = urllib.parse.urlencode({"key": created_key})
            wake = api_json(base_url, open_token, f"/api/wol/device/wakeup?{query}")
            report["wakeup_ret_zero"] = wake.get("ret") == 0

            packet = receive_magic_packet(capture, expected_packet, wol_port)
            report["magic_packet_received"] = bool(packet)
            report["magic_packet_size"] = len(packet)
            report["magic_packet_exact"] = packet == expected_packet

            delete_query = urllib.parse.urlencode({"key": created_key})
            api_json(base_url, open_token, f"/api/wol/device?{delete_query}", method="DELETE")
            created_key = ""
            report["device_deleted"] = True
            final_keys = {device_key(row) for row in get_devices(base_url, open_token) if device_key(row)}
            report["baseline_restored"] = final_keys == baseline_keys
        finally:
            if created_key:
                query = urllib.parse.urlencode({"key": created_key})
                try:
                    api_json(base_url, open_token, f"/api/wol/device?{query}", method="DELETE")
                except Exception:  # noqa: BLE001 - disposable container teardown is final safety net
                    pass
            if capture is not None:
                capture.close()
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            run(["docker", "network", "rm", network_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "api_only_lucky_operations",
        "network_internal",
        "capture_bridge_only",
        "admin_port_unpublished",
        "admin_reachable_on_internal_bridge",
        "baseline_empty",
        "device_created",
        "broadcast_ip_item_is_string",
        "wakeup_ret_zero",
        "magic_packet_received",
        "magic_packet_exact",
        "device_deleted",
        "baseline_restored",
    )
    failed = [key for key in required_true if report.get(key) is not True]
    if report.get("lucky_version") != EXPECTED_LUCKY_VERSION:
        failed.append("lucky_version")
    if report.get("shutdown_exercised") is not False:
        failed.append("shutdown_exercised")
    print(json.dumps({**report, "failed": failed}, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
