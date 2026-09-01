#!/usr/bin/env python3
"""Runtime-verify Lucky 3.0.0 FTP behavior on a disposable CI instance.

This probe refuses to run outside GitHub Actions. It starts a fresh pinned
Lucky container and exposes the admin, FTP control and passive-data ports only
on runner loopback. Lucky itself is configured exclusively through its HTTP
API: the probe enables one disposable FTP account, mounts one owned local TEST
directory, performs a real passive FTP login/list/upload/download/delete
roundtrip, reads status/log surfaces, and restores the original stopped FTP
configuration before removing the container.

No production Lucky instance, firewall, Docker daemon inventory, DNS record or
external FTP endpoint is touched. Passwords and transferred marker bytes stay
in process memory and are never printed.
"""

from __future__ import annotations

import copy
import ftplib
import io
import json
import secrets
import shutil
import socket
import sys
import tempfile
import time
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


TEST_PREFIX = "TEST-lucky-skills-ftp-ci-"


def choose_loopback_port(exclude: set[int] | None = None) -> int:
    excluded = exclude or set()
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in excluded:
            return port
    raise ProbeError("unable to choose a distinct loopback port")


def choose_passive_range(exclude: set[int]) -> tuple[int, int]:
    """Pick ten consecutive high TCP ports that are free on runner loopback.

    Lucky 3.0.0 rejects a smaller range with
    ``TheDifferenceBetweenPassiveModeStartPortAndEndPortCannotBeLessThan9``.
    """

    for _ in range(200):
        start = 20000 + secrets.randbelow(29991)
        ports = tuple(range(start, start + 10))
        if any(port in exclude for port in ports):
            continue
        sockets: list[socket.socket] = []
        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sockets.append(sock)
            return start, start + 9
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise ProbeError("unable to choose a free ten-port FTP passive range")


def get_ftp_config(base_url: str, token: str) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener, base_url, "/api/ftpserver/configure", open_token=token
    )
    require_ret_zero(status, response, "read FTP configure")
    config = response.get("configure")
    if not isinstance(config, dict):
        raise ProbeError("FTP configure response missing configure object")
    return config


def put_ftp_config(base_url: str, token: str, config: dict[str, Any]) -> None:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        "/api/ftpserver/configure",
        method="PUT",
        payload=config,
        open_token=token,
    )
    require_ret_zero(status, response, "write FTP configure")


def get_ftp_status(base_url: str, token: str) -> bool:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener, base_url, "/api/ftpserver/status", open_token=token
    )
    require_ret_zero(status, response, "read FTP status")
    value = response.get("status")
    if not isinstance(value, bool):
        raise ProbeError("FTP status response missing boolean status")
    return value


def wait_ftp_status(base_url: str, token: str, expected: bool, timeout: int = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if get_ftp_status(base_url, token) is expected:
                return True
        except Exception:  # noqa: BLE001 - bounded readiness poll
            pass
        time.sleep(0.5)
    return False


def read_ftp_logs(base_url: str, token: str) -> tuple[bool, bool]:
    opener = urllib.request.build_opener()
    status, last_logs = json_request(
        opener,
        base_url,
        "/api/ftpserver/lastlogs?page=1&pageSize=20",
        open_token=token,
    )
    require_ret_zero(status, last_logs, "read FTP lastlogs")
    status, logs = json_request(
        opener,
        base_url,
        "/api/ftpserver/logs?page=1&pageSize=20",
        open_token=token,
    )
    require_ret_zero(status, logs, "read FTP logs")
    return isinstance(last_logs.get("lastLogs"), list), isinstance(logs.get("logs"), list)


def config_owned_by_probe(
    config: dict[str, Any], username: str, control_port: int, passive_start: int, passive_end: int
) -> bool:
    users = config.get("Users")
    return (
        config.get("Enable") is True
        and int(config.get("Port") or 0) == control_port
        and int(config.get("PassivePortStart") or 0) == passive_start
        and int(config.get("PassivePortEnd") or 0) == passive_end
        and isinstance(users, list)
        and len(users) == 1
        and isinstance(users[0], dict)
        and users[0].get("Username") == username
    )


def docker_port_is_loopback(container_name: str, port: int) -> bool:
    output = docker("port", container_name, f"{port}/tcp", timeout=30)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return bool(lines) and all(line.startswith("127.0.0.1:") for line in lines)


def ftp_roundtrip(
    control_port: int,
    username: str,
    password: str,
    host_root: Path,
    seed_name: str,
    marker: bytes,
) -> dict[str, bool]:
    results = {
        "login": False,
        "list": False,
        "upload": False,
        "download": False,
        "delete": False,
        "wrong_password_rejected": False,
    }

    bad = ftplib.FTP()
    try:
        bad.connect("127.0.0.1", control_port, timeout=10)
        try:
            bad.login(username, password + "-wrong")
        except ftplib.error_perm:
            results["wrong_password_rejected"] = True
    finally:
        try:
            bad.close()
        except Exception:  # noqa: BLE001 - cleanup only
            pass

    ftp = ftplib.FTP()
    try:
        ftp.connect("127.0.0.1", control_port, timeout=10)
        ftp.login(username, password)
        ftp.set_pasv(True)
        results["login"] = True

        entries = ftp.nlst()
        results["list"] = seed_name in {entry.rstrip("/") for entry in entries}

        filename = "probe.bin"
        ftp.storbinary(f"STOR {filename}", io.BytesIO(marker))
        backing = host_root / filename
        results["upload"] = backing.is_file() and backing.read_bytes() == marker

        received = bytearray()
        ftp.retrbinary(f"RETR {filename}", received.extend)
        results["download"] = bytes(received) == marker

        ftp.delete(filename)
        results["delete"] = not backing.exists()
        ftp.quit()
    finally:
        try:
            ftp.close()
        except Exception:  # noqa: BLE001 - cleanup only
            pass

    return results


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise ProbeError("docker and openssl are required on the GitHub runner")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-ftp-ci-{nonce}"
    admin_host_port = choose_loopback_port()
    control_port = choose_loopback_port({admin_host_port})
    passive_start, passive_end = choose_passive_range({admin_host_port, control_port})
    base_url = f"http://127.0.0.1:{admin_host_port}"
    open_token = secrets.token_hex(16)
    username = TEST_PREFIX + nonce
    password = secrets.token_urlsafe(24)
    marker = secrets.token_bytes(64)

    report: dict[str, Any] = {
        "lucky_version": "",
        "api_only_configuration": True,
        "runner_loopback_only": False,
        "baseline_stopped_empty": False,
        "configure_put": False,
        "configure_readback": False,
        "service_started": False,
        "wrong_password_rejected": False,
        "ftp_login": False,
        "ftp_list": False,
        "ftp_upload": False,
        "ftp_download": False,
        "ftp_delete": False,
        "status_read": False,
        "lastlogs_read": False,
        "logs_read": False,
        "baseline_restored": False,
        "user_readback_fields": [],
        "mount_readback_fields": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-ftp-ci-", dir=runner_temp) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        conf_dir = temp_dir / "conf"
        ftp_root = temp_dir / "ftp-root"
        conf_dir.mkdir()
        ftp_root.mkdir()
        seed_name = "seed.bin"
        (ftp_root / seed_name).write_bytes(secrets.token_bytes(32))

        pull_pinned_image()
        baseline_config: dict[str, Any] | None = None
        test_config_applied = False

        try:
            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                "bridge",
                "-p",
                f"127.0.0.1:{admin_host_port}:{ADMIN_PORT}",
                "-p",
                f"127.0.0.1:{control_port}:{control_port}",
                "-p",
                f"127.0.0.1:{passive_start}-{passive_end}:{passive_start}-{passive_end}",
                "-v",
                f"{conf_dir}:/app/conf",
                "-v",
                f"{ftp_root}:/ci/ftp-root",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            wait_for_lucky(base_url, container_name)
            report["runner_loopback_only"] = all(
                docker_port_is_loopback(container_name, port)
                for port in (
                    ADMIN_PORT,
                    control_port,
                    *range(passive_start, passive_end + 1),
                )
            )
            if not report["runner_loopback_only"]:
                raise ProbeError("disposable Lucky published a probe port outside runner loopback")

            admin_token = login_default_admin(base_url, temp_dir)
            enable_open_token(base_url, admin_token, open_token)

            opener = urllib.request.build_opener()
            status, info = json_request(opener, base_url, "/api/info", open_token=open_token)
            require_ret_zero(status, info, "read Lucky info")
            info_object = info.get("info")
            if not isinstance(info_object, dict):
                raise ProbeError("Lucky info response missing info object")
            version = str(info_object.get("Version") or "")
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {version!r}")

            baseline_config = get_ftp_config(base_url, open_token)
            baseline_users = baseline_config.get("Users")
            baseline_stopped = get_ftp_status(base_url, open_token) is False
            report["baseline_stopped_empty"] = (
                baseline_stopped
                and baseline_config.get("Enable") is False
                and baseline_users in (None, [])
            )
            if not report["baseline_stopped_empty"]:
                raise ProbeError("fresh Lucky FTP baseline was not stopped with empty users")

            candidate = copy.deepcopy(baseline_config)
            candidate.update(
                {
                    "Enable": True,
                    "Network": "tcp4",
                    "Port": control_port,
                    "PassivePortStart": passive_start,
                    "PassivePortEnd": passive_end,
                    "AutoFireWall": False,
                    "TLSRequired": 0,
                    "DisableActiveMode": True,
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
                                    "Type": "local",
                                    "Param": "/ci/ftp-root",
                                    "DisplayName": "root",
                                    "Writable": True,
                                    "DisableChangeWriteTable": False,
                                }
                            ],
                        }
                    ],
                }
            )
            put_ftp_config(base_url, open_token, candidate)
            report["configure_put"] = True
            test_config_applied = True
            report["service_started"] = wait_ftp_status(base_url, open_token, True)
            if not report["service_started"]:
                raise ProbeError("FTP service did not enter running state")

            live = get_ftp_config(base_url, open_token)
            report["configure_readback"] = config_owned_by_probe(
                live, username, control_port, passive_start, passive_end
            )
            users = live.get("Users")
            first_user = users[0] if isinstance(users, list) and users and isinstance(users[0], dict) else {}
            report["user_readback_fields"] = sorted(first_user)
            mounts = first_user.get("MountList") if isinstance(first_user, dict) else None
            first_mount = (
                mounts[0] if isinstance(mounts, list) and mounts and isinstance(mounts[0], dict) else {}
            )
            report["mount_readback_fields"] = sorted(first_mount)
            if not report["configure_readback"]:
                raise ProbeError("FTP TEST configuration readback ownership mismatch")

            rounds = ftp_roundtrip(
                control_port, username, password, ftp_root, seed_name, marker
            )
            report["wrong_password_rejected"] = rounds["wrong_password_rejected"]
            report["ftp_login"] = rounds["login"]
            report["ftp_list"] = rounds["list"]
            report["ftp_upload"] = rounds["upload"]
            report["ftp_download"] = rounds["download"]
            report["ftp_delete"] = rounds["delete"]
            report["status_read"] = get_ftp_status(base_url, open_token) is True
            report["lastlogs_read"], report["logs_read"] = read_ftp_logs(base_url, open_token)
        finally:
            if test_config_applied and baseline_config is not None:
                try:
                    live = get_ftp_config(base_url, open_token)
                    if config_owned_by_probe(
                        live, username, control_port, passive_start, passive_end
                    ):
                        put_ftp_config(base_url, open_token, baseline_config)
                        report["baseline_restored"] = (
                            wait_ftp_status(base_url, open_token, False)
                            and get_ftp_config(base_url, open_token) == baseline_config
                        )
                except Exception:  # noqa: BLE001 - container teardown remains final safety net
                    report["baseline_restored"] = False
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            cleanup_root_owned_conf(conf_dir)

    required_true = (
        "api_only_configuration",
        "runner_loopback_only",
        "baseline_stopped_empty",
        "configure_put",
        "configure_readback",
        "service_started",
        "wrong_password_rejected",
        "ftp_login",
        "ftp_list",
        "ftp_upload",
        "ftp_download",
        "ftp_delete",
        "status_read",
        "lastlogs_read",
        "logs_read",
        "baseline_restored",
    )
    failed = [key for key in required_true if report.get(key) is not True]
    if report.get("lucky_version") != EXPECTED_LUCKY_VERSION:
        failed.append("lucky_version")
    print(json.dumps({**report, "failed": failed}, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
