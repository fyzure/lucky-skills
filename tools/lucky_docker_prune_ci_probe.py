#!/usr/bin/env python3
"""Verify Lucky 3.0.0 real Docker prune against a disposable Docker daemon.

The probe refuses non-GitHub-Actions execution. It starts a privileged
Docker-in-Docker daemon with a private Docker socket volume, then starts a
fresh pinned Lucky container that can see only that private socket. Lucky never
receives the GitHub runner's host Docker socket and therefore cannot prune the
runner daemon or any production daemon.

Inside the private daemon the probe creates uniquely named unused TEST
container/image/network/volume/build-cache resources plus a protected running
container with attached network/volume. It calls Lucky's POST /api/docker/prune
with all=true, volumes=true and verifies unused resources disappear while the
active protected resources remain. All Lucky operations use HTTP APIs.
"""

from __future__ import annotations

import json
import secrets
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
    json_request,
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    wait_for_lucky,
)
from lucky_rclone_mount_ci_probe import choose_loopback_port


DIND_IMAGE = "docker:28.0.4-dind"
BUSYBOX_IMAGE = "busybox:1.37.0"
TEST_PREFIX = "TEST-lucky-skills-prune-ci-"


def inner(dind_name: str, *args: str, timeout: int = 60) -> str:
    return docker("exec", dind_name, "docker", *args, timeout=timeout)


def wait_inner_docker(dind_name: str, timeout: int = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            output = inner(dind_name, "info", "--format", "{{.ServerVersion}}", timeout=5)
            if output.strip():
                return
        except Exception:  # noqa: BLE001 - bounded dind readiness loop
            pass
        time.sleep(0.5)
    logs = docker("logs", "--tail", "120", dind_name, timeout=30)
    raise ProbeError(f"disposable Docker daemon did not become ready; log bytes={len(logs)}")


def names(dind_name: str, kind: str, name: str) -> list[str]:
    if kind == "container":
        output = inner(
            dind_name,
            "ps",
            "-a",
            "--filter",
            f"name=^{name}$",
            "--format",
            "{{.Names}}",
        )
    elif kind == "image":
        output = inner(dind_name, "images", "-q", name)
    elif kind == "network":
        output = inner(
            dind_name,
            "network",
            "ls",
            "--filter",
            f"name=^{name}$",
            "--format",
            "{{.Name}}",
        )
    elif kind == "volume":
        output = inner(
            dind_name,
            "volume",
            "ls",
            "--filter",
            f"name=^{name}$",
            "--format",
            "{{.Name}}",
        )
    else:
        raise ProbeError(f"unsupported inner object kind: {kind}")
    return [line.strip() for line in output.splitlines() if line.strip()]


def build_cache_count(dind_name: str) -> int:
    output = inner(dind_name, "system", "df", "--format", "{{json .}}")
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(row.get("Type") or "").lower() != "build cache":
            continue
        value = row.get("TotalCount", 0)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    return 0


def configure_private_docker_host(base_url: str, token: str) -> None:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        "/api/docker/config",
        admin_token=token,
    )
    require_ret_zero(status, response, "read disposable Docker config")
    config = response.get("config")
    if not isinstance(config, dict):
        raise ProbeError("Docker config response missing config object")
    updated = dict(config)
    updated["docker_host"] = "unix:///var/run/docker.sock"
    status, saved = json_request(
        opener,
        base_url,
        "/api/docker/config",
        method="POST",
        payload=updated,
        admin_token=token,
    )
    require_ret_zero(status, saved, "configure private Docker socket")

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            check_status, check = json_request(
                opener,
                base_url,
                "/api/docker/info",
                admin_token=token,
                timeout=3,
            )
            if check_status == 200 and check.get("ret") == 0:
                return
        except Exception:  # noqa: BLE001 - Docker reconnect poll
            pass
        time.sleep(0.5)
    raise ProbeError("Lucky did not connect to the private Docker socket after API config")


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    dind_name = f"lucky-prune-dind-{nonce}"
    lucky_name = f"lucky-prune-ci-{nonce}"
    socket_volume = f"{TEST_PREFIX}{nonce}-socket"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"

    target_container = f"{TEST_PREFIX}{nonce}-stopped"
    target_image = f"test-lucky-skills-prune-{nonce}:unused"
    target_network = f"{TEST_PREFIX}{nonce}-network"
    target_volume = f"{TEST_PREFIX}{nonce}-volume"
    protected_container = f"{TEST_PREFIX}{nonce}-protected"
    protected_network = f"{TEST_PREFIX}{nonce}-protected-network"
    protected_volume = f"{TEST_PREFIX}{nonce}-protected-volume"

    report: dict[str, Any] = {
        "lucky_version": "",
        "dind_server_version": "",
        "dind_image_digest": "",
        "lucky_socket_scope": "private-dind-volume",
        "target_container_created": False,
        "target_image_created": False,
        "target_network_created": False,
        "target_volume_created": False,
        "protected_running": False,
        "build_cache_before": 0,
        "build_cache_after": 0,
        "prune_response_keys": [],
        "target_container_removed": False,
        "target_image_removed": False,
        "target_network_removed": False,
        "target_volume_removed": False,
        "build_cache_reduced": False,
        "protected_container_preserved": False,
        "protected_network_preserved": False,
        "protected_volume_preserved": False,
        "protected_image_preserved": False,
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-prune-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        build_ctx = tmp / "buildctx"
        conf_dir.mkdir()
        build_ctx.mkdir()
        (build_ctx / "Dockerfile").write_text(
            "FROM busybox:1.37.0\nRUN printf 'owned-prune-cache' > /owned-prune-cache\n",
            encoding="utf-8",
        )

        try:
            docker("pull", DIND_IMAGE, timeout=180)
            digest = docker(
                "image",
                "inspect",
                DIND_IMAGE,
                "--format",
                "{{index .RepoDigests 0}}",
                timeout=30,
            ).strip()
            report["dind_image_digest"] = digest
            docker("volume", "create", socket_volume, timeout=30)
            docker(
                "run",
                "-d",
                "--privileged",
                "--name",
                dind_name,
                "-e",
                "DOCKER_TLS_CERTDIR=",
                "-v",
                f"{socket_volume}:/var/run",
                "-v",
                f"{build_ctx}:/ci-build:ro",
                DIND_IMAGE,
                timeout=90,
            )
            wait_inner_docker(dind_name)
            report["dind_server_version"] = inner(
                dind_name, "info", "--format", "{{.ServerVersion}}"
            ).strip()

            # All fixture creation occurs in the disposable inner daemon.
            inner(dind_name, "pull", BUSYBOX_IMAGE, timeout=120)
            inner(dind_name, "network", "create", protected_network)
            inner(dind_name, "volume", "create", protected_volume)
            inner(
                dind_name,
                "run",
                "-d",
                "--name",
                protected_container,
                "--network",
                protected_network,
                "-v",
                f"{protected_volume}:/data",
                BUSYBOX_IMAGE,
                "sleep",
                "300",
            )
            report["protected_running"] = protected_container in names(
                dind_name, "container", protected_container
            )

            inner(
                dind_name,
                "create",
                "--name",
                target_container,
                BUSYBOX_IMAGE,
                "true",
            )
            report["target_container_created"] = target_container in names(
                dind_name, "container", target_container
            )
            inner(dind_name, "network", "create", target_network)
            report["target_network_created"] = target_network in names(
                dind_name, "network", target_network
            )
            inner(dind_name, "volume", "create", target_volume)
            report["target_volume_created"] = target_volume in names(
                dind_name, "volume", target_volume
            )
            inner(
                dind_name,
                "build",
                "--tag",
                target_image,
                "/ci-build",
                timeout=180,
            )
            report["target_image_created"] = bool(names(dind_name, "image", target_image))
            report["build_cache_before"] = build_cache_count(dind_name)

            # Lucky sees only the named-volume socket of the inner daemon. The
            # host runner Docker socket is never mounted into Lucky.
            docker(
                "run",
                "-d",
                "--name",
                lucky_name,
                "--network",
                "bridge",
                "-p",
                f"127.0.0.1:{host_port}:{ADMIN_PORT}",
                "-v",
                f"{socket_volume}:/var/run",
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            wait_for_lucky(base_url, lucky_name)
            token = login_default_admin(base_url, tmp)
            status, info = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/info",
                admin_token=token,
            )
            require_ret_zero(status, info, "read Lucky info")
            info_obj = info.get("info")
            version = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {version!r}")

            configure_private_docker_host(base_url, token)

            # Prove Lucky is connected to the private daemon before pruning.
            status, docker_info = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/docker/info",
                admin_token=token,
            )
            require_ret_zero(status, docker_info, "read private Docker info through Lucky")

            status, prune = json_request(
                urllib.request.build_opener(),
                base_url,
                "/api/docker/prune",
                method="POST",
                payload={"all": True, "volumes": True},
                admin_token=token,
                timeout=90,
            )
            require_ret_zero(status, prune, "real disposable Docker prune")
            report["prune_response_keys"] = sorted(prune.keys())

            report["target_container_removed"] = not names(
                dind_name, "container", target_container
            )
            report["target_image_removed"] = not names(dind_name, "image", target_image)
            report["target_network_removed"] = not names(
                dind_name, "network", target_network
            )
            report["target_volume_removed"] = not names(dind_name, "volume", target_volume)
            report["build_cache_after"] = build_cache_count(dind_name)
            report["build_cache_reduced"] = (
                report["build_cache_before"] > 0
                and report["build_cache_after"] < report["build_cache_before"]
            )

            report["protected_container_preserved"] = protected_container in names(
                dind_name, "container", protected_container
            )
            report["protected_network_preserved"] = protected_network in names(
                dind_name, "network", protected_network
            )
            report["protected_volume_preserved"] = protected_volume in names(
                dind_name, "volume", protected_volume
            )
            report["protected_image_preserved"] = bool(
                names(dind_name, "image", BUSYBOX_IMAGE)
            )

            required_true = (
                "target_container_created",
                "target_image_created",
                "target_network_created",
                "target_volume_created",
                "protected_running",
                "target_container_removed",
                "target_image_removed",
                "target_network_removed",
                "target_volume_removed",
                "build_cache_reduced",
                "protected_container_preserved",
                "protected_network_preserved",
                "protected_volume_preserved",
                "protected_image_preserved",
            )
            failed = [name for name in required_true if report.get(name) is not True]
            report["failed"] = failed
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 1 if failed else 0
        finally:
            try:
                docker("rm", "-f", lucky_name, timeout=45)
            except Exception:
                pass
            try:
                docker("rm", "-f", dind_name, timeout=45)
            except Exception:
                pass
            try:
                docker("volume", "rm", "-f", socket_volume, timeout=30)
            except Exception:
                pass
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
