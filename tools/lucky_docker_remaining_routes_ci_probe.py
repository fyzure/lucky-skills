#!/usr/bin/env python3
"""Close the last Docker route-evidence gaps on a private DinD fixture.

This probe runs only in GitHub Actions.  It starts a disposable Docker-in-
Docker daemon whose Unix socket is exposed only through a named volume to a
fresh pinned Lucky 3.0.0 container.  Lucky never receives the GitHub runner's
Docker socket.  The private daemon contains one owned, network-none BusyBox
container and one random marker file.

The probe exercises exactly two read-only frontend routes that return 404 on a
fresh Lucky without a Docker backend:

* GET /api/docker/containers/{id}/files/download?path=<owned file>
* GET /api/docker/containers/{id}/upgrade-check

The first must return non-empty binary data for the owned marker file.  The
second must reach a registered handler with the real owned container ID; any
non-404/non-405 application result is sufficient because registry/update
availability is not part of this route-existence assertion.  No upgrade is
performed.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import urllib.error
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
    json_request,
    login_default_admin,
    pull_pinned_image,
    require_github_hosted_runner,
    require_ret_zero,
    wait_for_lucky,
)
from lucky_docker_prune_ci_probe import (
    BUSYBOX_IMAGE,
    DIND_IMAGE,
    configure_private_docker_host,
    inner,
    wait_inner_docker,
)
from lucky_rclone_mount_ci_probe import choose_loopback_port


TEST_PREFIX = "TEST-lucky-skills-docker-remaining-ci-"
MAX_BODY = 8 * 1024 * 1024


def raw_request(
    base_url: str,
    path: str,
    *,
    admin_token: str,
    accept: str = "*/*",
    timeout: int = 30,
) -> tuple[int, dict[str, str], bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        base_url + path,
        headers={
            "Accept": accept,
            "Lucky-Admin-Token": admin_token,
            "Authorization": f"Bearer {admin_token}",
            "User-Agent": "lucky-skills-docker-remaining-ci/1",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        headers = {key.lower(): value for key, value in error.headers.items()}
        body = error.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ProbeError(f"response too large for GET {path}")
    return status, headers, body


def parse_json_body(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    dind_name = f"lucky-docker-remaining-dind-{nonce}"
    lucky_name = f"lucky-docker-remaining-{nonce}"
    socket_volume = f"{TEST_PREFIX}{nonce}-socket"
    owned_container = f"{TEST_PREFIX}{nonce}-container"
    marker_path = f"/tmp/{TEST_PREFIX}{nonce}.txt"
    marker = f"{TEST_PREFIX}{nonce}-marker".encode("utf-8")
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"

    report: dict[str, Any] = {
        "schema_version": 1,
        "target": {"product": "Lucky", "version": EXPECTED_LUCKY_VERSION},
        "pinned_image": PINNED_LUCKY_IMAGE,
        "docker_scope": "private-dind-volume",
        "owned_container_visible": False,
        "files_download": {},
        "upgrade_check": {},
        "failed": [],
    }

    with tempfile.TemporaryDirectory(prefix="lucky-docker-remaining-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        conf_dir.mkdir()
        try:
            docker("pull", DIND_IMAGE, timeout=180)
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
                DIND_IMAGE,
                timeout=90,
            )
            wait_inner_docker(dind_name)
            inner(dind_name, "pull", BUSYBOX_IMAGE, timeout=120)
            inner(
                dind_name,
                "run",
                "-d",
                "--name",
                owned_container,
                "--network",
                "none",
                BUSYBOX_IMAGE,
                "sleep",
                "300",
            )
            inner(
                dind_name,
                "exec",
                owned_container,
                "/bin/sh",
                "-c",
                "printf '%s' \"$1\" > \"$2\"",
                "sh",
                marker.decode("utf-8"),
                marker_path,
            )
            container_id = inner(
                dind_name,
                "inspect",
                "--format",
                "{{.Id}}",
                owned_container,
            ).strip()
            if not container_id:
                raise ProbeError("owned DinD container has no ID")

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
                urllib.request.build_opener(urllib.request.ProxyHandler({})),
                base_url,
                "/api/info",
                admin_token=token,
            )
            require_ret_zero(status, info, "read Lucky info")
            info_obj = info.get("info")
            version = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {version!r}")
            configure_private_docker_host(base_url, token)

            status, containers = json_request(
                urllib.request.build_opener(urllib.request.ProxyHandler({})),
                base_url,
                "/api/docker/containers?all=true",
                admin_token=token,
            )
            require_ret_zero(status, containers, "list private DinD containers")
            report["owned_container_visible"] = owned_container in json.dumps(
                containers, ensure_ascii=False
            )

            encoded_path = urllib.parse.quote(marker_path, safe="")
            download_status, download_headers, download_body = raw_request(
                base_url,
                f"/api/docker/containers/{container_id}/files/download?path={encoded_path}",
                admin_token=token,
            )
            download_json = parse_json_body(download_body)
            report["files_download"] = {
                "status": download_status,
                "content_type": download_headers.get("content-type", ""),
                "content_disposition_present": bool(download_headers.get("content-disposition")),
                "body_nonempty": bool(download_body),
                "json_ret": download_json.get("ret") if download_json else None,
                "marker_present": marker in download_body,
            }

            upgrade_status, upgrade_headers, upgrade_body = raw_request(
                base_url,
                f"/api/docker/containers/{container_id}/upgrade-check",
                admin_token=token,
                accept="application/json",
                timeout=45,
            )
            upgrade_json = parse_json_body(upgrade_body)
            report["upgrade_check"] = {
                "status": upgrade_status,
                "content_type": upgrade_headers.get("content-type", ""),
                "json": upgrade_json is not None,
                "ret": upgrade_json.get("ret") if upgrade_json else None,
                "response_keys": sorted(upgrade_json) if upgrade_json else [],
            }

            failed: list[str] = []
            if report["owned_container_visible"] is not True:
                failed.append("owned_container_visible")
            if download_status in {404, 405} or not download_body:
                failed.append("files_download_route")
            if download_json is not None and download_json.get("ret") == -1:
                failed.append("files_download_auth")
            if upgrade_status in {404, 405}:
                failed.append("upgrade_check_route")
            if upgrade_json is None:
                failed.append("upgrade_check_json")
            report["failed"] = failed
            print("DOCKER_REMAINING_REPORT=" + json.dumps(report, ensure_ascii=False, sort_keys=True))
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
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False))
        raise SystemExit(2)
