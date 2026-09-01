#!/usr/bin/env python3
"""Runtime-verify a bounded Lucky Docker Compose lifecycle.

The probe reuses an already-present ``gdy666/lucky:v3`` image and creates two
uniquely named TEST projects/containers under Lucky's own ``/tmp`` namespace.
The compose services use ``network_mode: none``, publish no ports, declare no
volumes, and do not build or pull an image. One fresh project verifies the
legacy synchronous up/down handlers. A separate project follows the current UI
flow: async up/task status, ps/config/logs, async stop, synchronous start and
restart, then async down. Both projects are removed before resource baselines
are checked.

Completed Docker task history has different semantics from active-task cancel:
``DELETE /api/docker/tasks/{id}`` cannot remove an already completed task.  This
probe therefore refuses to start unless the Docker task baseline is empty, and
uses the global completed-task clear endpoint only when the current task-ID set
exactly equals the IDs returned to this probe.  It never invokes Docker prune.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
from tools.lucky_cron_probe import delete_path, mkdir, mutate  # noqa: E402


CONFIRMATION = "PROBE-AND-CLEAN-DOCKER-COMPOSE"
PROJECT_PREFIX = "test-lucky-skills-compose-"
PATH_PREFIX = "TEST-lucky-skills-compose-"
PROBE_IMAGE = "gdy666/lucky:v3"
TERMINAL_TASK_STATES = {"success", "failed", "cancelled"}


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
        timeout=30,
    )


def rows(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise RuntimeError(f"unexpected Lucky response while reading {key}")
    raw = value.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RuntimeError(f"unexpected {key} response type")
    return [item for item in raw if isinstance(item, dict)]


def projects(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(client.request_json("GET", "/api/docker/compose/projects"), "projects")


def containers(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(
        client.request_json(
            "GET",
            "/api/docker/containers",
            query={
                "all": "true",
                "includeNetworkMode": "true",
                "includeStats": "false",
            },
        ),
        "containers",
    )


def tasks(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(client.request_json("GET", "/api/docker/tasks"), "tasks")


def images(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(
        client.request_json("GET", "/api/docker/images", query={"all": "true"}),
        "images",
    )


def networks(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(client.request_json("GET", "/api/docker/networks"), "networks")


def volumes(client: LuckyClient) -> list[dict[str, Any]]:
    return rows(client.request_json("GET", "/api/docker/volumes"), "volumes")


def container_names(row: dict[str, Any]) -> list[str]:
    names = row.get("Names")
    if not isinstance(names, list):
        return []
    return [str(value).lstrip("/") for value in names]


def task_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("ID") or "")


def response_task_id(value: dict[str, Any]) -> str:
    return str(value.get("task_id") or value.get("taskId") or "")


def project_identity(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("name") or ""), str(row.get("path") or "")


def container_identity(row: dict[str, Any]) -> str:
    return str(row.get("Id") or row.get("ID") or "")


def image_identity(row: dict[str, Any]) -> str:
    return str(row.get("Id") or row.get("ID") or "")


def network_identity(row: dict[str, Any]) -> str:
    return str(row.get("Id") or row.get("ID") or row.get("Name") or "")


def volume_identity(row: dict[str, Any]) -> str:
    return str(row.get("Name") or "")


def identity_set(items: list[dict[str, Any]], fn: Any) -> set[str] | set[tuple[str, str]]:
    return {value for item in items if (value := fn(item))}


def find_project(client: LuckyClient, project_name: str) -> dict[str, Any] | None:
    return next(
        (
            row
            for row in projects(client)
            if str(row.get("name") or "") == project_name
        ),
        None,
    )


def find_container(client: LuckyClient, container_name: str) -> dict[str, Any] | None:
    return next(
        (row for row in containers(client) if container_name in container_names(row)),
        None,
    )


def wait_project(
    client: LuckyClient,
    project_name: str,
    *,
    running: bool,
    timeout: float = 35.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = find_project(client, project_name)
        if last is not None:
            running_count = int(last.get("runningContainers") or 0)
            if running and running_count >= 1:
                return last
            if not running and running_count == 0:
                return last
        time.sleep(0.4)
    safe = None
    if last is not None:
        safe = {
            key: last.get(key)
            for key in ("status", "containers", "runningContainers", "stoppedContainers")
        }
    raise RuntimeError(f"TEST Compose project state timeout: {safe}")


def wait_task(
    client: LuckyClient,
    identifier: str,
    *,
    timeout: float = 90.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        value = client.request_json(
            "GET",
            f"/api/docker/tasks/{quote(identifier, safe='')}",
        )
        task = value.get("task") if isinstance(value, dict) else None
        if isinstance(task, dict):
            last = task
            status = str(task.get("status") or "").lower()
            if status in TERMINAL_TASK_STATES:
                return task
        time.sleep(0.4)
    raise RuntimeError(
        f"TEST Docker task timeout; last_status={str(last.get('status') or '')}"
    )


def task_success(task: dict[str, Any]) -> bool:
    return str(task.get("status") or "").lower() == "success"


def compose_yaml(container_name: str) -> str:
    return (
        "services:\n"
        "  probe:\n"
        f"    image: {PROBE_IMAGE}\n"
        f"    container_name: {container_name}\n"
        "    network_mode: none\n"
        '    restart: "no"\n'
    )


def run_probe() -> dict[str, Any]:
    client = make_client()
    suffix = secrets.token_hex(5)
    project_name = f"{PROJECT_PREFIX}{suffix}"
    container_name = project_name
    project_path = f"/tmp/{PATH_PREFIX}{suffix}"
    sync_project_name = f"{PROJECT_PREFIX}sync-{suffix}"
    sync_container_name = sync_project_name
    sync_project_path = f"/tmp/{PATH_PREFIX}sync-{suffix}"
    config_name = "compose.yml"
    content = compose_yaml(container_name)
    sync_content = compose_yaml(sync_container_name)

    baseline_projects = identity_set(projects(client), project_identity)
    baseline_containers = identity_set(containers(client), container_identity)
    baseline_tasks = identity_set(tasks(client), task_id)
    baseline_images = identity_set(images(client), image_identity)
    baseline_networks = identity_set(networks(client), network_identity)
    baseline_volumes = identity_set(volumes(client), volume_identity)

    if baseline_tasks:
        raise RuntimeError(
            "Docker task baseline is non-empty; refusing because completed-task cleanup would not be ownership-safe"
        )
    if any(str(row.get("name") or "").startswith(PROJECT_PREFIX) for row in projects(client)):
        raise RuntimeError("pre-existing TEST Compose project found")
    if any(
        any(name.startswith(PROJECT_PREFIX) for name in container_names(row))
        for row in containers(client)
    ):
        raise RuntimeError("pre-existing TEST Compose container found")
    if not any(
        PROBE_IMAGE in (row.get("RepoTags") or [])
        for row in images(client)
        if isinstance(row.get("RepoTags"), list)
    ):
        raise RuntimeError(
            f"required pre-existing image {PROBE_IMAGE!r} is absent; refusing to pull/build for this probe"
        )

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_project_count": len(baseline_projects),
        "baseline_container_count": len(baseline_containers),
        "baseline_task_count": len(baseline_tasks),
        "baseline_image_count": len(baseline_images),
        "baseline_network_count": len(baseline_networks),
        "baseline_volume_count": len(baseline_volumes),
        "probe_image_preexisting": True,
        "network_mode": "none",
        "published_ports": False,
        "declared_volumes": False,
        "build_or_pull_requested": False,
    }
    cleanup: dict[str, Any] = {}
    created_task_ids: list[str] = []
    failure: str | None = None

    project_request = {
        "project_name": project_name,
        "project_path": project_path,
        "config_file_name": config_name,
    }
    sync_project_request = {
        "project_name": sync_project_name,
        "project_path": sync_project_path,
        "config_file_name": config_name,
    }

    try:
        mkdir(client, sync_project_path)
        results["sync_test_path_created"] = True

        sync_up = mutate(
            client,
            "POST",
            "/api/docker/compose/up",
            body={
                **sync_project_request,
                "working_dir": sync_project_path,
                "compose_content": sync_content,
                "force_recreate": False,
                "build": False,
            },
            body_supplied=True,
        )
        results["sync_up_created"] = sync_up.get("ret") == 0
        wait_project(client, sync_project_name, running=True)
        results["sync_project_running"] = True
        sync_container = find_container(client, sync_container_name)
        results["sync_container_present"] = sync_container is not None
        if sync_container is None:
            raise RuntimeError("synchronous Compose up did not create the TEST container")
        results["sync_container_network_isolated"] = (
            str(sync_container.get("network_mode") or "") == "none"
        )
        results["sync_container_has_no_published_ports"] = (
            len(sync_container.get("Ports") or []) == 0
        )

        sync_down = mutate(
            client,
            "POST",
            "/api/docker/compose/down",
            body={**sync_project_request, "remove_volumes": False},
            body_supplied=True,
        )
        results["sync_down"] = sync_down.get("ret") == 0
        time.sleep(0.4)
        results["sync_container_absent_after_down"] = (
            find_container(client, sync_container_name) is None
        )

        mkdir(client, project_path)
        results["async_test_path_created"] = True

        up = mutate(
            client,
            "POST",
            "/api/docker/compose/up-async",
            body={
                "project_name": project_name,
                "working_dir": project_path,
                "compose_content": content,
                "config_file_name": config_name,
                "force_recreate": False,
                "build": False,
            },
            body_supplied=True,
        )
        up_task_id = response_task_id(up)
        results["up_async_dispatched"] = up.get("ret") == 0 and bool(up_task_id)
        if not up_task_id:
            raise RuntimeError("Compose up-async returned no task_id")
        created_task_ids.append(up_task_id)
        up_task = wait_task(client, up_task_id)
        results["up_async_task_success"] = task_success(up_task)
        observations["task_fields"] = sorted(up_task.keys())
        observations["up_task_type"] = str(up_task.get("type") or "")
        if not task_success(up_task):
            raise RuntimeError("Compose up-async TEST task failed")

        project = wait_project(client, project_name, running=True)
        results["project_running"] = True
        observations["project_fields"] = sorted(project.keys())
        observations["project_state"] = {
            key: project.get(key)
            for key in ("status", "containers", "runningContainers", "stoppedContainers")
        }

        container = find_container(client, container_name)
        results["container_present"] = container is not None
        if container is None:
            raise RuntimeError("Compose project is running but TEST container was not found")
        observations["container_network_mode"] = str(container.get("network_mode") or "")
        observations["container_port_count"] = len(container.get("Ports") or [])
        observations["container_mount_count"] = len(container.get("Mounts") or [])
        results["container_network_isolated"] = str(container.get("network_mode") or "") == "none"
        results["container_has_no_published_ports"] = len(container.get("Ports") or []) == 0

        ps = client.request_json(
            "GET",
            f"/api/docker/compose/{project_name}/ps",
            query={"path": project_path, "name": project_name},
        )
        ps_rows = rows(ps, "containers")
        results["ps_read"] = ps.get("ret") == 0 and len(ps_rows) == 1
        observations["ps_fields"] = sorted(ps_rows[0].keys()) if ps_rows else []

        config = mutate(
            client,
            "POST",
            "/api/docker/compose/config",
            body={"project_path": project_path},
            body_supplied=True,
        )
        results["config_read"] = config.get("ret") == 0 and bool(config.get("content"))
        observations["config_response_fields"] = sorted(config.keys())
        observations["config_filename_matches"] = str(config.get("filename") or "") == config_name

        logs = mutate(
            client,
            "POST",
            f"/api/docker/compose/{project_name}/logs",
            body={
                "project_name": project_name,
                "project_path": project_path,
                "services": ["probe"],
                "tail": "20",
                "timestamps": False,
                "follow": False,
            },
            body_supplied=True,
        )
        results["logs_read"] = logs.get("ret") == 0 and isinstance(logs.get("logs"), list)
        observations["log_row_count"] = len(logs.get("logs") or [])

        stop = mutate(
            client,
            "POST",
            "/api/docker/compose/stop-async",
            body=project_request,
            body_supplied=True,
        )
        stop_task_id = response_task_id(stop)
        results["stop_async_dispatched"] = stop.get("ret") == 0 and bool(stop_task_id)
        if not stop_task_id:
            raise RuntimeError("Compose stop-async returned no task_id")
        created_task_ids.append(stop_task_id)
        stop_task = wait_task(client, stop_task_id)
        results["stop_async_task_success"] = task_success(stop_task)
        observations["stop_task_type"] = str(stop_task.get("type") or "")
        if not task_success(stop_task):
            raise RuntimeError("Compose stop-async TEST task failed")
        wait_project(client, project_name, running=False)
        results["project_stopped"] = True

        start = mutate(
            client,
            "POST",
            "/api/docker/compose/start",
            body=project_request,
            body_supplied=True,
        )
        results["sync_start"] = start.get("ret") == 0
        wait_project(client, project_name, running=True)
        results["project_started"] = True

        restart = mutate(
            client,
            "POST",
            "/api/docker/compose/restart",
            body=project_request,
            body_supplied=True,
        )
        results["sync_restart"] = restart.get("ret") == 0
        wait_project(client, project_name, running=True)
        results["project_restarted"] = True

        down = mutate(
            client,
            "POST",
            "/api/docker/compose/down-async",
            body={**project_request, "remove_volumes": False},
            body_supplied=True,
        )
        down_task_id = response_task_id(down)
        results["down_async_dispatched"] = down.get("ret") == 0 and bool(down_task_id)
        if not down_task_id:
            raise RuntimeError("Compose down-async returned no task_id")
        created_task_ids.append(down_task_id)
        down_task = wait_task(client, down_task_id)
        results["down_async_task_success"] = task_success(down_task)
        observations["down_task_type"] = str(down_task.get("type") or "")
        if not task_success(down_task):
            raise RuntimeError("Compose down-async TEST task failed")
        time.sleep(0.5)
        results["container_absent_after_down"] = find_container(client, container_name) is None
    except Exception as error:  # cleanup still runs before reporting failure
        failure = f"{type(error).__name__}: {error}"
    finally:
        # Cancel only this probe's still-active async tasks. Completed history is
        # handled by the exact-ID global-clear gate below.
        for identifier in created_task_ids:
            try:
                detail = client.request_json(
                    "GET",
                    f"/api/docker/tasks/{quote(identifier, safe='')}",
                )
                task = detail.get("task") if isinstance(detail, dict) else None
                status = str(task.get("status") or "").lower() if isinstance(task, dict) else ""
                if status and status not in TERMINAL_TASK_STATES:
                    mutate(
                        client,
                        "DELETE",
                        f"/api/docker/tasks/{quote(identifier, safe='')}",
                    )
            except Exception:
                pass

        if (
            find_project(client, sync_project_name) is not None
            or find_container(client, sync_container_name) is not None
        ):
            try:
                mutate(
                    client,
                    "POST",
                    "/api/docker/compose/down",
                    body={**sync_project_request, "remove_volumes": False},
                    body_supplied=True,
                )
            except Exception:
                pass

        leftover_sync_container = find_container(client, sync_container_name)
        if leftover_sync_container is not None:
            identifier = container_identity(leftover_sync_container)
            if identifier:
                try:
                    mutate(
                        client,
                        "DELETE",
                        f"/api/docker/containers/{quote(identifier, safe='')}",
                        query={"force": "true", "remove_volumes": "false"},
                    )
                except Exception:
                    pass

        if find_project(client, project_name) is not None or find_container(client, container_name) is not None:
            try:
                mutate(
                    client,
                    "POST",
                    "/api/docker/compose/down",
                    body={**project_request, "remove_volumes": False},
                    body_supplied=True,
                )
            except Exception:
                pass

        leftover_container = find_container(client, container_name)
        if leftover_container is not None:
            identifier = container_identity(leftover_container)
            if identifier:
                try:
                    mutate(
                        client,
                        "DELETE",
                        f"/api/docker/containers/{quote(identifier, safe='')}",
                        query={"force": "true", "remove_volumes": "false"},
                    )
                except Exception:
                    pass

        try:
            cleanup["sync_test_path_removed"] = delete_path(client, sync_project_path)
        except Exception:
            cleanup["sync_test_path_removed"] = False
        try:
            cleanup["async_test_path_removed"] = delete_path(client, project_path)
        except Exception:
            cleanup["async_test_path_removed"] = False

        # Completed task history can only be cleared globally. Baseline is
        # required to be empty, and all current IDs must be exactly ours.
        time.sleep(0.4)
        current_tasks = tasks(client)
        current_task_ids = identity_set(current_tasks, task_id)
        expected_task_ids = {value for value in created_task_ids if value}
        terminal = all(
            str(row.get("status") or "").lower() in TERMINAL_TASK_STATES
            for row in current_tasks
        )
        cleanup["task_history_ownership_gate"] = (
            not baseline_tasks
            and bool(expected_task_ids)
            and current_task_ids == expected_task_ids
            and terminal
        )
        if cleanup["task_history_ownership_gate"]:
            try:
                cleared = mutate(client, "DELETE", "/api/docker/tasks")
                cleanup["task_history_clear_ret_zero"] = cleared.get("ret") == 0
            except Exception:
                cleanup["task_history_clear_ret_zero"] = False
        else:
            cleanup["task_history_clear_ret_zero"] = False

        time.sleep(0.4)
        cleanup["project_baseline_restored"] = identity_set(
            projects(client), project_identity
        ) == baseline_projects
        cleanup["container_baseline_restored"] = identity_set(
            containers(client), container_identity
        ) == baseline_containers
        cleanup["task_baseline_restored"] = identity_set(
            tasks(client), task_id
        ) == baseline_tasks
        cleanup["image_baseline_restored"] = identity_set(
            images(client), image_identity
        ) == baseline_images
        cleanup["network_baseline_restored"] = identity_set(
            networks(client), network_identity
        ) == baseline_networks
        cleanup["volume_baseline_restored"] = identity_set(
            volumes(client), volume_identity
        ) == baseline_volumes
        cleanup["leftover_sync_test_project"] = (
            find_project(client, sync_project_name) is not None
        )
        cleanup["leftover_sync_test_container"] = (
            find_container(client, sync_container_name) is not None
        )
        cleanup["leftover_async_test_project"] = find_project(client, project_name) is not None
        cleanup["leftover_async_test_container"] = find_container(client, container_name) is not None

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in (
        "sync_test_path_removed",
        "async_test_path_removed",
        "task_history_ownership_gate",
        "task_history_clear_ret_zero",
        "project_baseline_restored",
        "container_baseline_restored",
        "task_baseline_restored",
        "image_baseline_restored",
        "network_baseline_restored",
        "volume_baseline_restored",
    ):
        if cleanup.get(key) is not True:
            failed.append(f"cleanup:{key}")
    for key in (
        "leftover_sync_test_project",
        "leftover_sync_test_container",
        "leftover_async_test_project",
        "leftover_async_test_container",
    ):
        if cleanup.get(key):
            failed.append(f"cleanup:{key}")
    if failure:
        failed.append("probe_exception")
        observations["failure"] = failure

    return {
        "target": "Lucky Docker Compose isolated lifecycle",
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
