#!/usr/bin/env python3
"""Runtime-verify bounded Lucky Docker image import/save/load behavior.

The probe never pulls or builds an image.  An owned Cron shell task creates a
tiny raw root-filesystem tar under Lucky's own ``/tmp`` namespace.  The tar is
imported as a disposable image, tagged with a unique TEST repository, exported
through Lucky's image-save download route, deleted, materialized back into the
same TEST directory, and loaded again.  The restored tag and image identity are
then verified before all TEST image/Cron/path resources are removed.

The current Lucky frontend uploads a user-selected ``.tar`` through
``/api/docker/images/upload-temp`` and then calls ``/api/docker/images/load``
with the returned temporary path and ``cleanup=true``.  The extractor now
captures that direct Axios route, so the probe follows the same UI workflow
after separately verifying ``/api/docker/images/import``.  No image build,
pull, container, network, volume, or Docker prune is performed.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import secrets
import shlex
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
from lucky_api.client import LuckyAPIError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)
from tools.lucky_cron_probe import (  # noqa: E402
    base_task,
    cron_rows,
    delete_path,
    mkdir,
    mutate,
    row_key,
    wait_path,
    wait_task,
)


CONFIRMATION = "PROBE-AND-CLEAN-DOCKER-IMAGE-IMPORT"
IMAGE_PREFIX = "test-lucky-skills-image-"
CRON_PREFIX = "TEST-lucky-skills-cron-image-"
PATH_PREFIX = "TEST-lucky-skills-image-"


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
        timeout=60,
    )


def image_rows(client: LuckyClient) -> list[dict[str, Any]]:
    value = client.request_json(
        "GET",
        "/api/docker/images",
        query={"all": "true"},
    )
    rows = value.get("images") if isinstance(value, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected Docker image list type")
    return [row for row in rows if isinstance(row, dict)]


def image_id(row: dict[str, Any]) -> str:
    return str(row.get("Id") or "")


def image_tags(row: dict[str, Any]) -> list[str]:
    raw = row.get("RepoTags")
    if not isinstance(raw, list):
        return []
    return [str(value) for value in raw]


def image_snapshot(client: LuckyClient) -> set[tuple[str, tuple[str, ...]]]:
    return {
        (image_id(row), tuple(sorted(image_tags(row))))
        for row in image_rows(client)
        if image_id(row)
    }


def find_tag(client: LuckyClient, reference: str) -> dict[str, Any] | None:
    return next(
        (row for row in image_rows(client) if reference in image_tags(row)),
        None,
    )


def delete_image(client: LuckyClient, identifier: str) -> dict[str, Any]:
    return mutate(
        client,
        "DELETE",
        f"/api/docker/images/{quote(identifier, safe='')}",
        query={"force": "true", "noprune": "false"},
    )


def multipart_file(filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = f"----lucky-skills-{secrets.token_hex(12)}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/x-tar\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    return head + content + tail, f"multipart/form-data; boundary={boundary}"


def remove_owned_cron(client: LuckyClient, key: str) -> None:
    if not key:
        return
    try:
        mutate(
            client,
            "GET",
            "/api/cron/enable",
            query={"enable": "false", "key": key},
        )
    except Exception:
        pass
    try:
        mutate(client, "DELETE", "/api/cron/list", query={"key": key})
    except Exception:
        pass


def run_probe() -> dict[str, Any]:
    client = make_client()
    suffix = secrets.token_hex(5)
    repository = f"{IMAGE_PREFIX}{suffix}"
    reference = f"{repository}:latest"
    cron_name = f"{CRON_PREFIX}{suffix}"
    test_dir = f"/tmp/{PATH_PREFIX}{suffix}"
    rootfs_tar = f"{test_dir}/rootfs.tar"
    saved_tar = f"{test_dir}/saved-image.tar"

    baseline_images = image_snapshot(client)
    baseline_cron_keys = {row_key(row) for row in cron_rows(client) if row_key(row)}

    if any(
        any(tag.startswith(IMAGE_PREFIX) for tag in image_tags(row))
        for row in image_rows(client)
    ):
        raise RuntimeError("pre-existing TEST Docker image tag found")
    if any(
        str(row.get("Name") or "").startswith(CRON_PREFIX)
        for row in cron_rows(client)
    ):
        raise RuntimeError("pre-existing TEST Docker-image Cron task found")

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {
        "baseline_image_count": len(baseline_images),
        "build_requested": False,
        "pull_requested": False,
        "container_created": False,
        "frontend_upload_flow": "upload-temp -> load(cleanup=true)",
    }
    cleanup: dict[str, Any] = {}
    cron_key = ""
    owned_image_ids: list[str] = []
    uploaded_temp_path = ""
    failure: str | None = None

    try:
        mkdir(client, test_dir)

        # This creates a plain filesystem tar, not a Docker image build.
        rootfs_script = (
            "set -eu; "
            f"mkdir -p {test_dir}/rootfs; "
            f"printf '%s\\n' lucky-skills-image-probe > {test_dir}/rootfs/probe.txt; "
            f"tar -C {test_dir}/rootfs -cf {rootfs_tar} ."
        )
        cron_payload = base_task(cron_name, "", rootfs_script)
        created_cron = mutate(
            client,
            "POST",
            "/api/cron/list",
            body=cron_payload,
            body_supplied=True,
        )
        results["cron_created"] = created_cron.get("ret") == 0
        cron_row = wait_task(client, cron_name)
        cron_key = row_key(cron_row)

        dispatched = mutate(
            client,
            "GET",
            "/api/cron/dojobs",
            query={"key": cron_key},
        )
        results["rootfs_tar_dispatched"] = dispatched.get("ret") == 0
        results["rootfs_tar_created"] = wait_path(
            client,
            test_dir,
            "rootfs.tar",
            timeout=10.0,
        )
        if not results["rootfs_tar_created"]:
            raise RuntimeError("TEST rootfs tar was not created")

        before_ids = {image_id(row) for row in image_rows(client) if image_id(row)}
        imported = mutate(
            client,
            "POST",
            "/api/docker/images/import",
            body={"source": rootfs_tar},
            body_supplied=True,
        )
        results["import_ret_zero"] = imported.get("ret") == 0
        observations["import_response_fields"] = sorted(imported.keys())
        time.sleep(0.5)

        new_images = [
            row
            for row in image_rows(client)
            if image_id(row) and image_id(row) not in before_ids
        ]
        observations["new_image_count_after_import"] = len(new_images)
        results["import_created_one_image"] = len(new_images) == 1
        if len(new_images) != 1:
            raise RuntimeError(
                f"TEST import created {len(new_images)} new images; expected exactly one"
            )
        imported_id = image_id(new_images[0])
        owned_image_ids.append(imported_id)

        tagged = mutate(
            client,
            "POST",
            f"/api/docker/images/{quote(imported_id, safe='')}/tag",
            body={"repository": repository, "tag": "latest"},
            body_supplied=True,
        )
        results["tag_ret_zero"] = tagged.get("ret") == 0
        results["tag_visible"] = find_tag(client, reference) is not None
        if not results["tag_visible"]:
            raise RuntimeError("TEST Docker tag did not become visible")

        saved = client.request(
            "GET",
            "/api/docker/images/save.withoutcompression",
            query={"imageid": reference},
            allow_unsafe=True,
        )
        results["save_http_200"] = saved.status == 200 and bool(saved.body)
        observations["save_content_type"] = saved.content_type
        observations["saved_tar_nonempty"] = bool(saved.body)
        if not results["save_http_200"]:
            raise RuntimeError("TEST image save returned no tar payload")

        deleted = delete_image(client, imported_id)
        results["delete_before_load_ret_zero"] = deleted.get("ret") == 0
        time.sleep(0.4)
        results["tag_absent_before_load"] = find_tag(client, reference) is None
        if not results["tag_absent_before_load"]:
            raise RuntimeError("TEST Docker image remained present before load")
        owned_image_ids.clear()

        load_path = ""
        load_cleanup = False
        upload_body, upload_content_type = multipart_file(f"{repository}.tar", saved.body)
        try:
            upload = client.request_json(
                "POST",
                "/api/docker/images/upload-temp",
                raw_body=upload_body,
                content_type=upload_content_type,
                allow_unsafe=True,
            )
            if not isinstance(upload, dict):
                raise RuntimeError("unexpected image upload-temp response")
            uploaded_temp_path = str(upload.get("path") or "")
            results["upload_temp_request_handled"] = True
            results["upload_temp_ret_zero"] = upload.get("ret") == 0
            results["upload_temp_returned_path"] = bool(uploaded_temp_path)
            observations["upload_temp_response_fields"] = sorted(upload.keys())
            observations["upload_temp_status"] = "success"
            if not results["upload_temp_returned_path"]:
                raise RuntimeError("image upload-temp returned no temporary path")
            load_path = uploaded_temp_path
            load_cleanup = True
        except LuckyAPIError as error:
            if error.ret != 1 or "Temp operation path not configured" not in str(error):
                raise
            # The current image-import UI checks the same global Docker setting
            # before opening its upload dialog.  Do not mutate that production
            # setting solely for coverage; preserve the handler-level business
            # error and materialize the already-owned tar via the owned Cron
            # task so /images/load can still be exercised.
            results["upload_temp_request_handled"] = True
            observations["upload_temp_status"] = "blocked: temp operation path not configured"
            encoded = base64.b64encode(saved.body).decode("ascii")
            materialize_payload = copy.deepcopy(cron_payload)
            materialize_payload["Key"] = cron_key
            materialize_payload["Jobs"][0]["Options"]["shell_content"] = (
                "set -eu; "
                f"printf '%s' '{encoded}' | base64 -d > {saved_tar}; "
                f": > {test_dir}/decode.ok"
            )
            updated_cron = mutate(
                client,
                "PUT",
                "/api/cron/list",
                body=materialize_payload,
                body_supplied=True,
            )
            results["fallback_tar_materialize_put"] = updated_cron.get("ret") == 0
            dispatched_saved = mutate(
                client,
                "GET",
                "/api/cron/dojobs",
                query={"key": cron_key},
            )
            results["fallback_tar_materialize_dispatched"] = dispatched_saved.get("ret") == 0
            results["fallback_saved_tar_created"] = wait_path(
                client,
                test_dir,
                "saved-image.tar",
                timeout=12.0,
            )
            results["fallback_decode_marker"] = wait_path(
                client,
                test_dir,
                "decode.ok",
                timeout=12.0,
            )
            if not (
                results["fallback_saved_tar_created"]
                and results["fallback_decode_marker"]
            ):
                raise RuntimeError("fallback saved TEST Docker tar was not materialized")
            load_path = saved_tar
            load_cleanup = False

        loaded = mutate(
            client,
            "POST",
            "/api/docker/images/load",
            body={"path": load_path, "cleanup": load_cleanup},
            body_supplied=True,
        )
        results["load_ret_zero"] = loaded.get("ret") == 0
        observations["load_response_fields"] = sorted(loaded.keys())
        time.sleep(0.5)
        restored = find_tag(client, reference)
        results["load_restored_tag"] = restored is not None
        if restored is None:
            raise RuntimeError("TEST image load did not restore its tag")
        restored_id = image_id(restored)
        owned_image_ids.append(restored_id)
        results["load_restored_same_image_identity"] = restored_id == imported_id
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        for identifier in list(dict.fromkeys(owned_image_ids)):
            try:
                delete_image(client, identifier)
            except Exception:
                pass
        for row in image_rows(client):
            if (
                any(tag.startswith(f"{repository}:") for tag in image_tags(row))
                and image_id(row)
            ):
                try:
                    delete_image(client, image_id(row))
                except Exception:
                    pass

        # upload-temp returned this exact path to this probe. cleanup=true
        # normally deletes it during load; this fallback only handles an
        # interrupted load and never targets a path learned from another
        # resource.
        if uploaded_temp_path and cron_key:
            try:
                cleanup_payload = base_task(
                    cron_name,
                    "",
                    f"rm -f -- {shlex.quote(uploaded_temp_path)}",
                )
                cleanup_payload["Key"] = cron_key
                mutate(
                    client,
                    "PUT",
                    "/api/cron/list",
                    body=cleanup_payload,
                    body_supplied=True,
                )
                mutate(
                    client,
                    "GET",
                    "/api/cron/dojobs",
                    query={"key": cron_key},
                )
            except Exception:
                pass

        remove_owned_cron(client, cron_key)
        try:
            cleanup["test_path_removed"] = delete_path(client, test_dir)
        except Exception:
            cleanup["test_path_removed"] = False
        time.sleep(0.4)
        cleanup["image_baseline_restored"] = image_snapshot(client) == baseline_images
        cleanup["cron_task_baseline_restored"] = {
            row_key(row) for row in cron_rows(client) if row_key(row)
        } == baseline_cron_keys
        cleanup["leftover_test_tags"] = sum(
            any(tag.startswith(f"{repository}:") for tag in image_tags(row))
            for row in image_rows(client)
        )

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in ("test_path_removed", "image_baseline_restored", "cron_task_baseline_restored"):
        if cleanup.get(key) is not True:
            failed.append(f"cleanup:{key}")
    if cleanup.get("leftover_test_tags") != 0:
        failed.append("cleanup:leftover_test_tags")
    if failure:
        observations["failure"] = failure
        failed.append("probe_exception")

    return {
        "target": "Lucky Docker image import/save/load lifecycle",
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
        parser.error(f"--confirm must be exactly {CONFIRMATION!r}")
    try:
        report = run_probe()
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
