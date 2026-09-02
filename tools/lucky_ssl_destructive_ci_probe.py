#!/usr/bin/env python3
"""Verify TEST-only SSL flush/delete behavior in disposable GitHub Actions CI.

The probe creates its own short-lived self-signed certificate/key, imports it
into a fresh pinned Lucky 3.0.0 instance over HTTP APIs, exercises the SSL
``flush`` route only on that owned non-ACME certificate, classifies the exact
response/readback semantics, then deletes the TEST certificate and verifies
the empty certificate baseline is restored.

No production Lucky, public DNS, ACME account, Cloudflare credential or
production certificate is contacted. Certificate/key material exists only in
RUNNER_TEMP and request memory and is never printed.
"""

from __future__ import annotations

import base64
import json
import secrets
import subprocess
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


TEST_PREFIX = "TEST-lucky-skills-ssl-ci-"
ADD_FROM_CANDIDATES = ("manual", "custom", "file", "import", "local")


def admin_json(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    return json_request(
        urllib.request.build_opener(),
        base_url,
        path,
        method=method,
        payload=payload,
        admin_token=token,
        timeout=30,
    )


def ssl_rows(base_url: str, token: str) -> list[dict[str, Any]]:
    status, response = admin_json(base_url, token, "/api/ssl")
    require_ret_zero(status, response, "read disposable SSL list")
    rows = response.get("list")
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ProbeError("SSL list response had unexpected list shape")
    return rows


def generate_self_signed(workdir: Path, hostname: str) -> tuple[str, str]:
    cert = workdir / "test.crt"
    key = workdir / "test.key"
    completed = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN={hostname}",
            "-addext",
            f"subjectAltName=DNS:{hostname}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ProbeError("openssl could not create disposable self-signed certificate")
    cert_bytes = cert.read_bytes()
    key_bytes = key.read_bytes()
    if not cert_bytes or not key_bytes:
        raise ProbeError("generated certificate/key was empty")
    return (
        base64.b64encode(cert_bytes).decode("ascii"),
        base64.b64encode(key_bytes).decode("ascii"),
    )


def find_owned(rows: list[dict[str, Any]], remark: str) -> dict[str, Any] | None:
    for row in rows:
        if row.get("Remark") == remark:
            return row
    return None


def main() -> int:
    runner_temp = require_github_hosted_runner()
    pull_pinned_image()
    nonce = secrets.token_hex(5)
    container_name = f"lucky-ssl-destructive-ci-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"
    remark = TEST_PREFIX + nonce
    hostname = f"{nonce}.invalid"

    report: dict[str, Any] = {
        "lucky_version": "",
        "network_scope": "runner-loopback",
        "baseline_empty": False,
        "owned_certificate_generated": False,
        "certificate_created": False,
        "accepted_add_from": "",
        "certificate_key_present": False,
        "certificate_material_present": False,
        "flush_http_status": 0,
        "flush_ret": None,
        "flush_message": "",
        "flush_response_keys": [],
        "flush_classified": False,
        "flush_started_acme": False,
        "flush_changed_fingerprint": False,
        "certificate_deleted": False,
        "baseline_restored": False,
    }

    with tempfile.TemporaryDirectory(prefix="lucky-ssl-destructive-ci-", dir=runner_temp) as tmp_raw:
        tmp = Path(tmp_raw)
        conf_dir = tmp / "conf"
        conf_dir.mkdir()
        created_key = ""
        try:
            docker(
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                "bridge",
                "-p",
                f"127.0.0.1:{host_port}:{ADMIN_PORT}",
                "-v",
                f"{conf_dir}:/app/conf",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            wait_for_lucky(base_url, container_name)
            token = login_default_admin(base_url, tmp)

            status, info = admin_json(base_url, token, "/api/info")
            require_ret_zero(status, info, "read disposable Lucky info")
            info_obj = info.get("info")
            version = str(info_obj.get("Version") or "") if isinstance(info_obj, dict) else ""
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version {version!r}")

            baseline = ssl_rows(base_url, token)
            report["baseline_empty"] = not baseline
            if baseline:
                raise ProbeError("fresh Lucky SSL baseline was not empty")

            cert_b64, key_b64 = generate_self_signed(tmp, hostname)
            report["owned_certificate_generated"] = True
            create_status = 0
            create: dict[str, Any] = {}
            accepted_add_from = ""
            for add_from in ADD_FROM_CANDIDATES:
                candidate = {
                    "Key": "",
                    "Remark": remark,
                    "Enable": True,
                    "AddFrom": add_from,
                    "CertBase64": cert_b64,
                    "KeyBase64": key_b64,
                    "IssuerCertificate": "",
                    "AcmeErrorMsg": "",
                    "AddTime": "",
                    "UpdateTime": "",
                    "MappingToPath": False,
                    "MappingPath": "",
                    "MappingChangeScript": "",
                    "SyncClientList": [],
                    "AllSyncClient": False,
                    "ExtParams": {},
                }
                create_status, create = admin_json(
                    base_url,
                    token,
                    "/api/ssl",
                    method="POST",
                    payload=candidate,
                )
                if create_status == 200 and create.get("ret") == 0:
                    accepted_add_from = add_from
                    break
                msg = str(create.get("msg") or create.get("message") or "")
                if create_status != 200 or "UnsupportedType" not in msg:
                    break
            if not accepted_add_from:
                safe_msg = str(create.get("msg") or create.get("message") or "")[:200]
                raise ProbeError(
                    "create disposable certificate failed after bounded AddFrom discovery: "
                    f"HTTP {create_status}, ret={create.get('ret')}, msg={safe_msg!r}"
                )
            report["accepted_add_from"] = accepted_add_from
            rows = ssl_rows(base_url, token)
            owned = find_owned(rows, remark)
            if not owned:
                raise ProbeError("created TEST certificate was not listed")
            created_key = str(owned.get("Key") or "")
            report["certificate_created"] = bool(created_key)
            report["certificate_key_present"] = bool(created_key)
            certs = owned.get("CertsInfo") if isinstance(owned.get("CertsInfo"), dict) else {}
            before_sha = str(certs.get("SHA256") or "")

            detail_status, detail = admin_json(base_url, token, f"/api/ssl/{created_key}")
            require_ret_zero(detail_status, detail, "read disposable certificate detail")
            detail_info = detail.get("info")
            report["certificate_material_present"] = bool(
                isinstance(detail_info, dict)
                and detail_info.get("CertBase64")
                and detail_info.get("KeyBase64")
            )

            flush_status, flush = admin_json(
                base_url,
                token,
                f"/api/ssl/flush?key={created_key}",
                method="PUT",
            )
            report["flush_http_status"] = flush_status
            report["flush_ret"] = flush.get("ret")
            report["flush_message"] = str(
                flush.get("msg") or flush.get("message") or ""
            )[:200]
            report["flush_response_keys"] = sorted(str(key) for key in flush.keys())
            report["flush_classified"] = flush_status == 200 and type(flush.get("ret")) is int

            time.sleep(1)
            owned_after = find_owned(ssl_rows(base_url, token), remark)
            if not owned_after:
                raise ProbeError("TEST certificate disappeared after flush")
            report["flush_started_acme"] = bool(owned_after.get("ACMEing"))
            certs_after = (
                owned_after.get("CertsInfo")
                if isinstance(owned_after.get("CertsInfo"), dict)
                else {}
            )
            after_sha = str(certs_after.get("SHA256") or "")
            report["flush_changed_fingerprint"] = bool(
                before_sha and after_sha and before_sha != after_sha
            )

            delete_status, delete = admin_json(
                base_url,
                token,
                f"/api/ssl?key={created_key}",
                method="DELETE",
            )
            require_ret_zero(delete_status, delete, "delete disposable certificate")
            report["certificate_deleted"] = find_owned(ssl_rows(base_url, token), remark) is None
            report["baseline_restored"] = not ssl_rows(base_url, token)
            created_key = ""

            required = (
                "baseline_empty",
                "owned_certificate_generated",
                "certificate_created",
                "certificate_key_present",
                "certificate_material_present",
                "flush_classified",
                "certificate_deleted",
                "baseline_restored",
            )
            failed = [name for name in required if report.get(name) is not True]
            report["failed"] = failed
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 1 if failed else 0
        finally:
            if created_key:
                try:
                    token = login_default_admin(base_url, tmp)
                    admin_json(base_url, token, f"/api/ssl?key={created_key}", method="DELETE")
                except Exception:  # noqa: BLE001 - best-effort owned cleanup before teardown
                    pass
            docker("rm", "-f", container_name, timeout=45)
            cleanup_root_owned_conf(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"probe_error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
