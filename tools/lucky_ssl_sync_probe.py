#!/usr/bin/env python3
"""Runtime-verify Lucky v3 SSL linuxssh sync-client behavior and entitlement.

The probe creates an ephemeral localhost-only SSH key, appends exactly one
restricted TEST authorization to root's authorized_keys, adds one TEST
linuxssh sync client to Lucky's SSL settings, obtains a disposable TEST ACME
certificate, marks that certificate for all sync clients, and triggers the
real manual-sync business path toward a unique host /tmp directory. If the
current Lucky entitlement permits sync, it verifies delivered certificate/key
material. If Lucky rejects the action before transfer (as the current u=0
runtime does), the probe records that authorization boundary instead of
bypassing it. It then removes only the TEST certificate, TEST sync client,
TEST authorization line, and TEST directory.

Existing SSL setting scalars and non-TEST sync clients are always preserved
from the latest setting object. No SSH private key, certificate private key,
ACME credential, or host key value is printed.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api.client import LuckyAPIError  # noqa: E402
from tools.lucky_ssl_acme_probe import (  # noqa: E402
    build_candidate,
    detail,
    find_template,
    make_client,
    mutate,
    ssl_rows,
    wait_acme,
    wait_created,
)


CONFIRMATION = "PROBE-AND-CLEAN-SSL-SYNC"
TEST_CERT_PREFIX = "TEST-lucky-skills-ssl-sync-cert-"
TEST_CLIENT_PREFIX = "TEST-lucky-skills-ssl-sync-client-"
TEST_SSH_MARKER_PREFIX = "TEST-lucky-skills-ssl-sync-key-"


def ssl_setting(client: Any) -> dict[str, Any]:
    payload = client.request_json("GET", "/api/ssl/setting")
    if not isinstance(payload, dict) or payload.get("ret") != 0:
        raise RuntimeError("unexpected SSL setting response")
    return payload


def setting_put_body(setting: dict[str, Any], sync_clients: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "SyncClientList": sync_clients,
        "GlobalPrivateKey": setting.get("globalPrivateKey", ""),
        "DefaultACMEEMail": setting.get("defaultACMEEMail", ""),
        "CertificateCheckTime": copy.deepcopy(setting.get("certificateCheckTime") or {}),
        "RenewalThresholdDays": setting.get("renewalThresholdDays", 30),
        "ShortlivedRenewalThresholdHours": setting.get("shortlivedRenewalThresholdHours", 24),
        "ShortlivedCheckTimesPerDay": setting.get("shortlivedCheckTimesPerDay", 4),
    }


def setting_clients(setting: dict[str, Any]) -> list[dict[str, Any]]:
    rows = setting.get("syncClientList")
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected SSL syncClientList type")
    return [copy.deepcopy(row) for row in rows if isinstance(row, dict)]


def remove_test_sync_clients(client: Any) -> int:
    current = ssl_setting(client)
    rows = setting_clients(current)
    kept = [
        row
        for row in rows
        if not str(row.get("Remark") or "").startswith(TEST_CLIENT_PREFIX)
    ]
    removed = len(rows) - len(kept)
    if removed:
        mutate(
            client,
            "PUT",
            "/api/ssl/setting",
            json_body=setting_put_body(current, kept),
            body_supplied=True,
        )
    return removed


def wait_sync_client(client: Any, remark: str, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = ssl_setting(client)
        for row in setting_clients(current):
            if row.get("Remark") == remark:
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST SSL sync client did not appear")


def wait_synced_files(cert_path: Path, key_path: Path, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (
            cert_path.is_file()
            and cert_path.stat().st_size > 0
            and key_path.is_file()
            and key_path.stat().st_size > 0
        ):
            return True
        time.sleep(0.5)
    return False


def possible_material_bytes(value: str) -> list[bytes]:
    candidates = [value.encode("utf-8")]
    try:
        candidates.append(base64.b64decode(value, validate=True))
    except Exception:
        pass
    return candidates


def append_ephemeral_authorization(marker: str, public_key: str) -> Path:
    path = Path("/root/.ssh/authorized_keys")
    if not path.is_file():
        raise RuntimeError("root authorized_keys is unavailable")
    current = path.read_text(encoding="utf-8", errors="strict").splitlines()
    if any(marker in line for line in current):
        raise RuntimeError("pre-existing TEST SSH authorization marker found")
    restricted = f'from="127.0.0.1",restrict {public_key.strip()} {marker}'
    with path.open("a", encoding="utf-8") as handle:
        if path.stat().st_size and not path.read_bytes().endswith(b"\n"):
            handle.write("\n")
        handle.write(restricted + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o600)
    return path


def remove_ephemeral_authorization(path: Path, marker: str) -> bool:
    if not path.is_file():
        return False
    lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    kept = [line for line in lines if marker not in line]
    if len(kept) == len(lines):
        return True
    temp = path.with_name(path.name + ".lucky-skills.tmp")
    temp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, path)
    return marker not in path.read_text(encoding="utf-8", errors="strict")


def delete_exact_certificate(client: Any, key: str) -> bool:
    if not key:
        return True
    try:
        mutate(client, "DELETE", "/api/ssl", query={"key": key})
    except Exception:
        pass
    return all(str(row.get("Key") or "") != key for row in ssl_rows(client))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--domain-suffix", default="rs.fyzure.fyi")
    parser.add_argument("--ssh-host", default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=39147)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")
    if args.ssh_host != "127.0.0.1":
        raise SystemExit("this bounded probe only permits --ssh-host 127.0.0.1")

    client = make_client()
    initial_setting = ssl_setting(client)
    initial_clients = setting_clients(initial_setting)
    if any(
        str(row.get("Remark") or "").startswith(TEST_CLIENT_PREFIX)
        for row in initial_clients
    ):
        raise RuntimeError("pre-existing TEST SSL sync client found")

    initial_cert_keys = {
        str(row.get("Key") or "") for row in ssl_rows(client) if row.get("Key")
    }
    nonce = secrets.token_hex(5)
    client_remark = TEST_CLIENT_PREFIX + nonce
    cert_remark = TEST_CERT_PREFIX + nonce
    hostname = f"ssl-sync-{nonce}.{args.domain_suffix.strip().strip('.').lower()}"
    ssh_marker = TEST_SSH_MARKER_PREFIX + nonce
    target_dir = Path(tempfile.mkdtemp(prefix="TEST-lucky-skills-ssl-sync-target-", dir="/tmp"))
    target_dir.chmod(0o700)
    cert_path = target_dir / "cert.pem"
    key_path = target_dir / "key.pem"
    ssh_temp = Path(tempfile.mkdtemp(prefix="TEST-lucky-skills-ssl-sync-key-", dir="/tmp"))
    private_key_path = ssh_temp / "id_ed25519"
    authorization_path: Path | None = None
    test_cert_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                ssh_marker,
                "-f",
                str(private_key_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_key = private_key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()
        authorization_path = append_ephemeral_authorization(ssh_marker, public_key)
        results["ephemeral_ssh_authorization_added"] = True

        ssh_check = subprocess.run(
            [
                "ssh",
                "-i",
                str(private_key_path),
                "-p",
                str(args.ssh_port),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "root@127.0.0.1",
                "true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        results["ephemeral_ssh_login"] = ssh_check.returncode == 0
        if ssh_check.returncode != 0:
            raise RuntimeError("ephemeral localhost SSH login failed")

        sync_client = {
            "Remark": client_remark,
            "Target": "",
            "Token": "",
            "LastSyncTime": "",
            "ErrMsg": "",
            "Key": "",
            "Type": "linuxssh",
            "Params": {
                "AliESAID": "",
                "AliESAKey": "",
                "AliESASite": "",
                "TencentCloudSecretId": "",
                "TencentCloudSecretKey": "",
                "SSHHost": "127.0.0.1",
                "SSHPort": args.ssh_port,
                "SSHUser": "root",
                "SSHAuthType": "privatekey",
                "SSHPassword": "",
                "SSHPrivateKey": private_key_path.read_text(encoding="utf-8"),
                "SSHKeyPassphrase": "",
                "SSHHostKey": "",
                "SSHCertPath": str(cert_path),
                "SSHKeyPath": str(key_path),
                "SSHScriptDir": str(target_dir),
                "SSHCommand": "",
            },
        }
        latest = ssl_setting(client)
        current_clients = setting_clients(latest)
        current_clients.append(sync_client)
        mutate(
            client,
            "PUT",
            "/api/ssl/setting",
            json_body=setting_put_body(latest, current_clients),
            body_supplied=True,
        )
        saved_client = wait_sync_client(client, client_remark)
        results["sync_client_saved"] = saved_client.get("Type") == "linuxssh"
        observations["sync_client_key_present"] = bool(saved_client.get("Key"))
        sync_runtime = client.request_json("GET", "/api/ssl/syncclients")
        runtime_rows = sync_runtime.get("list") if isinstance(sync_runtime, dict) else None
        observations["syncclients_runtime_count"] = len(runtime_rows) if isinstance(runtime_rows, list) else 0

        _, template = find_template(client)
        candidate = build_candidate(template, cert_remark, hostname)
        candidate["AllSyncClient"] = True
        candidate["SyncClientList"] = []
        mutate(client, "POST", "/api/ssl", json_body=candidate, body_supplied=True)
        test_cert_key = wait_created(client, cert_remark)
        results["test_certificate_created"] = bool(test_cert_key)
        row, state = wait_acme(client, test_cert_key, hostname, timeout=180)
        observations["acme_state"] = state
        results["test_certificate_issued"] = state == "issued"
        if state != "issued":
            raise RuntimeError("TEST certificate issuance failed")

        cert_info = detail(client, test_cert_key)
        observations["certificate_all_sync_client"] = bool(cert_info.get("AllSyncClient"))
        sync_selection = cert_info.get("SyncClientList")
        observations["certificate_sync_client_selection_count"] = (
            len(sync_selection) if isinstance(sync_selection, list) else -1
        )
        try:
            manual = mutate(client, "GET", f"/api/ssl/manualsync/{test_cert_key}")
            results["manual_sync_executed"] = isinstance(manual, dict)
        except LuckyAPIError as error:
            results["manual_sync_executed"] = False
            observations["manual_sync_ret"] = error.ret
            text = str(error)
            observations["manual_sync_error"] = text.rsplit(":", 1)[-1].strip()[:180]

        results["sync_files_written"] = wait_synced_files(cert_path, key_path)
        if results["sync_files_written"]:
            cert_bytes = cert_path.read_bytes()
            key_bytes = key_path.read_bytes()
            cert_material = str(cert_info.get("CertBase64") or "")
            key_material = str(cert_info.get("KeyBase64") or "")
            results["synced_certificate_matches"] = cert_bytes in possible_material_bytes(cert_material)
            results["synced_private_key_matches"] = key_bytes in possible_material_bytes(key_material)
        else:
            results["synced_certificate_matches"] = False
            results["synced_private_key_matches"] = False

        after_sync_client = wait_sync_client(client, client_remark)
        observations["last_sync_time_present"] = bool(after_sync_client.get("LastSyncTime"))
        observations["sync_error_present"] = bool(after_sync_client.get("ErrMsg"))
        params = after_sync_client.get("Params") if isinstance(after_sync_client.get("Params"), dict) else {}
        observations["ssh_host_key_learned"] = bool(params.get("SSHHostKey"))
        results["sync_status_success"] = bool(after_sync_client.get("LastSyncTime")) and not bool(after_sync_client.get("ErrMsg"))

    finally:
        cleanup["test_certificate_deleted"] = delete_exact_certificate(client, test_cert_key)
        try:
            cleanup["test_sync_clients_removed"] = remove_test_sync_clients(client)
        except Exception:
            cleanup["test_sync_clients_removed"] = -1
        if authorization_path is not None:
            cleanup["ephemeral_ssh_authorization_removed"] = remove_ephemeral_authorization(
                authorization_path, ssh_marker
            )
        else:
            cleanup["ephemeral_ssh_authorization_removed"] = True
        shutil.rmtree(target_dir, ignore_errors=True)
        shutil.rmtree(ssh_temp, ignore_errors=True)
        cleanup["target_directory_removed"] = not target_dir.exists()
        cleanup["ssh_key_directory_removed"] = not ssh_temp.exists()

    final_setting = ssl_setting(client)
    final_clients = setting_clients(final_setting)
    cleanup["no_test_sync_clients"] = not any(
        str(row.get("Remark") or "").startswith(TEST_CLIENT_PREFIX)
        for row in final_clients
    )
    final_cert_keys = {
        str(row.get("Key") or "") for row in ssl_rows(client) if row.get("Key")
    }
    cleanup["certificate_key_baseline_restored"] = final_cert_keys == initial_cert_keys
    cleanup["non_test_sync_client_count_restored"] = len(final_clients) == len(initial_clients)

    failed = sorted(key for key, value in results.items() if not value)
    for key in (
        "test_certificate_deleted",
        "ephemeral_ssh_authorization_removed",
        "target_directory_removed",
        "ssh_key_directory_removed",
        "no_test_sync_clients",
        "certificate_key_baseline_restored",
        "non_test_sync_client_count_restored",
    ):
        if not cleanup.get(key):
            failed.append(key)

    print(
        json.dumps(
            {
                "target": "Lucky SSL linuxssh sync-client behavior",
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
