#!/usr/bin/env python3
"""Runtime-verify Lucky v3 ACME certificate lifecycle with a disposable cert.

The probe clones the existing ACME account/DNS-provider configuration only in
memory, clears certificate/private-key material, requests a certificate for a
unique TEST hostname, verifies SAN/metadata, exercises safe update/toggle and
TEST-only refresh/sync actions, then deletes the disposable certificate.

No certificate bodies, private keys, DNS credentials, ACME account material,
or live business domain names are printed.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError, LuckyAPIError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-AND-CLEAN-SSL-ACME"
TEST_PREFIX = "TEST-lucky-skills-ssl-"


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(base_url, token, catalog=catalog, retries=0, timeout=30)
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(
        values["base_url"], values["open_token"], catalog=catalog, retries=0, timeout=30
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    body_supplied: bool = False,
    attempts: int = 6,
    raise_for_lucky: bool = True,
) -> Any:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {
            "allow_unsafe": True,
            "raise_for_lucky": raise_for_lucky,
        }
        if query is not None:
            kwargs["query"] = query
        if body_supplied:
            kwargs["json_body"] = json_body
        try:
            response = client.request(method, path, **kwargs)
            return response.json()
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(6.0 + attempt * 4.0)
    raise AssertionError("unreachable")


def ssl_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/ssl")
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected SSL list response")
    return [row for row in rows if isinstance(row, dict)]


def row_key(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def detail(client: LuckyClient, key: str) -> dict[str, Any]:
    payload = client.request_json("GET", f"/api/ssl/{key}")
    info = payload.get("info") if isinstance(payload, dict) else None
    if not isinstance(info, dict):
        raise RuntimeError("unexpected SSL detail response")
    return info


def find_template(client: LuckyClient) -> tuple[dict[str, Any], dict[str, Any]]:
    for row in ssl_rows(client):
        key = row_key(row)
        if not key or str(row.get("Remark", "")).startswith(TEST_PREFIX):
            continue
        if row.get("AddFrom") != "acme":
            continue
        info = detail(client, key)
        ext = info.get("ExtParams")
        if (
            isinstance(ext, dict)
            and isinstance(ext.get("acmeDNSSecret"), str)
            and ext.get("acmeDNSSecret")
            and isinstance(ext.get("acmeEmail"), str)
            and ext.get("acmeEmail")
            and isinstance(ext.get("acmeCADirURL"), str)
            and ext.get("acmeCADirURL")
        ):
            return row, info
    raise RuntimeError("no reusable ACME certificate template with DNS credentials found")


def build_candidate(template: dict[str, Any], remark: str, hostname: str) -> dict[str, Any]:
    candidate = copy.deepcopy(template)
    candidate["Key"] = ""
    candidate["Remark"] = remark
    candidate["Enable"] = True
    candidate["AddFrom"] = "acme"
    candidate["CertBase64"] = ""
    candidate["KeyBase64"] = ""
    candidate["IssuerCertificate"] = ""
    candidate["AcmeErrorMsg"] = ""
    candidate["AddTime"] = ""
    candidate["UpdateTime"] = ""
    candidate["MappingToPath"] = False
    candidate["MappingPath"] = ""
    candidate["MappingChangeScript"] = ""
    candidate["SyncClientList"] = []
    candidate["AllSyncClient"] = False
    ext = candidate.get("ExtParams")
    if not isinstance(ext, dict):
        raise RuntimeError("ACME template ExtParams missing")
    ext["acmeDomains"] = [hostname]
    ext["certPath"] = ""
    ext["keyPath"] = ""
    # Preserve ACME account registration/prePrivateKeyBase64 and provider
    # credentials in memory, but never persist them outside Lucky or print them.
    return candidate


def wait_created(client: LuckyClient, remark: str, timeout: float = 30.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in ssl_rows(client):
            if row.get("Remark") == remark:
                key = row_key(row)
                if key:
                    return key
        time.sleep(0.7)
    raise RuntimeError("TEST SSL item did not appear")


def wait_acme(
    client: LuckyClient, key: str, hostname: str, *, timeout: float = 180.0
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + timeout
    last_state = "unknown"
    while time.monotonic() < deadline:
        row = next((row for row in ssl_rows(client) if row_key(row) == key), None)
        if row is None:
            raise RuntimeError("TEST SSL item disappeared during issuance")
        if row.get("ACMEing"):
            last_state = "issuing"
            time.sleep(2.0)
            continue
        error = str(row.get("ACMEErrMsg") or "")
        certs = row.get("CertsInfo") if isinstance(row.get("CertsInfo"), dict) else {}
        domains = certs.get("Domains") if isinstance(certs, dict) else None
        sans = certs.get("SANs") if isinstance(certs, dict) else None
        names = []
        if isinstance(domains, list):
            names.extend(str(item) for item in domains)
        if isinstance(sans, list):
            names.extend(str(item) for item in sans)
        if hostname in names and certs.get("SHA256"):
            return row, "issued"
        if error:
            return row, "error"
        last_state = "idle-no-cert"
        time.sleep(2.0)
    raise RuntimeError(f"ACME issuance timed out ({last_state})")


def cleanup_tests(client: LuckyClient) -> int:
    removed = 0
    for row in ssl_rows(client):
        if not str(row.get("Remark", "")).startswith(TEST_PREFIX):
            continue
        key = row_key(row)
        if not key:
            continue
        if row.get("ACMEing"):
            try:
                mutate(client, "DELETE", f"/api/ssl/{key}/acmecancel")
                time.sleep(1.0)
            except Exception:
                pass
        try:
            mutate(client, "DELETE", "/api/ssl", query={"key": key})
            removed += 1
        except Exception:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--domain-suffix", default="rs.fyzure.fyi")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline_rows = ssl_rows(client)
    baseline_keys = {row_key(row) for row in baseline_rows if row_key(row)}
    if any(str(row.get("Remark", "")).startswith(TEST_PREFIX) for row in baseline_rows):
        raise RuntimeError("pre-existing TEST SSL certificate found")
    _, template = find_template(client)

    nonce = secrets.token_hex(5)
    remark = TEST_PREFIX + nonce
    hostname = f"ssl-{nonce}.{args.domain_suffix.strip().strip('.').lower()}"
    candidate = build_candidate(template, remark, hostname)
    test_key = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        mutate(client, "POST", "/api/ssl", json_body=candidate, body_supplied=True)
        test_key = wait_created(client, remark)
        results["post_create"] = bool(test_key)

        row, state = wait_acme(client, test_key, hostname)
        observations["initial_acme_state"] = state
        results["acme_issued"] = state == "issued"
        certs = row.get("CertsInfo") if isinstance(row.get("CertsInfo"), dict) else {}
        names = []
        for field in ("Domains", "SANs"):
            value = certs.get(field) if isinstance(certs, dict) else None
            if isinstance(value, list):
                names.extend(str(item) for item in value)
        results["certificate_hostname_verified"] = hostname in names
        results["certificate_fingerprint_present"] = bool(certs.get("SHA256"))
        results["certificate_validity_present"] = bool(
            certs.get("NotBeforeTime") and certs.get("NotAfterTime")
        )

        info = detail(client, test_key)
        results["certificate_material_present"] = bool(
            info.get("CertBase64") and info.get("KeyBase64")
        )
        updated = copy.deepcopy(info)
        updated_remark = remark + "-updated"
        updated["Remark"] = updated_remark
        mutate(client, "PUT", "/api/ssl", json_body=updated, body_supplied=True)
        time.sleep(0.5)
        after_update = detail(client, test_key)
        results["put_update"] = after_update.get("Remark") == updated_remark

        mutate(client, "PUT", f"/api/ssl/{test_key}", query={"enable": "false"})
        disabled = next(row for row in ssl_rows(client) if row_key(row) == test_key)
        results["disable_toggle"] = disabled.get("Enable") is False
        mutate(client, "PUT", f"/api/ssl/{test_key}", query={"enable": "true"})
        enabled = next(row for row in ssl_rows(client) if row_key(row) == test_key)
        results["enable_toggle"] = enabled.get("Enable") is True

        # Exercise TEST-only manual sync even when no sync clients are
        # configured. Record success/no-op vs a bounded Lucky business error
        # without treating absence of sync clients as certificate failure.
        try:
            manual_payload = mutate(client, "GET", f"/api/ssl/manualsync/{test_key}")
            results["manual_sync_route_executed"] = True
            observations["manual_sync_result"] = "success"
            if isinstance(manual_payload, dict):
                observations["manual_sync_ret"] = manual_payload.get("ret")
        except LuckyAPIError as error:
            results["manual_sync_route_executed"] = True
            observations["manual_sync_result"] = "business-error"
            observations["manual_sync_error_class"] = "no-client-or-not-syncable"

        # /ssl/flush is exercised only on the disposable certificate. Whether
        # it causes a re-issuance is inferred from ACMEing/fingerprint changes,
        # not guessed from the route name.
        before_sha = str(certs.get("SHA256") or "")
        flush_payload = mutate(
            client,
            "PUT",
            "/api/ssl/flush",
            query={"key": test_key},
            raise_for_lucky=False,
        )
        results["flush_route_executed"] = isinstance(flush_payload, dict)
        time.sleep(1.0)
        flush_row = next(row for row in ssl_rows(client) if row_key(row) == test_key)
        observations["flush_started_acme"] = bool(flush_row.get("ACMEing"))
        if flush_row.get("ACMEing"):
            flush_row, flush_state = wait_acme(client, test_key, hostname, timeout=180)
            observations["flush_acme_state"] = flush_state
        flush_certs = (
            flush_row.get("CertsInfo") if isinstance(flush_row.get("CertsInfo"), dict) else {}
        )
        after_sha = str(flush_certs.get("SHA256") or "")
        observations["flush_changed_certificate"] = bool(before_sha and after_sha and before_sha != after_sha)

    finally:
        cleanup["test_certificates_removed"] = cleanup_tests(client)

    final_rows = ssl_rows(client)
    final_keys = {row_key(row) for row in final_rows if row_key(row)}
    cleanup["certificate_key_baseline_restored"] = final_keys == baseline_keys
    cleanup["leftover_test_certificates"] = sum(
        1 for row in final_rows if str(row.get("Remark", "")).startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if not value)
    if not cleanup.get("certificate_key_baseline_restored"):
        failed.append("certificate_key_baseline_restored")
    if cleanup.get("leftover_test_certificates") != 0:
        failed.append("leftover_test_certificates")

    print(
        json.dumps(
            {
                "target": "Lucky SSL ACME certificate lifecycle",
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
