#!/usr/bin/env python3
"""Verify remaining Lucky route/method pairs on an isolated GitHub runner.

This probe is deliberately narrower than a behavior test. It starts the
repository-pinned Lucky 3.0.0 image on a Docker ``--internal`` network, never
logs in, never enables OpenToken, and probes only merged routes that are still
``frontend-call`` and are classified read-only or mutating. Dangerous routes
are skipped entirely.

For each HTTP method the probe compares a known protected route with a random
missing route. A target is accepted when it either reaches the same calibrated
authentication gate as the known route, or returns another non-404/non-405
route-specific response distinct from the missing-route control. This proves
only ``METHOD + path`` existence on the pinned runtime; it does not claim a
successful business handler execution or complete schema semantics.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lucky_api import load_merged_snapshot
from lucky_api.catalog import classify_known_operation


PINNED_LUCKY_IMAGE = (
    "gdy666/lucky@sha256:0ea4276bcb7e57bc528ac2f3fa28cfec100103a2089087b30b1e8f7eca02c003"
)
EXPECTED_LUCKY_VERSION = "3.0.0"
ADMIN_PORT = 16601
MAX_HTTP_BYTES = 64 * 1024
MINIMUM_VERIFIED = 50
HTTP_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

POSITIVE_CONTROLS = {
    "GET": "/api/baseconfigure",
    "POST": "/api/cron/list",
    "PUT": "/api/cron/list",
    "DELETE": "/api/cron/list",
}

# These are not dangerous in the catalog, but could disrupt the one shared
# disposable instance if authentication behavior ever changed. They are not
# needed to meet the requested coverage target, so keep them out of this probe.
STATEFUL_EXCLUSIONS = {
    ("PUT", "/api/logout"),
    ("PUT", "/api/lucky/service"),
}


class ProbeError(RuntimeError):
    pass


def require_github_hosted_runner() -> Path:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ProbeError("refusing route-method probe outside GitHub Actions")
    if not os.environ.get("GITHUB_RUN_ID"):
        raise ProbeError("missing GITHUB_RUN_ID")
    runner_temp = os.environ.get("RUNNER_TEMP", "").strip()
    if not runner_temp:
        raise ProbeError("missing RUNNER_TEMP")
    path = Path(runner_temp).resolve()
    if not path.is_dir():
        raise ProbeError("RUNNER_TEMP is not a directory")
    return path


def run(args: list[str], *, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout).decode("utf-8", errors="replace")[:1000]
        raise ProbeError(f"command failed: {args[0]} ({detail})") from None
    except subprocess.TimeoutExpired:
        raise ProbeError(f"command timed out: {args[0]}") from None


def docker(*args: str, timeout: int = 120, check: bool = True) -> str:
    result = run(["docker", *args], timeout=timeout, check=check)
    return result.stdout.decode("utf-8", errors="replace").strip()


def pull_pinned_image() -> None:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            docker("pull", PINNED_LUCKY_IMAGE, timeout=180)
            return
        except Exception as error:  # noqa: BLE001 - bounded Docker Hub retry
            last_error = error
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
    raise ProbeError(f"unable to pull pinned Lucky image: {type(last_error).__name__}")


def materialize_path(path: str) -> str:
    return re.sub(r"\{[^/{}]+\}", "route-probe", path)


def request_signature(base_url: str, method: str, path: str) -> dict[str, Any]:
    body = b"{}" if method in {"POST", "PUT", "PATCH"} else None
    headers = {"Accept": "application/json, */*;q=0.1"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    try:
        response = HTTP_OPENER.open(request, timeout=5)
        status = int(response.status)
        content_type = str(response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        raw = response.read(MAX_HTTP_BYTES + 1)
        response.close()
    except urllib.error.HTTPError as error:
        status = int(error.code)
        content_type = str(error.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        raw = error.read(MAX_HTTP_BYTES + 1)
    except urllib.error.URLError as error:
        raise ProbeError(f"HTTP request failed for {method} {path}: {error.reason}") from None

    truncated = len(raw) > MAX_HTTP_BYTES
    raw = raw[:MAX_HTTP_BYTES]
    payload: Any = None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    signature: dict[str, Any] = {
        "status": status,
        "content_type": content_type,
        "kind": "json" if isinstance(payload, dict) else ("empty" if not raw else "non-json"),
        "truncated": truncated,
    }
    if isinstance(payload, dict):
        signature["ret"] = payload.get("ret")
        message = payload.get("msg") if "msg" in payload else payload.get("message")
        if message is not None:
            signature["message"] = str(message)[:160]
    return signature


def wait_for_lucky(base_url: str, container_name: str, timeout: int = 45) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            signature = request_signature(base_url, "GET", "/api/login/challenge")
            if signature.get("status") == 200 and signature.get("ret") == 0:
                return
        except Exception:  # noqa: BLE001 - readiness loop is intentionally broad
            pass
        time.sleep(1)
    logs = docker("logs", "--tail", "80", container_name, timeout=30, check=False)
    raise ProbeError(f"Lucky did not become ready; tail length={len(logs)}")


def cleanup_conf_dir(conf_dir: Path) -> None:
    if not conf_dir.exists():
        return
    docker(
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{conf_dir}:/cleanup",
        "--entrypoint",
        "/bin/sh",
        PINNED_LUCKY_IMAGE,
        "-c",
        "find /cleanup -mindepth 1 -maxdepth 1 -exec rm -rf {} +",
        timeout=60,
        check=False,
    )
    shutil.rmtree(conf_dir, ignore_errors=True)


def load_targets() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    snapshot_path = ROOT / "evidence" / "lucky-v3-endpoints.json"
    runtime_path = ROOT / "evidence" / "lucky-v3-runtime-verification.json"
    merged = load_merged_snapshot(snapshot_path, runtime_verification=runtime_path)
    if str(merged.get("target", {}).get("version")) != EXPECTED_LUCKY_VERSION:
        raise ProbeError("merged catalog no longer targets Lucky 3.0.0")

    targets: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for route in merged.get("routes", []):
        if route.get("confidence") != "frontend-call":
            continue
        method = str(route["method"]).upper()
        path = str(route["path"])
        risk = classify_known_operation(method, path).value
        row = {"method": method, "path": path, "risk": risk}
        if risk == "dangerous":
            row["reason"] = "dangerous"
            skipped.append(row)
            continue
        if (method, path) in STATEFUL_EXCLUSIONS:
            row["reason"] = "stateful-exclusion"
            skipped.append(row)
            continue
        targets.append(row)
    return targets, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None:
        raise ProbeError("docker is required on the GitHub runner")

    nonce = secrets.token_hex(5)
    container_name = f"lucky-route-method-{nonce}"
    network_name = f"lucky-route-method-{nonce}"
    conf_dir = Path(tempfile.mkdtemp(prefix="lucky-route-method-", dir=runner_temp))

    targets, skipped = load_targets()
    verified: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    controls: dict[str, Any] = {}

    try:
        pull_pinned_image()
        docker("network", "create", "--internal", network_name)
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
        )
        container_ip = docker(
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_name,
        ).strip()
        if not container_ip:
            raise ProbeError("disposable Lucky container has no internal-network IP")
        base_url = f"http://{container_ip}:{ADMIN_PORT}"
        wait_for_lucky(base_url, container_name)

        for method in sorted({row["method"] for row in targets}):
            positive_path = POSITIVE_CONTROLS.get(method)
            if not positive_path:
                raise ProbeError(f"missing positive control for method {method}")
            negative_path = f"/api/__lucky_skills_missing_{nonce}_{method.lower()}"
            positive = request_signature(base_url, method, positive_path)
            negative = request_signature(base_url, method, negative_path)
            controls[method] = {
                "positive_path": positive_path,
                "positive": positive,
                "negative": negative,
                "calibrated": positive != negative,
            }

        for row in targets:
            method = row["method"]
            path = row["path"]
            actual_path = materialize_path(path)
            signature = request_signature(base_url, method, actual_path)
            control = controls[method]
            classification = ""
            if control["calibrated"] and signature == control["positive"]:
                classification = "auth-gate"
            elif signature != control["negative"] and signature.get("status") not in {404, 405}:
                classification = "route-response"

            result = {
                **row,
                "classification": classification or "unverified",
                "status": signature.get("status"),
                "response_kind": signature.get("kind"),
            }
            if classification:
                verified.append(result)
                print(f"VERIFIED\t{method}\t{path}\t{classification}\tHTTP {signature.get('status')}")
            else:
                unverified.append(result)
                print(f"UNVERIFIED\t{method}\t{path}\tHTTP {signature.get('status')}")

        report = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": EXPECTED_LUCKY_VERSION},
            "pinned_image": PINNED_LUCKY_IMAGE,
            "network": "docker-internal",
            "authenticated": False,
            "open_token_enabled": False,
            "target_count": len(targets),
            "verified_count": len(verified),
            "unverified_count": len(unverified),
            "skipped_count": len(skipped),
            "verified_by_classification": dict(Counter(row["classification"] for row in verified)),
            "controls": controls,
            "verified": verified,
            "unverified": unverified,
            "skipped": skipped,
        }
        serialized = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        print("ROUTE_METHOD_REPORT=" + serialized)
        if args.report:
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if len(verified) < MINIMUM_VERIFIED:
            raise ProbeError(
                f"route-method coverage target missed: verified={len(verified)} minimum={MINIMUM_VERIFIED}"
            )
        return 0
    finally:
        docker("rm", "-f", container_name, timeout=60, check=False)
        docker("network", "rm", network_name, timeout=60, check=False)
        cleanup_conf_dir(conf_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"route-method probe failed: {error}", file=os.sys.stderr)
        raise SystemExit(1) from None
