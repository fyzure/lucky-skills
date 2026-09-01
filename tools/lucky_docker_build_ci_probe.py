#!/usr/bin/env python3
"""Run Lucky Docker image build handlers only on a GitHub-hosted CI runner.

This probe intentionally refuses local/production execution. It starts a fresh
Lucky 3.0.0 container pinned to the image digest already verified by this
repository, exposes the admin listener only on runner loopback, logs in with
the disposable instance's default credentials, enables a random OpenToken,
and exercises the ZIP and Git image-build handlers against the runner's
ephemeral Docker daemon.

The Git path never reaches an external Git service. A read-only fake ``git``
wrapper mounted into the disposable Lucky container implements only the
``clone`` operation by copying an owned TEST context. Both build contexts use
``FROM scratch`` and contain one tiny marker file, so the probe performs no
image pull/build dependency work beyond Lucky itself.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


PINNED_LUCKY_IMAGE = (
    "gdy666/lucky@sha256:0ea4276bcb7e57bc528ac2f3fa28cfec100103a2089087b30b1e8f7eca02c003"
)
EXPECTED_LUCKY_VERSION = "3.0.0"
DEFAULT_ADMIN_ACCOUNT = "666"
DEFAULT_ADMIN_PASSWORD = "666"
ADMIN_PORT = 16601
TEST_PREFIX = "TEST-lucky-skills-docker-build-ci-"
MAX_HTTP_BYTES = 4 * 1024 * 1024


class ProbeError(RuntimeError):
    pass


def require_github_hosted_runner() -> Path:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ProbeError("refusing Docker build probe outside GitHub Actions")
    if not os.environ.get("GITHUB_RUN_ID"):
        raise ProbeError("missing GITHUB_RUN_ID")
    runner_temp = os.environ.get("RUNNER_TEMP", "").strip()
    if not runner_temp:
        raise ProbeError("missing RUNNER_TEMP")
    temp_path = Path(runner_temp).resolve()
    if not temp_path.is_dir():
        raise ProbeError("RUNNER_TEMP is not a directory")
    return temp_path


def run(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            args,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.decode("utf-8", errors="replace").strip()
        stdout = error.stdout.decode("utf-8", errors="replace").strip()
        detail = (stderr or stdout)[:1000]
        raise ProbeError(f"command failed: {args[0]} ({detail})") from None
    except subprocess.TimeoutExpired:
        raise ProbeError(f"command timed out: {args[0]}") from None


def docker(*args: str, timeout: int = 120) -> str:
    result = run(["docker", *args], timeout=timeout)
    return result.stdout.decode("utf-8", errors="replace").strip()


def pull_pinned_image() -> None:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            docker("pull", PINNED_LUCKY_IMAGE, timeout=180)
            return
        except Exception as error:  # noqa: BLE001 - bounded retry around Docker Hub
            last_error = error
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
    raise ProbeError(f"unable to pull pinned Lucky image: {type(last_error).__name__}")


def choose_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def split_utf8_chunks(value: str, limit: int = 120) -> list[str]:
    chunks: list[str] = []
    current = ""
    current_bytes = 0
    for char in value:
        size = len(char.encode("utf-8"))
        if current and current_bytes + size > limit:
            chunks.append(current)
            current = ""
            current_bytes = 0
        current += char
        current_bytes += size
    if current:
        chunks.append(current)
    return chunks


def rsa_encrypt_with_openssl(public_key_pem: str, plaintext: str, workdir: Path) -> str:
    key_path = workdir / "login-public-key.pem"
    key_path.write_text(public_key_pem, encoding="utf-8")
    encoded: list[str] = []
    for chunk in split_utf8_chunks(plaintext):
        result = run(
            [
                "openssl",
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                str(key_path),
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
            ],
            input_bytes=chunk.encode("utf-8"),
            timeout=30,
        )
        encoded.append(base64.b64encode(result.stdout).decode("ascii"))
    return ".".join(encoded)


def read_http_body(response: Any) -> bytes:
    body = response.read(MAX_HTTP_BYTES + 1)
    if len(body) > MAX_HTTP_BYTES:
        raise ProbeError("HTTP response exceeded probe limit")
    return body


def json_request(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: Any | None = None,
    open_token: str = "",
    timeout: int = 30,
) -> tuple[int, dict[str, Any]]:
    body = None
    headers = {"Accept": "application/json", "User-Agent": "lucky-skills-ci-probe/1"}
    if open_token:
        headers["openToken"] = open_token
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = read_http_body(response)
            status = int(response.status)
    except urllib.error.HTTPError as error:
        raw = read_http_body(error)
        status = int(error.code)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeError(f"non-JSON response for {method} {path}, HTTP {status}") from None
    if not isinstance(decoded, dict):
        raise ProbeError(f"unexpected JSON type for {method} {path}")
    return status, decoded


def require_ret_zero(status: int, payload: dict[str, Any], label: str) -> dict[str, Any]:
    if status != 200 or payload.get("ret") != 0:
        msg = str(payload.get("msg") or payload.get("message") or "")[:300]
        raise ProbeError(f"{label} failed: HTTP {status}, ret={payload.get('ret')}, msg={msg!r}")
    return payload


def wait_for_lucky(base_url: str, container_name: str, timeout: int = 45) -> None:
    opener = urllib.request.build_opener()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload = json_request(opener, base_url, "/api/login/challenge", timeout=3)
            if status == 200 and payload.get("ret") == 0:
                return
        except Exception:  # noqa: BLE001 - readiness loop is intentionally broad
            pass
        time.sleep(1)
    logs = docker("logs", "--tail", "80", container_name, timeout=30)
    raise ProbeError(f"Lucky did not become ready; tail length={len(logs)}")


def login_default_admin(base_url: str, workdir: Path) -> urllib.request.OpenerDirector:
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    status, challenge = json_request(opener, base_url, "/api/login/challenge")
    require_ret_zero(status, challenge, "login challenge")
    required = ("challengeId", "nonce", "publicKey")
    if not all(challenge.get(key) for key in required):
        raise ProbeError("login challenge missing required fields")
    plaintext = json.dumps(
        {
            "account": DEFAULT_ADMIN_ACCOUNT,
            "password": DEFAULT_ADMIN_PASSWORD,
            "twoFA": "",
            "challengeId": challenge["challengeId"],
            "nonce": challenge["nonce"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    cipher = rsa_encrypt_with_openssl(str(challenge["publicKey"]), plaintext, workdir)
    status, response = json_request(
        opener,
        base_url,
        "/api/login",
        method="POST",
        payload={"challengeId": challenge["challengeId"], "cipherText": cipher},
    )
    require_ret_zero(status, response, "default admin login")
    if not list(cookie_jar):
        raise ProbeError("default admin login returned no session cookie")
    return opener


def enable_open_token(
    session: urllib.request.OpenerDirector,
    base_url: str,
    token: str,
) -> None:
    status, response = json_request(session, base_url, "/api/baseconfigure")
    require_ret_zero(status, response, "read baseconfigure")
    config = response.get("configure")
    if not isinstance(config, dict):
        raise ProbeError("baseconfigure response missing configure object")
    updated = dict(config)
    updated["EnableOpenToken"] = True
    updated["OpenToken"] = token
    updated["OpenTokenConfirmed"] = True
    # The disposable CI instance is loopback-published only. These two flags
    # prevent first-save security guards for an empty SafeURL/default account
    # from blocking OpenToken setup; they never touch a persistent instance.
    updated["IgnoreSafeURLCheck"] = True
    updated["IgnoreAuthInfoCheck"] = True
    status, result = json_request(session, base_url, "/api/baseconfigure", method="PUT", payload=updated)
    require_ret_zero(status, result, "enable OpenToken")

    token_opener = urllib.request.build_opener()
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            check_status, check = json_request(
                token_opener,
                base_url,
                "/api/status",
                open_token=token,
                timeout=3,
            )
            if check_status == 200 and isinstance(check.get("ret"), int):
                return
        except Exception:  # noqa: BLE001 - bounded activation poll
            pass
        time.sleep(1)
    raise ProbeError("OpenToken did not become usable")


def configure_docker_temp_path(base_url: str, token: str, temp_path: str) -> None:
    opener = urllib.request.build_opener()
    status, response = json_request(opener, base_url, "/api/docker/config", open_token=token)
    require_ret_zero(status, response, "read Docker config")
    config = response.get("config")
    if not isinstance(config, dict):
        raise ProbeError("Docker config response missing config object")
    updated = dict(config)
    updated["temp_operation_path"] = temp_path
    status, result = json_request(
        opener,
        base_url,
        "/api/docker/config",
        method="POST",
        payload=updated,
        open_token=token,
    )
    require_ret_zero(status, result, "set Docker temp_operation_path")
    status, verify = json_request(opener, base_url, "/api/docker/config", open_token=token)
    require_ret_zero(status, verify, "verify Docker config")
    verify_config = verify.get("config")
    if not isinstance(verify_config, dict) or verify_config.get("temp_operation_path") != temp_path:
        raise ProbeError("Docker temp_operation_path readback mismatch")


def image_ids() -> set[str]:
    output = docker("image", "ls", "--no-trunc", "--format", "{{.ID}}", timeout=30)
    return {line.strip() for line in output.splitlines() if line.strip()}


def image_label(image_id: str, key: str) -> str:
    raw = docker("image", "inspect", image_id, "--format", "{{json .Config.Labels}}", timeout=30)
    try:
        labels = json.loads(raw) if raw and raw != "null" else {}
    except json.JSONDecodeError:
        return ""
    return str(labels.get(key) or "") if isinstance(labels, dict) else ""


def marker_from_image(image_id: str, expected: str, workdir: Path, nonce: str) -> None:
    inspect_name = f"lucky-build-inspect-{nonce}-{secrets.token_hex(3)}"
    output_path = workdir / f"{inspect_name}.txt"
    try:
        docker("create", "--name", inspect_name, image_id, "/marker.txt", timeout=30)
        docker("cp", f"{inspect_name}:/marker.txt", str(output_path), timeout=30)
        content = output_path.read_text(encoding="utf-8").strip()
        if content != expected:
            raise ProbeError("built image marker mismatch")
    finally:
        run(["docker", "rm", "-f", inspect_name], check=False, timeout=30)
        output_path.unlink(missing_ok=True)


def call_build(base_url: str, token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    opener = urllib.request.build_opener()
    status, response = json_request(
        opener,
        base_url,
        path,
        method="POST",
        payload=payload,
        open_token=token,
        timeout=150,
    )
    return require_ret_zero(status, response, path)


def write_context(context_dir: Path, label_value: str, marker_value: str) -> None:
    context_dir.mkdir(parents=True, exist_ok=True)
    (context_dir / "marker.txt").write_text(marker_value + "\n", encoding="utf-8")
    dockerfile = (
        "FROM scratch\n"
        f'LABEL lucky.skills.probe="{label_value}"\n'
        "COPY marker.txt /marker.txt\n"
    )
    (context_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")


def write_zip_context(context_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(context_dir / "Dockerfile", "Dockerfile")
        archive.write(context_dir / "marker.txt", "marker.txt")


def write_fake_git(wrapper_path: Path) -> None:
    wrapper_path.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  echo "git version 2.45.0-lucky-skills-fake"
  exit 0
fi
if [ "${1:-}" = "clone" ]; then
  shift
  last=""
  nonopt_count=0
  for arg in "$@"; do
    last="$arg"
    case "$arg" in
      -*) ;;
      *) nonopt_count=$((nonopt_count + 1)) ;;
    esac
  done
  if [ "$nonopt_count" -lt 2 ] || [ -z "$last" ]; then
    echo "fake git requires clone URL and destination" >&2
    exit 2
  fi
  mkdir -p "$last"
  cp -a /ci/git-context/. "$last"/
  exit 0
fi
echo "unsupported fake git invocation" >&2
exit 2
""",
        encoding="utf-8",
    )
    wrapper_path.chmod(0o755)


def select_built_image(before: set[str], label_key: str, label_value: str) -> tuple[str, set[str]]:
    after = image_ids()
    new_ids = after - before
    matches = [image_id for image_id in new_ids if image_label(image_id, label_key) == label_value]
    if len(matches) != 1:
        raise ProbeError(
            f"expected exactly one labeled image, got matches={len(matches)} new_images={len(new_ids)}"
        )
    return matches[0], new_ids


def main() -> int:
    runner_temp = require_github_hosted_runner()
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        raise ProbeError("docker and openssl are required on the GitHub runner")

    nonce = secrets.token_hex(5)
    label_key = "lucky.skills.probe"
    zip_label = TEST_PREFIX + nonce + "-zip"
    git_label = TEST_PREFIX + nonce + "-git"
    zip_marker = TEST_PREFIX + nonce + "-zip-marker"
    git_marker = TEST_PREFIX + nonce + "-git-marker"
    container_name = f"lucky-build-ci-{nonce}"
    host_port = choose_loopback_port()
    base_url = f"http://127.0.0.1:{host_port}"
    open_token = secrets.token_hex(16)

    created_images: set[str] = set()
    report: dict[str, Any] = {
        "lucky_version": "",
        "zip_build": False,
        "git_build": False,
        "cleanup": False,
        "network_scope": "runner-loopback",
        "git_source": "local-fake-clone",
    }

    with tempfile.TemporaryDirectory(prefix="lucky-build-ci-", dir=runner_temp) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        conf_dir = temp_dir / "conf"
        fixture_dir = temp_dir / "fixtures"
        zip_context = fixture_dir / "zip-context"
        git_context = fixture_dir / "git-context"
        zip_path = fixture_dir / "context.zip"
        fake_git = temp_dir / "git"
        conf_dir.mkdir()
        fixture_dir.mkdir()
        write_context(zip_context, zip_label, zip_marker)
        write_context(git_context, git_label, git_marker)
        write_zip_context(zip_context, zip_path)
        write_fake_git(fake_git)

        pull_pinned_image()
        baseline_images = image_ids()

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
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                f"{conf_dir}:/app/conf",
                "-v",
                f"{fixture_dir}:/ci:ro",
                "-v",
                f"{fake_git}:/usr/local/bin/git:ro",
                PINNED_LUCKY_IMAGE,
                timeout=90,
            )
            wait_for_lucky(base_url, container_name)

            info_raw = docker("exec", container_name, "/app/lucky", "-info", timeout=30)
            info = json.loads(info_raw)
            version = str(info.get("Version") or "")
            report["lucky_version"] = version
            if version != EXPECTED_LUCKY_VERSION:
                raise ProbeError(f"unexpected Lucky version: {version!r}")

            session = login_default_admin(base_url, temp_dir)
            enable_open_token(session, base_url, open_token)
            docker("exec", container_name, "mkdir", "-p", "/tmp/lucky-skills-docker-build-ci", timeout=30)
            configure_docker_temp_path(base_url, open_token, "/tmp/lucky-skills-docker-build-ci")

            before_zip = image_ids()
            call_build(
                base_url,
                open_token,
                "/api/docker/images/build-from-zip",
                {"zip_path": "/ci/context.zip"},
            )
            zip_image, zip_new = select_built_image(before_zip, label_key, zip_label)
            created_images.update(zip_new)
            marker_from_image(zip_image, zip_marker, temp_dir, nonce)
            report["zip_build"] = True

            before_git = image_ids()
            call_build(
                base_url,
                open_token,
                "/api/docker/images/build-from-git",
                {"git_url": "https://example.invalid/TEST-lucky-skills.git"},
            )
            git_image, git_new = select_built_image(before_git, label_key, git_label)
            created_images.update(git_new)
            marker_from_image(git_image, git_marker, temp_dir, nonce)
            report["git_build"] = True
        finally:
            run(["docker", "rm", "-f", container_name], check=False, timeout=45)
            current = image_ids()
            cleanup_targets = (current - baseline_images) | created_images
            for image_id in sorted(cleanup_targets):
                run(["docker", "image", "rm", "-f", image_id], check=False, timeout=45)
            report["cleanup"] = image_ids() == baseline_images

    failed = [key for key in ("zip_build", "git_build", "cleanup") if report.get(key) is not True]
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
