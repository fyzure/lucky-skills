#!/usr/bin/env python3
"""Runtime-verify Lucky v3 localhost SSH host-key and SFTP behavior.

This bounded probe uses the RS host's existing sshd on 127.0.0.1:39147. It
generates one ephemeral Ed25519 key, appends one localhost-only authorization
line, creates one TEST WebTerminal SSH connection, exercises Lucky's explicit
first-use host-key confirmation flow, opens a real SSH terminal session, and
uses that session for isolated SFTP operations under /tmp/TEST-*.

The probe verifies mkdir/touch/write/read/rename/copy/chmod, archive
compress/preview/decompress, session closure, and cleanup. It also executes
the current frontend shapes for multipart and streaming uploads and records
their runtime result; on the verified Lucky 3.0.0 instance both upload routes
currently fail and are treated as defects rather than successful capability.
SSH private keys, server host keys/fingerprints, terminal output, and file
content are never emitted in the JSON result.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
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

from tools.lucky_ssl_sync_probe import (  # noqa: E402
    append_ephemeral_authorization,
    remove_ephemeral_authorization,
)
from lucky_api.client import LuckyAPIError, TransportError  # noqa: E402
from tools.lucky_webterminal_probe import (  # noqa: E402
    TEST_PREFIX as TERMINAL_TEST_PREFIX,
    connection_key,
    connection_rows,
    credentials,
    delete_test_connections,
    delete_test_sessions,
    make_client,
    masked_frame,
    mutate,
    read_until,
    session_id,
    session_rows,
    websocket_for_path,
)


CONFIRMATION = "PROBE-AND-CLEAN-WEBTERMINAL-SFTP"
TEST_PREFIX = "TEST-lucky-skills-webterminal-sftp-"
SSH_MARKER_PREFIX = "TEST-lucky-skills-webterminal-sftp-key-"


def multipart_upload(path: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----lucky-skills-sftp-" + secrets.token_hex(12)
    chunks: list[bytes] = []
    # Match the current Lucky frontend's FormData append order exactly:
    # file -> path -> filename. The TEST filename is ASCII, so the frontend's
    # encodeURIComponent(file.name) produces the same value here.
    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        + content
        + b"\r\n"
    )
    for name, value in (("path", path), ("filename", filename)):
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")
        )
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def connection_detail(client: Any, key: str) -> dict[str, Any]:
    payload = client.request_json("GET", f"/api/webterminal/connections/{key}")
    row = payload.get("connection") if isinstance(payload, dict) else None
    if not isinstance(row, dict):
        raise RuntimeError("unexpected WebTerminal connection detail response")
    return row


def safe_test_connection(client: Any, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.request(
        "POST",
        "/api/webterminal/connections/test",
        json_body=payload,
        allow_unsafe=True,
        raise_for_lucky=False,
    )
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("unexpected WebTerminal connection test response")
    return value


def sanitized_saved_connection(connection: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(json.dumps(connection))
    ssh_config = payload.get("sshConfig")
    if isinstance(ssh_config, dict):
        for key in ("password", "privateKey", "passphrase"):
            if ssh_config.get(key) in {"", "******"}:
                ssh_config.pop(key, None)
        proxy = ssh_config.get("proxy")
        if isinstance(proxy, dict) and proxy.get("password") in {"", "******"}:
            proxy.pop("password", None)
    return payload


def sftp_json(
    client: Any,
    method: str,
    sid: str,
    action: str,
    *,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if query is not None:
        kwargs["query"] = query
    if body is not None:
        kwargs["json_body"] = body
        kwargs["body_supplied"] = True
    value = mutate(client, method, f"/api/webterminal/sftp/{sid}/{action}", **kwargs)
    if not isinstance(value, dict):
        raise RuntimeError(f"unexpected SFTP {action} response")
    return value


def read_content(client: Any, sid: str, path: str) -> str:
    value = client.request_json(
        "GET", f"/api/webterminal/sftp/{sid}/read", query={"path": path}
    )
    content = value.get("content") if isinstance(value, dict) else None
    return content if isinstance(content, str) else ""


def list_path(client: Any, sid: str, path: str) -> tuple[str, list[dict[str, Any]]]:
    value = client.request_json(
        "GET", f"/api/webterminal/sftp/{sid}/list", query={"path": path}
    )
    files = value.get("files") if isinstance(value, dict) else None
    return str(value.get("path") or ""), [
        row for row in files if isinstance(row, dict)
    ] if isinstance(files, list) else []


def cleanup_host_test_dir(path: Path) -> bool:
    try:
        if path.exists():
            shutil.rmtree(path)
        return not path.exists()
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--ssh-port", type=int, default=39147)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    base_url, token = credentials()
    client = make_client(base_url, token)
    baseline_connections = connection_rows(client)
    baseline_connection_keys = {
        connection_key(row) for row in baseline_connections if connection_key(row)
    }
    baseline_sessions = session_rows(client)
    baseline_session_ids = {session_id(row) for row in baseline_sessions if session_id(row)}

    nonce = secrets.token_hex(5)
    name = TEST_PREFIX + nonce
    key = "conn_sftp_test_" + nonce
    ssh_marker = SSH_MARKER_PREFIX + nonce
    host_dir = Path("/tmp") / (TEST_PREFIX + nonce)
    if host_dir.exists():
        raise RuntimeError("pre-existing TEST SFTP directory found")

    key_dir = Path(tempfile.mkdtemp(prefix="TEST-lucky-skills-wt-sftp-key-", dir="/tmp"))
    private_key_path = key_dir / "id_ed25519"
    authorization_path: Path | None = None
    ws: socket.socket | None = None
    sid = ""
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
        pub = private_key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()

        # The SSL helper uses `restrict`, which intentionally disables PTY.
        # WebTerminal needs PTY, so replace that exact TEST line with a
        # localhost-only line that still disables forwarding/X11/agent use.
        authorization_path = append_ephemeral_authorization(ssh_marker, pub)
        lines = authorization_path.read_text(encoding="utf-8").splitlines()
        replaced: list[str] = []
        for line in lines:
            if ssh_marker in line:
                key_material = " ".join(pub.split()[:2])
                replaced.append(
                    f'from="127.0.0.1",no-agent-forwarding,no-port-forwarding,'
                    f'no-X11-forwarding,no-user-rc {key_material} {ssh_marker}'
                )
            else:
                replaced.append(line)
        authorization_path.write_text("\n".join(replaced) + "\n", encoding="utf-8")
        authorization_path.chmod(0o600)
        results["ephemeral_ssh_authorization_added"] = True

        payload = {
            "key": key,
            "name": name,
            "type": "ssh",
            "remark": "Lucky skills localhost SSH/SFTP runtime probe",
            "localConfig": {"shell": "/bin/sh", "workDir": "/tmp"},
            "sshConfig": {
                "host": "127.0.0.1",
                "port": args.ssh_port,
                "username": "root",
                "authType": "key",
                "password": "",
                "privateKey": private_key_path.read_text(encoding="utf-8"),
                "keyFile": "",
                "passphrase": "",
                "timeout": 10,
                "keepAlive": 0,
                "workDir": "/tmp",
                "hostKey": "",
                "hostKeyFingerprint": "",
                "hostKeyTrustedAt": "",
                "proxy": {"type": "", "host": "", "port": 0, "username": "", "password": ""},
            },
            "telnetConfig": {},
            "shortcuts": [],
            "quickAccessDirs": ["/tmp"],
        }

        created = mutate(
            client,
            "POST",
            "/api/webterminal/connections",
            json_body=payload,
            body_supplied=True,
        )
        results["ssh_connection_created"] = isinstance(created, dict) and created.get("ret") == 0

        first_test = safe_test_connection(client, payload)
        host_key = first_test.get("sshHostKey")
        results["first_test_requires_host_key_confirmation"] = (
            first_test.get("ret") == 409
            and isinstance(host_key, dict)
            and bool(host_key.get("hostKey"))
            and bool(host_key.get("hostKeyFingerprint"))
        )
        observations["first_test_ret"] = first_test.get("ret")
        observations["host_key_field_names"] = sorted(host_key.keys()) if isinstance(host_key, dict) else []
        if not results["first_test_requires_host_key_confirmation"]:
            raise RuntimeError("Lucky did not request first-use SSH host-key confirmation")

        trust_payload = {
            "host": str(host_key.get("host") or "127.0.0.1"),
            "port": int(host_key.get("port") or args.ssh_port),
            "hostname": str(host_key.get("hostname") or ""),
            "hostKey": str(host_key.get("hostKey") or ""),
            "hostKeyFingerprint": str(host_key.get("hostKeyFingerprint") or ""),
            "hostKeyTrustedAt": str(host_key.get("hostKeyTrustedAt") or ""),
            "keyType": str(host_key.get("keyType") or ""),
            "previousHostKeyFingerprint": str(host_key.get("previousHostKeyFingerprint") or ""),
            "changed": bool(host_key.get("changed")),
        }
        trusted = mutate(
            client,
            "PUT",
            f"/api/webterminal/connections/{key}/ssh-host-key",
            json_body=trust_payload,
            body_supplied=True,
        )
        results["host_key_trusted"] = isinstance(trusted, dict) and trusted.get("ret") == 0

        saved = connection_detail(client, key)
        saved_ssh = saved.get("sshConfig") if isinstance(saved.get("sshConfig"), dict) else {}
        results["trusted_host_key_persisted"] = bool(saved_ssh.get("hostKeyFingerprint"))

        # The frontend intentionally requires the private key to be supplied
        # again when testing an already-saved key-auth connection. Saved
        # credentials are masked, so test the trusted host key using the
        # original disposable private key plus the persisted host-key fields.
        trusted_test_payload = json.loads(json.dumps(payload))
        trusted_test_ssh = trusted_test_payload["sshConfig"]
        for field in ("hostKey", "hostKeyFingerprint", "hostKeyTrustedAt"):
            trusted_test_ssh[field] = str(saved_ssh.get(field) or "")
        second_test = safe_test_connection(client, trusted_test_payload)
        results["connection_test_after_host_key_trust"] = second_test.get("ret") == 0
        observations["second_test_ret"] = second_test.get("ret")

        ws = websocket_for_path(client, base_url, f"/api/webterminal/connect/{key}")
        connected, sid, message_keys = read_until(ws, need_event="connected", timeout=20.0)
        results["ssh_terminal_connected"] = connected and bool(sid)
        observations["connect_message_key_sets"] = message_keys

        marker = f"LUCKY_SKILLS_SSH_246_{nonce}".encode("ascii")
        command = f"printf 'LUCKY_SKILLS_SSH_%d_{nonce}\\n' $((123+123))\r".encode("utf-8")
        ws.sendall(masked_frame(0x1, command))
        marker_seen, _, _ = read_until(ws, marker=marker, timeout=20.0)
        results["ssh_terminal_roundtrip"] = marker_seen

        sftp_json(client, "POST", sid, "mkdir", body={"path": str(host_dir)})
        results["sftp_mkdir"] = host_dir.is_dir()
        listed_path, listed = list_path(client, sid, str(host_dir))
        results["sftp_list"] = listed_path == str(host_dir) and isinstance(listed, list)

        original = host_dir / "original.txt"
        renamed = host_dir / "renamed.txt"
        copied = host_dir / "copied.txt"
        content = f"Lucky skills SFTP write {nonce}\n"
        sftp_json(client, "POST", sid, "touch", body={"path": str(original)})
        results["sftp_touch"] = original.is_file()
        sftp_json(client, "POST", sid, "write", body={"path": str(original), "content": content})
        results["sftp_write_read"] = read_content(client, sid, str(original)) == content

        sftp_json(
            client,
            "POST",
            sid,
            "rename",
            body={"oldPath": str(original), "newPath": str(renamed)},
        )
        results["sftp_rename"] = renamed.is_file() and not original.exists()

        sftp_json(
            client,
            "POST",
            sid,
            "copy",
            body={"src_path": str(renamed), "dst_path": str(copied)},
        )
        results["sftp_copy"] = copied.is_file() and copied.read_text(encoding="utf-8") == content

        sftp_json(
            client,
            "POST",
            sid,
            "chmod",
            body={"path": str(copied), "permissions": "0640"},
        )
        results["sftp_chmod"] = (copied.stat().st_mode & 0o777) == 0o640

        multipart_name = "multipart.bin"
        multipart_data = ("multipart-" + nonce).encode("utf-8")
        multipart_body, multipart_type = multipart_upload(
            str(host_dir), multipart_name, multipart_data
        )
        try:
            multipart_resp = client.request(
                "POST",
                f"/api/webterminal/sftp/{sid}/upload",
                raw_body=multipart_body,
                content_type=multipart_type,
                allow_unsafe=True,
            )
            multipart_json = multipart_resp.json()
            results["sftp_multipart_upload"] = (
                isinstance(multipart_json, dict)
                and multipart_json.get("ret") == 0
                and (host_dir / multipart_name).read_bytes() == multipart_data
            )
        except LuckyAPIError as error:
            results["sftp_multipart_upload"] = False
            observations["multipart_upload_ret"] = error.ret
            observations["multipart_upload_error_class"] = (
                "ssh-fx-failure"
                if "ssh_fx_failure" in str(error).lower()
                else "lucky-api-error"
            )

        # Use an archive format supported by the existing RS userspace. The
        # host has tar+gzip but no zip/unzip; installing packages solely for a
        # runtime probe would distort the environment under test.
        archive = host_dir / "bundle.tar.gz"
        compressed = sftp_json(
            client,
            "POST",
            sid,
            "compress",
            body={
                "paths": [str(renamed), str(copied)],
                "output_path": str(host_dir),
                "output_name": archive.name,
            },
        )
        results["sftp_compress"] = compressed.get("ret") == 0 and archive.is_file()

        preview = client.request_json(
            "GET",
            f"/api/webterminal/sftp/{sid}/preview-archive",
            query={"path": str(archive)},
        )
        results["sftp_archive_preview"] = preview.get("ret") == 0
        observations["archive_preview_fields"] = sorted(
            key for key in preview.keys() if key != "ret"
        )

        extracted = host_dir / "extracted"
        sftp_json(client, "POST", sid, "mkdir", body={"path": str(extracted)})
        decompressed = sftp_json(
            client,
            "POST",
            sid,
            "decompress",
            body={"file_path": str(archive), "output_path": str(extracted)},
        )
        results["sftp_decompress"] = (
            decompressed.get("ret") == 0
            and any(path.is_file() for path in extracted.rglob("*"))
        )

        removed = sftp_json(
            client,
            "DELETE",
            sid,
            "remove",
            query={"path": str(host_dir)},
        )
        results["sftp_remove_test_tree"] = removed.get("ret") == 0 and not host_dir.exists()

        # Test streaming upload last because Lucky 3.0.0 has been observed to
        # close the SFTP pipe on this route. Isolate it in a second TEST tree
        # so a handler failure cannot invalidate the preceding SFTP evidence.
        stream_dir = Path(str(host_dir) + "-stream")
        sftp_json(client, "POST", sid, "mkdir", body={"path": str(stream_dir)})
        streaming_name = "streaming.bin"
        streaming_data = (("streaming-" + nonce + "\n").encode("utf-8") * 65536)[: 1024 * 1024]
        observations["streaming_upload_bytes"] = len(streaming_data)
        try:
            stream_resp = client.request(
                "POST",
                f"/api/webterminal/sftp/{sid}/upload-streaming",
                query={"path": str(stream_dir), "filename": streaming_name},
                raw_body=streaming_data,
                content_type="application/octet-stream",
                allow_unsafe=True,
            )
            stream_json = stream_resp.json()
            results["sftp_streaming_upload"] = (
                isinstance(stream_json, dict)
                and stream_json.get("ret") == 0
                and (stream_dir / streaming_name).read_bytes() == streaming_data
            )
        except LuckyAPIError as error:
            results["sftp_streaming_upload"] = False
            observations["streaming_upload_ret"] = error.ret
            observations["streaming_upload_error_class"] = (
                "closed-pipe" if "closed pipe" in str(error).lower() else "lucky-api-error"
            )
        except TransportError as error:
            results["sftp_streaming_upload"] = False
            observations["streaming_upload_error_class"] = (
                "broken-pipe" if "BrokenPipeError" in str(error) else "transport-error"
            )

        closed = mutate(client, "DELETE", f"/api/webterminal/sessions/{sid}")
        results["session_deleted"] = isinstance(closed, dict) and closed.get("ret") == 0
        deleted = mutate(client, "DELETE", f"/api/webterminal/connections/{key}")
        results["connection_deleted"] = isinstance(deleted, dict) and deleted.get("ret") == 0
    finally:
        if ws is not None:
            try:
                ws.sendall(masked_frame(0x8))
            except OSError:
                pass
            try:
                ws.close()
            except OSError:
                pass
        cleanup["test_sessions_removed"] = delete_test_sessions(client)
        cleanup["test_connections_removed"] = delete_test_connections(client)
        cleanup["test_directory_removed"] = cleanup_host_test_dir(host_dir)
        stream_dir = Path(str(host_dir) + "-stream")
        cleanup["stream_test_directory_removed"] = cleanup_host_test_dir(stream_dir)
        if authorization_path is not None:
            cleanup["ephemeral_ssh_authorization_removed"] = remove_ephemeral_authorization(
                authorization_path, ssh_marker
            )
        else:
            cleanup["ephemeral_ssh_authorization_removed"] = True
        shutil.rmtree(key_dir, ignore_errors=True)
        cleanup["ephemeral_key_directory_removed"] = not key_dir.exists()

    final_connections = connection_rows(client)
    final_sessions = session_rows(client)
    cleanup["connection_key_baseline_restored"] = {
        connection_key(row) for row in final_connections if connection_key(row)
    } == baseline_connection_keys
    cleanup["session_id_baseline_restored"] = {
        session_id(row) for row in final_sessions if session_id(row)
    } == baseline_session_ids
    cleanup["no_test_connections"] = not any(
        str(row.get("name") or row.get("Name") or "").startswith(
            (TEST_PREFIX, TERMINAL_TEST_PREFIX)
        )
        for row in final_connections
    )

    failed = sorted(key for key, value in results.items() if not value)
    for key_name in (
        "test_directory_removed",
        "stream_test_directory_removed",
        "ephemeral_ssh_authorization_removed",
        "ephemeral_key_directory_removed",
        "connection_key_baseline_restored",
        "session_id_baseline_restored",
        "no_test_connections",
    ):
        if not cleanup.get(key_name):
            failed.append(key_name)

    print(
        json.dumps(
            {
                "target": "Lucky WebTerminal localhost SSH host-key + SFTP behavior",
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
