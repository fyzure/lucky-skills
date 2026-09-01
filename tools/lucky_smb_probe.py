#!/usr/bin/env python3
"""Runtime-verify Lucky v3 SMB2 guest behavior on loopback only.

The probe requires an inactive SMB baseline with no configured users or shares.
It creates one unique local TEST directory through Lucky, starts SMB on a random
127.0.0.1 high port with WSDD/mDNS/NBNS disabled, and exposes exactly one
writable guest share.  A tiny dependency-free SMB2 client then performs:

  NEGOTIATE -> guest SESSION_SETUP -> TREE_CONNECT -> CREATE -> WRITE -> READ
  -> CLOSE(delete-on-close) -> TREE_DISCONNECT -> LOGOFF

The backing TEST file is cross-checked through Lucky local-path-browser while
open and after close.  The original stopped SMB configuration is restored only
while the live listener/share still carry this probe's ownership markers.
"""

from __future__ import annotations

import argparse
import copy
import json
import secrets
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from tools.lucky_storage_probe import (  # noqa: E402
    create_test_path,
    delete_test_path,
    path_entries,
)
from tools.lucky_stun_probe import make_client, mutate  # noqa: E402


CONFIRMATION = "PROBE-AND-CLEAN-SMB"
TEST_PREFIX = "TEST-lucky-skills-smb-"
STATUS_SUCCESS = 0
SMB2_SESSION_FLAG_IS_GUEST = 0x0001


def free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def smb_header(
    command: int,
    message_id: int,
    *,
    session_id: int = 0,
    tree_id: int = 0,
) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        0,
        0,
        command,
        32,
        0,
        0,
        message_id,
        0xFFFF,
        tree_id,
        session_id,
        b"\0" * 16,
    )


def netbios_frame(payload: bytes) -> bytes:
    return b"\0" + len(payload).to_bytes(3, "big") + payload


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected SMB socket EOF")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    length = int.from_bytes(header[1:4], "big")
    return recv_exact(sock, length)


def response_status(packet: bytes) -> int:
    return struct.unpack_from("<I", packet, 8)[0]


def response_session_id(packet: bytes) -> int:
    return struct.unpack_from("<Q", packet, 40)[0]


def response_tree_id(packet: bytes) -> int:
    return struct.unpack_from("<I", packet, 36)[0]


class SMB2GuestClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), timeout=3.0)
        self.sock.settimeout(4.0)
        self.session_id = 0
        self.tree_id = 0
        self.message_id = 0

    def close_socket(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, command: int, body: bytes) -> tuple[bytes, int]:
        packet = smb_header(
            command,
            self.message_id,
            session_id=self.session_id,
            tree_id=self.tree_id,
        ) + body
        self.message_id += 1
        self.sock.sendall(netbios_frame(packet))
        response = recv_frame(self.sock)
        return response, response_status(response)

    def negotiate(self) -> int:
        dialects = [0x0202, 0x0210]
        body = struct.pack(
            "<HHHHI16sIHH",
            36,
            len(dialects),
            1,
            0,
            0,
            secrets.token_bytes(16),
            0,
            0,
            0,
        ) + struct.pack("<HH", *dialects)
        packet, status = self.request(0, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 NEGOTIATE failed: 0x{status:08x}")
        return struct.unpack_from("<H", packet, 68)[0]

    def guest_session_setup(self) -> int:
        flags = 0xA0888205
        ntlm_type1 = (
            b"NTLMSSP\0"
            + struct.pack("<II", 1, flags)
            + struct.pack("<HHI", 0, 0, 32)
            + struct.pack("<HHI", 0, 0, 32)
        )
        body = struct.pack(
            "<HBBIIHHQ",
            25,
            0,
            1,
            0,
            0,
            88,
            len(ntlm_type1),
            0,
        ) + ntlm_type1
        packet, status = self.request(1, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 SESSION_SETUP failed: 0x{status:08x}")
        self.session_id = response_session_id(packet)
        if not self.session_id:
            raise RuntimeError("SMB2 SESSION_SETUP returned an empty SessionId")
        return struct.unpack_from("<H", packet, 66)[0]

    def tree_connect(self, share_name: str) -> None:
        unc = f"\\\\{self.host}\\{share_name}".encode("utf-16le")
        body = struct.pack("<HHHH", 9, 0, 72, len(unc)) + unc
        packet, status = self.request(3, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 TREE_CONNECT failed: 0x{status:08x}")
        self.tree_id = response_tree_id(packet)
        if not self.tree_id:
            raise RuntimeError("SMB2 TREE_CONNECT returned an empty TreeId")

    def create_delete_on_close(self, filename: str) -> bytes:
        name = filename.encode("utf-16le")
        desired_access = 0xC0010000
        file_attributes = 0x80
        share_access = 0x7
        create_disposition = 5
        create_options = 0x1040
        body = struct.pack(
            "<HBBIQQIIIIIHHII",
            57,
            0,
            0,
            2,
            0,
            0,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            120,
            len(name),
            0,
            0,
        ) + name
        packet, status = self.request(5, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 CREATE failed: 0x{status:08x}")
        file_id = packet[128:144]
        if len(file_id) != 16 or file_id == b"\0" * 16:
            raise RuntimeError("SMB2 CREATE returned an invalid FileId")
        return file_id

    def write(self, file_id: bytes, data: bytes) -> int:
        body = struct.pack(
            "<HHIQ16sIIHHI",
            49,
            112,
            len(data),
            0,
            file_id,
            0,
            0,
            0,
            0,
            0,
        ) + data
        packet, status = self.request(9, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 WRITE failed: 0x{status:08x}")
        return struct.unpack_from("<I", packet, 68)[0]

    def read(self, file_id: bytes, length: int) -> bytes:
        body = struct.pack(
            "<HBBIQ16sIIIHH",
            49,
            0,
            0,
            length,
            0,
            file_id,
            0,
            0,
            0,
            0,
            0,
        )
        packet, status = self.request(8, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 READ failed: 0x{status:08x}")
        data_offset = packet[66]
        data_length = struct.unpack_from("<I", packet, 68)[0]
        return packet[data_offset : data_offset + data_length]

    def close_file(self, file_id: bytes) -> None:
        body = struct.pack("<HHI16s", 24, 0, 0, file_id)
        _, status = self.request(6, body)
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 CLOSE failed: 0x{status:08x}")

    def tree_disconnect(self) -> None:
        _, status = self.request(4, struct.pack("<HH", 4, 0))
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 TREE_DISCONNECT failed: 0x{status:08x}")
        self.tree_id = 0

    def logoff(self) -> None:
        _, status = self.request(2, struct.pack("<HH", 4, 0))
        if status != STATUS_SUCCESS:
            raise RuntimeError(f"SMB2 LOGOFF failed: 0x{status:08x}")
        self.session_id = 0


def wait_started(client: Any, port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.request_json("GET", "/api/smb/status")
        if status.get("status"):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.7):
                    return True
            except OSError:
                pass
        time.sleep(0.3)
    return False


def wait_stopped(client: Any, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not client.request_json("GET", "/api/smb/status").get("status"):
            return True
        time.sleep(0.3)
    return not client.request_json("GET", "/api/smb/status").get("status")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline_payload = client.request_json("GET", "/api/smb/configure")
    baseline = copy.deepcopy(baseline_payload.get("configure") or {})
    baseline_status = client.request_json("GET", "/api/smb/status")
    if baseline_status.get("status") or baseline.get("Enable"):
        raise RuntimeError("SMB is already active; refusing disposable probe")
    if baseline.get("Users") not in (None, []):
        raise RuntimeError("SMB already has configured users; refusing disposable probe")
    if baseline.get("PublicMountList") not in (None, []):
        raise RuntimeError("SMB already has configured public shares; refusing disposable probe")

    nonce = secrets.token_hex(5)
    test_root = f"/tmp/{TEST_PREFIX}{nonce}"
    share_name = "testshare" + nonce
    filename = "probe.bin"
    marker = secrets.token_bytes(53)
    port = free_tcp_port()
    smb: SMB2GuestClient | None = None

    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        create_test_path(client, test_root)
        results["test_root_created"] = True

        config = copy.deepcopy(baseline)
        config.update(
            {
                "Enable": True,
                "ListenIP": "127.0.0.1",
                "ListenPort": port,
                "DiscoveryIP": "127.0.0.1",
                "PublicMountList": [
                    {
                        "Type": "local",
                        "Param": test_root,
                        "DisplayName": share_name,
                        "Writable": True,
                        "DisableChangeWriteTable": False,
                    }
                ],
                "Users": [],
                "ListenNetwork": "tcp4",
                "AutoFirewall": False,
                "ServerName": "TEST-Lucky-SMB",
                "Workgroup": "WORKGROUP",
                "Signing": "disabled",
                "Encryption": "disabled",
                "Multichannel": False,
                "GuestEnable": True,
                "MaxConnections": 8,
                "LiteSMBLogLevel": "info",
                "LiteSMBLogToTerminal": False,
                "EnableWSDD": False,
                "EnableMDNS": False,
                "EnableNBNS": False,
            }
        )
        put = mutate(
            client,
            "PUT",
            "/api/smb/configure",
            json_body=config,
            body_supplied=True,
        )
        results["configure_put_ret_zero"] = isinstance(put, dict) and put.get("ret") == 0
        results["service_started"] = wait_started(client, port)

        live = client.request_json("GET", "/api/smb/configure").get("configure") or {}
        mounts = live.get("PublicMountList")
        results["isolated_readback"] = (
            live.get("ListenIP") == "127.0.0.1"
            and int(live.get("ListenPort") or 0) == port
            and live.get("ListenNetwork") == "tcp4"
            and live.get("AutoFirewall") is False
            and live.get("GuestEnable") is True
            and live.get("EnableWSDD") is False
            and live.get("EnableMDNS") is False
            and live.get("EnableNBNS") is False
            and isinstance(mounts, list)
            and len(mounts) == 1
            and mounts[0].get("DisplayName") == share_name
            and mounts[0].get("Param") == test_root
            and mounts[0].get("Writable") is True
        )

        smb = SMB2GuestClient("127.0.0.1", port)
        dialect = smb.negotiate()
        results["negotiate"] = dialect == 0x0210
        observations["dialect"] = f"0x{dialect:04x}"

        session_flags = smb.guest_session_setup()
        results["guest_session"] = bool(session_flags & SMB2_SESSION_FLAG_IS_GUEST)
        observations["session_flags"] = session_flags

        smb.tree_connect(share_name)
        results["tree_connect"] = True

        file_id = smb.create_delete_on_close(filename)
        results["create"] = True
        results["write"] = smb.write(file_id, marker) == len(marker)

        entries = path_entries(client, test_root)
        results["backing_visible_while_open"] = any(
            row.get("name") == filename and row.get("isDir") is False for row in entries
        )

        results["read_exact"] = smb.read(file_id, len(marker)) == marker

        runtime = client.request_json("GET", "/api/smb/runtime")
        summary = runtime.get("summary") if isinstance(runtime, dict) else None
        results["runtime_surface"] = isinstance(runtime, dict) and runtime.get("ret") == 0
        observations["runtime_summary_fields"] = (
            sorted(summary.keys()) if isinstance(summary, dict) else []
        )
        observations["runtime_connection_count"] = (
            int(summary.get("connectionCount") or 0) if isinstance(summary, dict) else 0
        )

        smb.close_file(file_id)
        results["close"] = True
        time.sleep(0.2)
        entries = path_entries(client, test_root)
        results["deleted_on_close"] = not any(row.get("name") == filename for row in entries)

        smb.tree_disconnect()
        results["tree_disconnect"] = True
        smb.logoff()
        results["logoff"] = True
        smb.close_socket()
        smb = None

        logs = client.request_json("GET", "/api/smb/lastlogs")
        log_rows = logs.get("lastLogs") if isinstance(logs, dict) else None
        results["logs_surface"] = isinstance(logs, dict) and logs.get("ret") == 0
        observations["lastlog_count"] = len(log_rows) if isinstance(log_rows, list) else 0

    finally:
        if smb is not None:
            smb.close_socket()

        try:
            live = client.request_json("GET", "/api/smb/configure").get("configure") or {}
            mounts = live.get("PublicMountList")
            owned = (
                live.get("ListenIP") == "127.0.0.1"
                and int(live.get("ListenPort") or 0) == port
                and isinstance(mounts, list)
                and len(mounts) == 1
                and mounts[0].get("DisplayName") == share_name
                and mounts[0].get("Param") == test_root
            )
            cleanup["ownership_guard"] = owned
            if owned:
                restore = mutate(
                    client,
                    "PUT",
                    "/api/smb/configure",
                    json_body=baseline,
                    body_supplied=True,
                )
                cleanup["restore_ret_zero"] = (
                    isinstance(restore, dict) and restore.get("ret") == 0
                )
                cleanup["status_restored"] = wait_stopped(client)
            else:
                cleanup["restore_ret_zero"] = False
                cleanup["status_restored"] = False
        except Exception as error:
            cleanup["restore_error_type"] = type(error).__name__

        try:
            cleanup["test_tree_removed"] = delete_test_path(client, test_root)
        except Exception as error:
            cleanup["test_tree_removed"] = False
            cleanup["delete_error_type"] = type(error).__name__

        try:
            cleanup["baseline_config_restored"] = (
                client.request_json("GET", "/api/smb/configure").get("configure") or {}
            ) == baseline
        except Exception:
            cleanup["baseline_config_restored"] = False

    failed = sorted(key for key, value in results.items() if value is not True)
    for key in (
        "ownership_guard",
        "restore_ret_zero",
        "status_restored",
        "test_tree_removed",
        "baseline_config_restored",
    ):
        if cleanup.get(key) is not True:
            failed.append("cleanup:" + key)

    print(
        json.dumps(
            {
                "target": "Lucky SMB2 loopback guest share behavior",
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
