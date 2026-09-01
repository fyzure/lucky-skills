#!/usr/bin/env python3
"""Runtime-verify Lucky v3 local WebTerminal WebSocket/session behavior.

The probe creates one uniquely named local connection using /bin/sh and /tmp,
obtains Lucky temporary-access tickets for the WebSocket connect/attach paths,
and speaks RFC6455 using the dependency-free helpers already used by the NAT
Detect probe. It verifies connected/session semantics, raw terminal input and
output, resize messages, session read/stats/remark APIs, detach + re-attach,
and explicit session closure. Finally it removes only the TEST connection and
verifies the original connection/session baselines are restored.

Terminal output itself is never printed or persisted; only marker booleans and
safe structural field names are emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api import LuckyClient, RouteCatalog  # noqa: E402
from lucky_api.client import HTTPStatusError  # noqa: E402
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)
from tools.lucky_natdetect_probe import (  # noqa: E402
    connect_websocket,
    masked_frame,
    recv_frame,
)


CONFIRMATION = "PROBE-AND-CLEAN-WEBTERMINAL"
TEST_PREFIX = "TEST-lucky-skills-webterminal-"


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


def make_client(base_url: str, token: str) -> LuckyClient:
    return LuckyClient(
        base_url,
        token,
        catalog=RouteCatalog.load_default(),
        retries=0,
        timeout=25,
    )


def mutate(
    client: LuckyClient,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    body_supplied: bool = False,
    attempts: int = 5,
) -> Any:
    for attempt in range(attempts):
        kwargs: dict[str, Any] = {"allow_unsafe": True}
        if query is not None:
            kwargs["query"] = query
        if body_supplied:
            kwargs["json_body"] = json_body
        try:
            return client.request_json(method, path, **kwargs)
        except HTTPStatusError as error:
            if error.status != 429 or attempt + 1 >= attempts:
                raise
            time.sleep(5.0 + attempt * 3.0)
    raise AssertionError("unreachable")


def connection_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/webterminal/connections")
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected WebTerminal connection list response")
    return [row for row in rows if isinstance(row, dict)]


def session_rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/webterminal/sessions")
    rows = payload.get("list") if isinstance(payload, dict) else None
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise RuntimeError("unexpected WebTerminal session list response")
    return [row for row in rows if isinstance(row, dict)]


def connection_key(row: dict[str, Any]) -> str:
    return str(row.get("key") or row.get("Key") or "")


def session_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("ID") or row.get("sessionId") or "")


def create_ticket(client: LuckyClient, path: str) -> tuple[str, str]:
    payload = {
        "method": "GET",
        "path": path,
        "query": {},
        "module": "webterminal",
        "action": "terminal-websocket",
    }
    response = client.request_json(
        "POST",
        "/api/temp-access-tickets",
        json_body=payload,
        allow_unsafe=True,
    )
    if response.get("ret") != 0 or not response.get("ticket"):
        raise RuntimeError("Lucky did not issue a WebTerminal temporary-access ticket")
    return str(response["ticket"]), str(
        response.get("ticketParam") or "Lucky-Temp-Access-Ticket"
    )


def websocket_target(
    base_url: str, path: str, ticket: str, ticket_param: str
) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    full_path = parsed.path.rstrip("/") + path
    query = urllib.parse.urlencode(
        {"_": str(int(time.time() * 1000)), ticket_param: ticket}
    )
    return urllib.parse.SplitResult(scheme, parsed.netloc, full_path, query, "")


def websocket_for_path(
    client: LuckyClient, base_url: str, path: str
) -> socket.socket:
    ticket, ticket_param = create_ticket(client, path)
    return connect_websocket(
        websocket_target(base_url, path, ticket, ticket_param), timeout=15.0
    )


def read_until(
    sock: socket.socket,
    *,
    marker: bytes | None = None,
    need_event: str | None = None,
    timeout: float = 20.0,
) -> tuple[bool, str, list[tuple[str, ...]]]:
    deadline = time.monotonic() + timeout
    raw = bytearray()
    found_event = ""
    key_sets: set[tuple[str, ...]] = set()
    fragments = bytearray()
    fragment_opcode: int | None = None
    while time.monotonic() < deadline:
        sock.settimeout(max(0.5, min(3.0, deadline - time.monotonic())))
        try:
            fin, opcode, payload = recv_frame(sock)
        except socket.timeout:
            continue
        if opcode == 0x8:
            break
        if opcode == 0x9:
            sock.sendall(masked_frame(0xA, payload))
            continue
        if opcode == 0xA:
            continue
        if opcode in {0x1, 0x2}:
            fragments = bytearray(payload)
            fragment_opcode = opcode
        elif opcode == 0x0 and fragment_opcode is not None:
            fragments.extend(payload)
        else:
            continue
        if not fin:
            continue

        data = bytes(fragments)
        current_opcode = fragment_opcode
        fragments.clear()
        fragment_opcode = None

        obj: dict[str, Any] | None = None
        if current_opcode == 0x1:
            try:
                parsed = json.loads(data.decode("utf-8"))
                if isinstance(parsed, dict):
                    obj = parsed
            except (UnicodeDecodeError, json.JSONDecodeError):
                obj = None
        if obj is not None:
            key_sets.add(tuple(sorted(str(key) for key in obj.keys())))
            event_type = str(obj.get("type") or "")
            if event_type:
                found_event = event_type
            if obj.get("error"):
                raise RuntimeError("WebTerminal WebSocket returned an error event")
            if need_event and event_type == need_event:
                sid = str(obj.get("sessionId") or "")
                return True, sid, sorted(key_sets)
            continue

        if len(raw) < 256 * 1024:
            raw.extend(data[: 256 * 1024 - len(raw)])
        if marker is not None and marker in raw:
            return True, "", sorted(key_sets)
    return False, "", sorted(key_sets)


def wait_session(client: LuckyClient, sid: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in session_rows(client):
            if session_id(row) == sid:
                return row
        time.sleep(0.3)
    return {}


def delete_test_connections(client: LuckyClient) -> int:
    removed = 0
    for row in connection_rows(client):
        name = str(row.get("name") or row.get("Name") or "")
        if not name.startswith(TEST_PREFIX):
            continue
        key = connection_key(row)
        if not key:
            continue
        try:
            mutate(client, "DELETE", f"/api/webterminal/connections/{key}")
            removed += 1
        except Exception:
            pass
    return removed


def delete_test_sessions(client: LuckyClient) -> int:
    removed = 0
    for row in session_rows(client):
        connection_name = str(row.get("connectionName") or "")
        if not connection_name.startswith(TEST_PREFIX):
            continue
        sid = session_id(row)
        if not sid:
            continue
        try:
            mutate(client, "DELETE", f"/api/webterminal/sessions/{sid}")
            removed += 1
        except Exception:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
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
    if any(
        str(row.get("name") or row.get("Name") or "").startswith(TEST_PREFIX)
        for row in baseline_connections
    ):
        raise RuntimeError("pre-existing TEST WebTerminal connection found")

    nonce = secrets.token_hex(5)
    name = TEST_PREFIX + nonce
    key = "conn_test_" + nonce
    payload = {
        "key": key,
        "name": name,
        "type": "local",
        "remark": "Lucky skills local WebSocket runtime probe",
        "localConfig": {"shell": "/bin/sh", "workDir": "/tmp"},
        "sshConfig": {},
        "telnetConfig": {},
        "shortcuts": [],
        "quickAccessDirs": ["/tmp"],
    }
    ws: socket.socket | None = None
    attach_ws: socket.socket | None = None
    sid = ""
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}

    try:
        test = mutate(
            client,
            "POST",
            "/api/webterminal/connections/test",
            json_body=payload,
            body_supplied=True,
        )
        results["local_connection_test"] = isinstance(test, dict) and test.get("ret") == 0

        created = mutate(
            client,
            "POST",
            "/api/webterminal/connections",
            json_body=payload,
            body_supplied=True,
        )
        results["connection_created"] = isinstance(created, dict) and created.get("ret") == 0
        row = next((row for row in connection_rows(client) if connection_key(row) == key), {})
        results["connection_readback"] = bool(row) and str(row.get("type") or "") == "local"

        ws = websocket_for_path(client, base_url, f"/api/webterminal/connect/{key}")
        connected, sid, connect_key_sets = read_until(
            ws, need_event="connected", timeout=20.0
        )
        results["websocket_connected"] = connected and bool(sid)
        observations["connect_message_key_sets"] = connect_key_sets

        ws.sendall(
            masked_frame(
                0x1,
                json.dumps({"type": "resize", "cols": 97, "rows": 31}).encode("utf-8"),
            )
        )
        results["resize_frame_sent"] = True

        marker = f"LUCKY_SKILLS_WEBTERMINAL_579_{nonce}".encode("ascii")
        command = (
            f"printf 'LUCKY_SKILLS_WEBTERMINAL_%d_{nonce}\\n' $((123+456))\r"
        ).encode("utf-8")
        ws.sendall(masked_frame(0x1, command))
        marker_seen, _, output_key_sets = read_until(ws, marker=marker, timeout=20.0)
        results["raw_terminal_roundtrip"] = marker_seen
        observations["output_json_key_sets"] = output_key_sets

        session = wait_session(client, sid)
        results["session_listed"] = bool(session)
        observations["session_list_fields"] = sorted(session.keys()) if session else []

        detail = client.request_json("GET", f"/api/webterminal/sessions/{sid}")
        results["session_detail"] = isinstance(detail, dict) and detail.get("ret") == 0
        observations["session_detail_fields"] = sorted(
            key for key in detail.keys() if key != "ret"
        ) if isinstance(detail, dict) else []

        stats = client.request_json("GET", f"/api/webterminal/sessions/{sid}/stats")
        results["session_stats"] = isinstance(stats, dict) and stats.get("ret") == 0
        observations["session_stats_fields"] = sorted(
            key for key in stats.keys() if key != "ret"
        ) if isinstance(stats, dict) else []

        remark = mutate(
            client,
            "PUT",
            f"/api/webterminal/sessions/{sid}/remark",
            json_body={"remark": "TEST lucky-skills attached session"},
            body_supplied=True,
        )
        results["session_remark_updated"] = isinstance(remark, dict) and remark.get("ret") == 0

        # Close only the WebSocket, leaving the backend session within the
        # configured sessionKeepAlive window so attach semantics can be tested.
        try:
            ws.sendall(masked_frame(0x8))
        finally:
            ws.close()
            ws = None
        detached = wait_session(client, sid)
        results["session_survived_websocket_detach"] = bool(detached)
        observations["detached_session_state"] = str(detached.get("state") or detached.get("status") or "")

        attach_ws = websocket_for_path(client, base_url, f"/api/webterminal/attach/{sid}")
        attached, attached_sid, attach_key_sets = read_until(
            attach_ws, need_event="attached", timeout=20.0
        )
        results["session_attached"] = attached and attached_sid == sid
        observations["attach_message_key_sets"] = attach_key_sets

        marker_two = f"LUCKY_SKILLS_WEBTERMINAL_135_{nonce}".encode("ascii")
        command_two = (
            f"printf 'LUCKY_SKILLS_WEBTERMINAL_%d_{nonce}\\n' $((100+35))\r"
        ).encode("utf-8")
        attach_ws.sendall(masked_frame(0x1, command_two))
        marker_two_seen, _, _ = read_until(
            attach_ws, marker=marker_two, timeout=20.0
        )
        results["raw_terminal_roundtrip_after_attach"] = marker_two_seen

        closed = mutate(client, "DELETE", f"/api/webterminal/sessions/{sid}")
        results["session_deleted"] = isinstance(closed, dict) and closed.get("ret") == 0
        time.sleep(0.5)
        results["session_absent_after_delete"] = all(
            session_id(row) != sid for row in session_rows(client)
        )

        deleted = mutate(client, "DELETE", f"/api/webterminal/connections/{key}")
        results["connection_deleted"] = isinstance(deleted, dict) and deleted.get("ret") == 0
    finally:
        for current in (ws, attach_ws):
            if current is None:
                continue
            try:
                current.sendall(masked_frame(0x8))
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass
        cleanup["test_sessions_removed"] = delete_test_sessions(client)
        cleanup["test_connections_removed"] = delete_test_connections(client)

    final_connections = connection_rows(client)
    final_sessions = session_rows(client)
    cleanup["connection_key_baseline_restored"] = {
        connection_key(row) for row in final_connections if connection_key(row)
    } == baseline_connection_keys
    cleanup["session_id_baseline_restored"] = {
        session_id(row) for row in final_sessions if session_id(row)
    } == baseline_session_ids
    cleanup["leftover_test_connections"] = sum(
        1
        for row in final_connections
        if str(row.get("name") or row.get("Name") or "").startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if not value)
    for key_name in ("connection_key_baseline_restored", "session_id_baseline_restored"):
        if not cleanup.get(key_name):
            failed.append(key_name)
    if cleanup.get("leftover_test_connections") != 0:
        failed.append("leftover_test_connections")

    print(
        json.dumps(
            {
                "target": "Lucky WebTerminal local WebSocket/session behavior",
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
