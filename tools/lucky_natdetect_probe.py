#!/usr/bin/env python3
"""Runtime-verify Lucky v3 NAT Detect WebSocket using only stdlib.

The current Lucky frontend first creates a temporary-access ticket for
GET /api/natdetect/ws, converts the resulting URL to ws/wss, then listens for
JSON messages containing log/result/error fields. This probe reproduces that
flow without exposing OpenToken in a WebSocket URL and without requiring a
browser or third-party WebSocket package.

Address values are deliberately omitted from output; only presence flags and
NAT behavior labels are reported.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
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
from tools.lucky_credentials import (  # noqa: E402
    CredentialError,
    default_credentials_path,
    load_credentials,
)


CONFIRMATION = "PROBE-NAT-DETECT-WEBSOCKET"
DEFAULT_SERVER = "stun.miwifi.com:3478"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
        timeout=20,
    )


def create_ticket(client: LuckyClient, server: str) -> tuple[str, str, int | None]:
    payload = {
        "method": "GET",
        "path": "/api/natdetect/ws",
        "query": {"server": server},
    }
    response = client.request_json(
        "POST",
        "/api/temp-access-tickets",
        json_body=payload,
        allow_unsafe=True,
    )
    if response.get("ret") != 0 or not response.get("ticket"):
        raise RuntimeError("Lucky did not issue a temporary access ticket")
    return (
        str(response["ticket"]),
        str(response.get("ticketParam") or "Lucky-Temp-Access-Ticket"),
        response.get("expiresIn") if isinstance(response.get("expiresIn"), int) else None,
    )


def websocket_target(
    base_url: str,
    *,
    server: str,
    ticket: str,
    ticket_param: str,
) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = parsed.path.rstrip("/") + "/api/natdetect/ws"
    query = urllib.parse.urlencode(
        {
            "server": server,
            "_": str(int(time.time() * 1000)),
            ticket_param: ticket,
        }
    )
    return urllib.parse.SplitResult(scheme, parsed.netloc, path, query, "")


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        part = sock.recv(count - len(chunks))
        if not part:
            raise EOFError("WebSocket connection closed unexpectedly")
        chunks.extend(part)
    return bytes(chunks)


def masked_frame(opcode: int, payload: bytes = b"") -> bytes:
    first = 0x80 | (opcode & 0x0F)
    mask = secrets.token_bytes(4)
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])
    elif length < 65536:
        header = bytes([first, 0x80 | 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, 0x80 | 127]) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + masked


def recv_frame(sock: socket.socket) -> tuple[bool, int, bytes]:
    head = recv_exact(sock, 2)
    first, second = head
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return fin, opcode, payload


class PrefixedSocket:
    """Socket-compatible wrapper that drains already-read bytes first."""

    def __init__(self, sock: socket.socket, prefix: bytes) -> None:
        self._sock = sock
        self._prefix = bytearray(prefix)

    def recv(self, count: int) -> bytes:
        if self._prefix:
            take = min(count, len(self._prefix))
            chunk = bytes(self._prefix[:take])
            del self._prefix[:take]
            return chunk
        return self._sock.recv(count)

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)

    def settimeout(self, value: float | None) -> None:
        self._sock.settimeout(value)

    def close(self) -> None:
        self._sock.close()


def connect_websocket(
    target: urllib.parse.SplitResult, timeout: float = 15.0
) -> socket.socket | PrefixedSocket:
    host = target.hostname
    if not host:
        raise RuntimeError("invalid WebSocket target host")
    port = target.port or (443 if target.scheme == "wss" else 80)
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if target.scheme == "wss":
        context = ssl.create_default_context()
        sock = context.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    host_header = host
    if (target.scheme == "ws" and port != 80) or (target.scheme == "wss" and port != 443):
        host_header += f":{port}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {'https' if target.scheme == 'wss' else 'http'}://{host_header}\r\n"
        "User-Agent: lucky-skills-natdetect-probe/1\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)

    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("WebSocket handshake closed before headers")
        response.extend(chunk)
        if len(response) > 65536:
            raise RuntimeError("WebSocket handshake headers too large")
    header_bytes, extra = bytes(response).split(b"\r\n\r\n", 1)
    lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    if not lines or " 101 " not in f" {lines[0]} ":
        raise RuntimeError(f"WebSocket handshake failed: {lines[0] if lines else 'empty response'}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    if headers.get("sec-websocket-accept") != expected:
        raise RuntimeError("invalid Sec-WebSocket-Accept")
    # A valid server may send its first WebSocket frame in the same TCP read as
    # the HTTP 101 response. Preserve those bytes instead of treating packet
    # boundaries as protocol boundaries.
    return PrefixedSocket(sock, extra) if extra else sock


def run_job(sock: socket.socket, timeout: float = 45.0) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    deadline = time.monotonic() + timeout
    messages: list[dict[str, Any]] = []
    final: dict[str, Any] = {}
    fragments = bytearray()
    fragment_opcode: int | None = None
    while time.monotonic() < deadline:
        sock.settimeout(max(0.5, min(5.0, deadline - time.monotonic())))
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
        if fragment_opcode != 0x1:
            fragments.clear()
            fragment_opcode = None
            continue
        try:
            obj = json.loads(fragments.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            obj = {}
        fragments.clear()
        fragment_opcode = None
        if not isinstance(obj, dict):
            continue
        messages.append(obj)
        if obj.get("result") or obj.get("error"):
            final = obj
            break
    return messages, final


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--server", default=DEFAULT_SERVER)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing active NAT diagnosis; pass --confirm {CONFIRMATION}")

    base_url, token = credentials()
    client = make_client(base_url, token)
    ticket, ticket_param, expires_in = create_ticket(client, args.server)
    target = websocket_target(
        base_url,
        server=args.server,
        ticket=ticket,
        ticket_param=ticket_param,
    )

    sock: socket.socket | None = None
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    try:
        sock = connect_websocket(target)
        results["websocket_handshake"] = True
        messages, final = run_job(sock)
        results["messages_received"] = bool(messages)
        results["job_completed"] = bool(final.get("result") or final.get("error"))
        results["job_succeeded"] = bool(final.get("result")) and not bool(final.get("error"))
        observations["ticket_param"] = ticket_param
        observations["ticket_expires_in_type"] = type(expires_in).__name__
        observations["message_count"] = len(messages)
        observations["message_key_sets"] = sorted(
            {tuple(sorted(str(key) for key in message.keys())) for message in messages}
        )
        observations["log_message_count"] = sum(1 for message in messages if message.get("log"))
        observations["final_fields"] = sorted(final.keys())
        observations["mapping_behavior"] = str(final.get("mappingBehavior") or "")
        observations["filtering_behavior"] = str(final.get("filteringBehavior") or "")
        observations["confidence"] = str(final.get("confidence") or "")
        observations["behavior_discovery_supported"] = final.get("behaviorDiscoverySupported")
        observations["local_address_present"] = bool(final.get("localAddress"))
        observations["public_address_present"] = bool(final.get("publicAddress"))
        observations["other_address_present"] = bool(final.get("otherAddress"))
        warnings = final.get("warnings")
        observations["warning_count"] = len(warnings) if isinstance(warnings, list) else 0
    finally:
        if sock is not None:
            try:
                sock.sendall(masked_frame(0x8))
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    failed = sorted(key for key, value in results.items() if not value)
    print(
        json.dumps(
            {
                "target": "Lucky NAT Detect WebSocket",
                "results": results,
                "observations": observations,
                "failed": failed,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
