#!/usr/bin/env python3
"""Runtime-verify Lucky v3 STUN public-endpoint discovery safely.

The probe creates one uniquely named udp4 TEST rule. Port forwarding, UPnP,
NAT-PMP, automatic firewall changes, webhook, scripts and public-address
whitelisting are all disabled. Lucky is allowed to perform real outbound STUN
traffic only. The probe records whether a public endpoint is observed without
printing or persisting the address itself, then deletes the TEST rule and
verifies the original rule baseline.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any, Iterable

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


CONFIRMATION = "PROBE-AND-CLEAN-STUN"
TEST_PREFIX = "TEST-lucky-skills-stun-"


def make_client() -> LuckyClient:
    catalog = RouteCatalog.load_default()
    base_url = os.environ.get("LUCKY_BASE_URL", "").strip()
    token = os.environ.get("LUCKY_OPEN_TOKEN", "").strip()
    if base_url and token:
        return LuckyClient(base_url, token, catalog=catalog, retries=0, timeout=20)
    if bool(base_url) != bool(token):
        raise CredentialError(
            "set both LUCKY_BASE_URL and LUCKY_OPEN_TOKEN, unset both, or use the default credential file"
        )
    values = load_credentials(default_credentials_path())
    return LuckyClient(
        values["base_url"], values["open_token"], catalog=catalog, retries=0, timeout=20
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
            time.sleep(6.0 + attempt * 4.0)
    raise AssertionError("unreachable")


def rows(client: LuckyClient) -> list[dict[str, Any]]:
    payload = client.request_json("GET", "/api/stunrulelist")
    value = payload.get("list") if isinstance(payload, dict) else None
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuntimeError("unexpected STUN list response")
    return [item for item in value if isinstance(item, dict)]


def key_of(row: dict[str, Any]) -> str:
    return str(row.get("Key") or row.get("key") or "")


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def options() -> dict[str, Any]:
    return {
        "DisableSelfForwardingCheck": False,
        "SingleProxyMaxTCPConnections": 64,
        "SingleProxyMaxUDPReadTargetDatagoroutineCount": 16,
        "UDPShortMode": False,
        "SafeMode": "blacklist",
        "SecurityGroupKeys": [],
        "SecurityGroupAccessMode": "disabled",
        "SecurityGroupRefreshOnTraffic": False,
        "TCPListenTLS": False,
        "TCPRelayTLS": False,
        "TCPRelayTLSServerName": "",
        "TCPRelayTLSInsecureSkipVerify": False,
        "TCPAcceptProxyProtocolV2": False,
        "TCPProxyProtocolV2": False,
        "TCPStreamEncryptionSource": False,
        "TCPStreamEncryptionAccept": False,
        "TCPStreamEncryptionKey": "",
        "SinglePortSpeedLimit": False,
        "SinglePortSendSpeedLimit": 0,
        "SinglePortReceSpeedLimit": 0,
        "RuleSpeedLimit": False,
        "RuleSendSpeedLimit": 0,
        "RuleReceSpeedLimit": 0,
        "UDPSessionTimeout": 30000,
        "UDPPacketSourceEncryption": False,
        "UDPPacketAcceptEncryption": False,
        "UDPPacketEncryptionKey": "",
        "UDPPacketSize": 1500,
    }


def payload(name: str, listen_port: int, stun_servers: list[str]) -> dict[str, Any]:
    return {
        "Name": name,
        "Key": "",
        "Enable": True,
        "UseGlobalStunServerList": True,
        "DiaglogShowMode": "simple",
        "StunHeartbeatInterval": 2300,
        "StunTimeout": 3000,
        "StunRetryInterval": 3000,
        "StunAutoRetry": True,
        "AutoAddPubAddrWhiteList": False,
        "StunType": "udp4",
        "StunListenType": "ip",
        "SpecifyNetworkInterface": "",
        "NetworkInterfaceReg": "",
        "ListenIP": "",
        "AutoOptionsFirewall": False,
        "ListenPort": listen_port,
        "NatPMP": False,
        "UPnPGawayIP": "",
        "NatPMPGateway": "",
        "UPnP": False,
        "UPnPLocalPort": 0,
        "UPnpLocalHost": "",
        "UPnPInternalClientIP": "",
        "UpnPDiyControlAPIUrl": "",
        "DisableStunAvalidCheck": False,
        "DisablePortForward": True,
        "TargetAddressList": [],
        "TargetPort": 0,
        "LogLevel": 4,
        "LogOutputToConsole": False,
        "AccessLogMaxNum": 128,
        "WebListShowLastLogMaxCount": 20,
        "Options": options(),
        "StunServerList": list(stun_servers),
        "TcpKeepAliveServerList": [],
        "GlobalWebhook": False,
        "WebhookEnable": False,
        "WebhookOnlyAddrChange": True,
        "WebhookURL": "",
        "WebhookMethod": "",
        "WebhookHeaders": [],
        "WebhookRequestBody": "",
        "WebhookDisableCallbackSuccessContentCheck": False,
        "WebhookSuccessContent": [],
        "WebhookProxy": "",
        "WebhookProxyAddr": "",
        "WebhookProxyUser": "",
        "WebhookProxyPassword": "",
        "CallScript": False,
        "CallScriptContent": "",
        "RetryCount": 0,
        "RetryInterval": 500,
        "LogStreamSettings": {},
    }


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def contains_public_ipv4(value: Any) -> bool:
    for text in iter_strings(value):
        for match in re.finditer(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if (
                address.version == 4
                and not address.is_private
                and not address.is_loopback
                and not address.is_link_local
                and not address.is_multicast
                and not address.is_unspecified
                and not address.is_reserved
            ):
                return True
    return False


def wait_rule(client: LuckyClient, name: str, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in rows(client):
            if row.get("Name") == name:
                return row
        time.sleep(0.5)
    raise RuntimeError("TEST STUN rule did not appear")


def wait_mapping(
    client: LuckyClient, key: str, *, timeout: float = 35.0
) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + timeout
    latest_row: dict[str, Any] = {}
    latest_stats: dict[str, Any] = {}
    while time.monotonic() < deadline:
        listing = client.request_json("GET", "/api/stunrulelist")
        for row in listing.get("list") or []:
            if isinstance(row, dict) and key_of(row) == key:
                latest_row = row
                break
        stats = listing.get("statistics")
        latest_stats = stats if isinstance(stats, dict) else {}
        if contains_public_ipv4(latest_row) or contains_public_ipv4(latest_stats):
            return True, latest_row, latest_stats
        try:
            logs = client.request_json("GET", f"/api/stun/{key}/lastlogs")
        except Exception:
            logs = {}
        if contains_public_ipv4(logs):
            return True, latest_row, latest_stats
        time.sleep(1.0)
    return False, latest_row, latest_stats


def delete_rule(client: LuckyClient, key: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(key_of(row) == key for row in rows(client)):
            return True
        try:
            mutate(client, "DELETE", "/api/stunrule", query={"key": key})
        except LuckyAPIError:
            pass
        time.sleep(0.8)
    return not any(key_of(row) == key for row in rows(client))


def cleanup_tests(client: LuckyClient) -> int:
    removed = 0
    for row in rows(client):
        if not str(row.get("Name", "")).startswith(TEST_PREFIX):
            continue
        key = key_of(row)
        if key and delete_rule(client, key):
            removed += 1
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"refusing mutation; pass --confirm {CONFIRMATION}")

    client = make_client()
    baseline_rows = rows(client)
    baseline_keys = {key_of(row) for row in baseline_rows if key_of(row)}
    if any(str(row.get("Name", "")).startswith(TEST_PREFIX) for row in baseline_rows):
        raise RuntimeError("pre-existing TEST STUN rule found")
    config = client.request_json("GET", "/api/stun/configure").get("configure") or {}
    global_servers = config.get("GlobalStunServerList")
    if not isinstance(global_servers, list) or not global_servers:
        raise RuntimeError("Lucky global STUN server list is empty")
    safe_servers = [str(item) for item in global_servers if isinstance(item, str) and item][:20]

    name = TEST_PREFIX + secrets.token_hex(5)
    listen_port = free_udp_port()
    results: dict[str, bool] = {}
    observations: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    test_key = ""

    try:
        mutate(
            client,
            "POST",
            "/api/stunrule",
            json_body=payload(name, listen_port, safe_servers),
            body_supplied=True,
        )
        row = wait_rule(client, name)
        test_key = key_of(row)
        results["rule_create"] = bool(test_key)

        detail_payload = client.request_json("GET", f"/api/stun/{test_key}")
        detail = detail_payload.get("rule") if isinstance(detail_payload, dict) else None
        results["detail_udp4"] = isinstance(detail, dict) and detail.get("StunType") == "udp4"
        results["portforward_disabled"] = isinstance(detail, dict) and detail.get("DisablePortForward") is True
        results["firewall_automation_disabled"] = isinstance(detail, dict) and detail.get("AutoOptionsFirewall") is False
        results["upnp_natpmp_disabled"] = (
            isinstance(detail, dict)
            and detail.get("UPnP") is False
            and detail.get("NatPMP") is False
        )

        found, runtime_row, stats = wait_mapping(client, test_key)
        results["public_endpoint_observed"] = found
        observations["runtime_summary_fields"] = sorted(runtime_row.keys())
        observations["statistics_top_level_fields"] = sorted(stats.keys())[:50]
        observations["statistics_entry_count"] = len(stats)

        logs = client.request_json("GET", f"/api/stun/{test_key}/lastlogs")
        log_rows = logs.get("lastLogs") if isinstance(logs, dict) else None
        results["log_surface"] = isinstance(logs, dict) and logs.get("ret") == 0
        observations["lastlog_count"] = len(log_rows) if isinstance(log_rows, list) else 0
    finally:
        cleanup["test_rules_removed"] = cleanup_tests(client)

    final_rows = rows(client)
    cleanup["rule_key_baseline_restored"] = {
        key_of(row) for row in final_rows if key_of(row)
    } == baseline_keys
    cleanup["leftover_test_rules"] = sum(
        1 for row in final_rows if str(row.get("Name", "")).startswith(TEST_PREFIX)
    )

    failed = sorted(key for key, value in results.items() if not value)
    if not cleanup.get("rule_key_baseline_restored"):
        failed.append("rule_key_baseline_restored")
    if cleanup.get("leftover_test_rules") != 0:
        failed.append("leftover_test_rules")

    print(
        json.dumps(
            {
                "target": "Lucky STUN udp4 public endpoint discovery",
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
