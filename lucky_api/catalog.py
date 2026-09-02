"""Route inventory loading, matching, and conservative risk classification."""

from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable


class CatalogError(ValueError):
    """Raised when a route catalog is unavailable or malformed."""


class OperationRisk(str, Enum):
    READ_ONLY = "read-only"
    MUTATING = "mutating"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


VERIFIED_READ_ONLY = {
    ("GET", "/api/status"),
    ("GET", "/api/info"),
    ("GET", "/api/modules/list"),
}

# These frontend routes use the final path parameter as the desired enabled state.
# Keep them mutating even when the optional runtime-verification sidecar is absent.
VERIFIED_MUTATING_GET_TEMPLATES = {
    "/api/cloudflared/list/{param}/{param2}",
    "/api/coraza/list/{param}/{param2}",
    "/api/frp/list/{param}/{param2}",
    "/api/ipfliter/list/{param}/{param2}/{param3}",
    "/api/rclone/remotelist/option",
    "/api/rclone/sync/option",
}

# These operations are destructive even when their path does not contain a
# generic action word. Keep the conservative classification without relying on
# the optional runtime-verification sidecar.
VERIFIED_DANGEROUS_OPERATIONS = {
    ("DELETE", "/api/local-path-browser/path"),
}

# Lucky has state-changing GET routes. Match complete path segments or well-known
# action names instead of assuming all GET requests are safe.
SIDE_EFFECT_GET_ACTIONS = {
    "acmecancel",
    "cancel",
    "clear",
    "comfire",
    "disconnect",
    "dojobs",
    "enable",
    "expanded",
    "export",
    "flush",
    "getipfromcmdtest",
    "host-process-kill",
    "ip-info-refresh",
    "ipsectionexpanded",
    "kill",
    "manualsync",
    "oneclickrecord",
    "reboot_program",
    "refresh-ipinfo",
    "reset",
    "resetadmin",
    "restoreconfigureconfirm",
    "run",
    "shutdown",
    "start",
    "stop",
    "trigger",
    "unlock",
    "wakeup",
}

DANGEROUS_SEGMENTS = {
    "attach",
    "backup",
    "chmod",
    "clear",
    "commit",
    "compress",
    "copy",
    "delete",
    "decompress",
    "disconnect",
    "down",
    "edit",
    "exec",
    "export",
    "getipfromcmdtest",
    "import",
    "kill",
    "prune",
    "reboot_program",
    "remove",
    "rename",
    "reset",
    "resetadmin",
    "restart",
    "restore",
    "shell",
    "shutdown",
    "start",
    "stop",
    "terminal",
    "unpause",
    "update",
    "upgrade",
    "upload",
    "write",
}


def _segments(path: str) -> set[str]:
    return {segment.lower() for segment in path.strip("/").split("/") if segment}


def _template_pattern(template: str) -> re.Pattern[str]:
    cursor = 0
    pieces = ["^"]
    for match in re.finditer(r"\{[^{}]+\}", template):
        pieces.append(re.escape(template[cursor : match.start()]))
        pieces.append(r"[^/?#]+")
        cursor = match.end()
    pieces.append(re.escape(template[cursor:]))
    pieces.append("$")
    return re.compile("".join(pieces))


@dataclass(frozen=True)
class Route:
    path: str
    method: str
    module: str
    confidence: str
    query_keys: tuple[str, ...]
    body_keys: tuple[str, ...]
    has_body: bool
    response_type: str
    response_content_type: str | None = field(default=None, compare=False)
    risk_override: OperationRisk | None = None
    request_body_schema: dict | None = field(default=None, compare=False)
    request_content_type: str | None = field(default=None, compare=False)
    response_schema: dict | None = field(default=None, compare=False)
    schema_evidence: str | None = field(default=None, compare=False)
    success_response_markers: tuple[tuple[int, str], ...] = field(default=(), compare=False)

    @property
    def risk(self) -> OperationRisk:
        if self.risk_override is not None:
            return self.risk_override
        if self.method == "UNKNOWN":
            return OperationRisk.UNKNOWN
        return classify_known_operation(self.method, self.path)

    def matches(self, method: str, path: str) -> bool:
        return self.method == method.upper() and bool(_template_pattern(self.path).fullmatch(path))


def classify_known_operation(method: str, path: str) -> OperationRisk:
    method = method.upper()
    if (method, path) in VERIFIED_READ_ONLY:
        return OperationRisk.READ_ONLY
    if (method, path) in VERIFIED_DANGEROUS_OPERATIONS:
        return OperationRisk.DANGEROUS
    if method == "GET" and path in VERIFIED_MUTATING_GET_TEMPLATES:
        return OperationRisk.MUTATING
    segments = _segments(path)
    if method == "GET":
        if not segments & SIDE_EFFECT_GET_ACTIONS:
            return OperationRisk.READ_ONLY
        if segments & DANGEROUS_SEGMENTS:
            return OperationRisk.DANGEROUS
        return OperationRisk.MUTATING
    return OperationRisk.DANGEROUS if segments & DANGEROUS_SEGMENTS else OperationRisk.MUTATING


def _route_module(path: str) -> str:
    parts = path.split("/")
    return parts[2] if len(parts) > 2 else "unknown"


def _apply_schema_patches(
    route_map: dict[tuple[str, str], dict],
    patches: object,
) -> None:
    if patches is None:
        return
    if not isinstance(patches, list):
        raise CatalogError("runtime schema_patches must be an array")
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for patch in patches:
        if not isinstance(patch, dict):
            raise CatalogError("runtime schema patch must be an object")
        path = patch.get("path")
        method = patch.get("method")
        at = patch.get("at")
        value = patch.get("value")
        evidence = patch.get("evidence")
        if not isinstance(path, str) or not path.startswith("/api/"):
            raise CatalogError("runtime schema patch has invalid path")
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            raise CatalogError("runtime schema patch has invalid method")
        if not isinstance(at, list) or not at or not all(isinstance(key, str) and key for key in at):
            raise CatalogError("runtime schema patch at must be a non-empty string path")
        if not isinstance(value, dict) or not value:
            raise CatalogError("runtime schema patch value must be a non-empty object")
        if not isinstance(evidence, str) or not evidence.strip():
            raise CatalogError("runtime schema patch requires evidence")
        key = (path, method, tuple(at))
        if key in seen:
            raise CatalogError("runtime schema patch target is duplicated")
        seen.add(key)
        route = route_map.get((path, method))
        if route is None:
            raise CatalogError("runtime schema patch route is not backed by the merged catalog")
        schema = route.get("response_schema")
        if not isinstance(schema, dict):
            raise CatalogError("runtime schema patch requires an existing response schema")
        patched_schema = deepcopy(schema)
        current: object = patched_schema
        for segment in at[:-1]:
            if not isinstance(current, dict) or segment not in current:
                raise CatalogError("runtime schema patch target path does not exist")
            current = current[segment]
        leaf = at[-1]
        if not isinstance(current, dict) or leaf not in current:
            raise CatalogError("runtime schema patch target path does not exist")
        if current[leaf] != {}:
            raise CatalogError("runtime schema patch may only replace an empty schema object")
        current[leaf] = deepcopy(value)
        route["response_schema"] = patched_schema


def _apply_runtime_verification(
    raw_routes: list[dict],
    source: Path,
    *,
    version: str,
    snapshot_sha256: str,
    apply_schema_patches: bool = True,
) -> list[dict]:
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"cannot read runtime route verification: {source}") from error
    if payload.get("schema_version") != 1:
        raise CatalogError("unsupported runtime route verification schema")
    target = payload.get("target", {})
    if str(target.get("version", "unknown")) != version:
        raise CatalogError(
            f"runtime route verification targets Lucky {target.get('version')}, catalog is {version}"
        )
    if payload.get("static_snapshot_sha256") != snapshot_sha256:
        raise CatalogError("runtime route verification does not match this exact static snapshot")
    suppress = payload.get("suppress_literals", [])
    verified = payload.get("routes", [])
    if not isinstance(suppress, list) or not all(isinstance(item, str) for item in suppress):
        raise CatalogError("runtime suppress_literals must be an array of paths")
    if not isinstance(verified, list):
        raise CatalogError("runtime routes must be an array")

    route_map: dict[tuple[str, str], dict] = {}
    suppress_set = set(suppress)
    static_keys: set[tuple[str, str]] = set()
    for item in raw_routes:
        if not isinstance(item, dict) or "path" not in item or "method" not in item:
            raise CatalogError("malformed route catalog entry")
        path = str(item["path"])
        method = str(item["method"]).upper()
        static_keys.add((path, method))
        if method == "UNKNOWN" and path in suppress_set:
            continue
        route_map[(path, method)] = dict(item)
    unknown_paths = {path for path, method in static_keys if method == "UNKNOWN"}
    missing_suppressions = suppress_set - unknown_paths
    if missing_suppressions:
        raise CatalogError("runtime suppression is not backed by static UNKNOWN evidence")

    for item in verified:
        if not isinstance(item, dict):
            raise CatalogError("malformed runtime route verification entry")
        try:
            path = str(item["path"])
            method = str(item["method"]).upper()
        except KeyError as error:
            raise CatalogError("runtime route verification requires path and method") from error
        if not path.startswith("/api/") or method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            raise CatalogError(f"invalid runtime verified route: {method} {path}")
        if (path, "UNKNOWN") not in static_keys and (path, method) not in static_keys:
            raise CatalogError("runtime verified route is not backed by the static snapshot")
        route_map.pop((path, "UNKNOWN"), None)
        base = route_map.get((path, method), {})
        merged = dict(base)
        merged.update(item)
        merged.setdefault("module", _route_module(path))
        # A runtime sidecar entry is stronger route/method evidence than the
        # static frontend discovery that it overlays.  The static record
        # already carries confidence="frontend-call", so setdefault() here
        # would incorrectly preserve that weaker value for sidecar entries
        # which intentionally omit an explicit confidence field.
        if "confidence" not in item:
            merged["confidence"] = "runtime-verified"
        merged.setdefault("query_keys", [])
        merged.setdefault("body_keys", [])
        merged.setdefault("has_body", False)
        merged.setdefault("response_type", "unknown")
        route_map[(path, method)] = merged

    if apply_schema_patches:
        _apply_schema_patches(route_map, payload.get("schema_patches"))

    return sorted(route_map.values(), key=lambda item: (str(item.get("module", "")), item["path"], item["method"]))


def load_merged_snapshot(
    path: str | Path,
    *,
    runtime_verification: str | Path | None = None,
    apply_schema_patches: bool = True,
) -> dict:
    source = Path(path).expanduser()
    try:
        source_bytes = source.read_bytes()
        payload = json.loads(source_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogError(f"cannot read route catalog: {source}") from error
    raw_routes = payload.get("routes")
    if payload.get("schema_version") != 1 or not isinstance(raw_routes, list):
        raise CatalogError("unsupported route catalog schema")
    target = payload.get("target", {})
    version = str(target.get("version", "unknown"))
    if runtime_verification is not None:
        raw_routes = _apply_runtime_verification(
            raw_routes,
            Path(runtime_verification).expanduser(),
            version=version,
            snapshot_sha256=hashlib.sha256(source_bytes).hexdigest(),
            apply_schema_patches=apply_schema_patches,
        )
    merged = dict(payload)
    merged["routes"] = raw_routes
    merged["route_count"] = len(raw_routes)
    if runtime_verification is not None:
        merged["runtime_verification_applied"] = True
    return merged


class RouteCatalog:
    def __init__(self, routes: Iterable[Route], *, version: str = "unknown") -> None:
        self.routes = tuple(routes)
        self.version = version

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        runtime_verification: str | Path | None = None,
        apply_schema_patches: bool = True,
    ) -> "RouteCatalog":
        payload = load_merged_snapshot(
            path,
            runtime_verification=runtime_verification,
            apply_schema_patches=apply_schema_patches,
        )
        raw_routes = payload["routes"]
        target = payload.get("target", {})
        version = str(target.get("version", "unknown"))
        routes = []
        for item in raw_routes:
            try:
                if not isinstance(item, dict):
                    raise CatalogError("malformed route catalog entry")
                raw_risk = item.get("risk")
                risk_override = OperationRisk(str(raw_risk)) if raw_risk is not None else None
                raw_success_response_markers = item.get("success_response_markers", [])
                if not isinstance(raw_success_response_markers, list):
                    raise CatalogError("route success_response_markers must be an array")
                success_response_markers: list[tuple[int, str]] = []
                for marker in raw_success_response_markers:
                    if (
                        not isinstance(marker, dict)
                        or set(marker) != {"ret", "msg"}
                        or type(marker.get("ret")) is not int
                        or marker["ret"] <= 0
                        or not isinstance(marker.get("msg"), str)
                        or not marker["msg"]
                    ):
                        raise CatalogError(
                            "route success_response_markers entries require positive integer ret and non-empty msg"
                        )
                    success_response_markers.append((marker["ret"], marker["msg"]))
                if len(success_response_markers) != len(set(success_response_markers)):
                    raise CatalogError("route success_response_markers must be unique")
                routes.append(
                    Route(
                        path=str(item["path"]),
                        method=str(item["method"]).upper(),
                        module=str(item.get("module", "unknown")),
                        confidence=str(item.get("confidence", "unknown")),
                        query_keys=tuple(str(value) for value in item.get("query_keys", [])),
                        body_keys=tuple(str(value) for value in item.get("body_keys", [])),
                        has_body=bool(item.get("has_body", False)),
                        response_type=str(item.get("response_type", "unknown")),
                        response_content_type=(
                            str(item["response_content_type"])
                            if item.get("response_content_type") is not None
                            else None
                        ),
                        risk_override=risk_override,
                        request_body_schema=(
                            dict(item["request_body_schema"])
                            if isinstance(item.get("request_body_schema"), dict)
                            else None
                        ),
                        request_content_type=(
                            str(item["request_content_type"])
                            if item.get("request_content_type") is not None
                            else None
                        ),
                        response_schema=(
                            dict(item["response_schema"])
                            if isinstance(item.get("response_schema"), dict)
                            else None
                        ),
                        schema_evidence=(
                            str(item["schema_evidence"])
                            if item.get("schema_evidence") is not None
                            else None
                        ),
                        success_response_markers=tuple(success_response_markers),
                    )
                )
            except (KeyError, TypeError, ValueError) as error:
                raise CatalogError("malformed route catalog entry") from error
        return cls(routes, version=version)

    @classmethod
    def load_default(cls) -> "RouteCatalog":
        configured = os.environ.get("LUCKY_API_CATALOG")
        candidates = []
        if configured:
            candidates.append(Path(configured))
        candidates.extend(
            [
                Path.cwd() / "evidence" / "lucky-v3-endpoints.json",
                Path(__file__).resolve().parents[1] / "evidence" / "lucky-v3-endpoints.json",
            ]
        )
        runtime_override = os.environ.get("LUCKY_API_RUNTIME_VERIFICATION")
        for candidate in candidates:
            if candidate.is_file():
                if runtime_override:
                    runtime_path: Path | None = Path(runtime_override).expanduser()
                else:
                    sibling = candidate.with_name("lucky-v3-runtime-verification.json")
                    runtime_path = sibling if sibling.is_file() else None
                return cls.from_file(candidate, runtime_verification=runtime_path)
        raise CatalogError("route catalog not found; set LUCKY_API_CATALOG")

    def match(self, method: str, path: str) -> Route | None:
        method = method.upper()
        candidates = [route for route in self.routes if route.matches(method, path)]
        if not candidates:
            return None
        return min(candidates, key=lambda route: route.path.count("{"))

    def classify(self, method: str, path: str) -> OperationRisk:
        if (method.upper(), path) in VERIFIED_READ_ONLY:
            return OperationRisk.READ_ONLY
        route = self.match(method, path)
        return route.risk if route else OperationRisk.UNKNOWN

    def search(
        self,
        *,
        text: str = "",
        module: str | None = None,
        method: str | None = None,
        risk: OperationRisk | None = None,
    ) -> list[Route]:
        needle = text.lower()
        results = []
        for route in self.routes:
            if needle and needle not in route.path.lower():
                continue
            if module and route.module != module:
                continue
            if method and route.method != method.upper():
                continue
            if risk and route.risk is not risk:
                continue
            results.append(route)
        return results
