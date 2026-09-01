#!/usr/bin/env python3
"""Dependency-free repository checks used locally and in GitHub Actions."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from extract_lucky_frontend import write_markdown, write_openapi
from lucky_api import OperationRisk, RouteCatalog, load_merged_snapshot


ROOT = Path(__file__).resolve().parents[1]
TOKEN_ASSIGNMENT = re.compile(
    r"(?i)(?:open[_-]?token|authorization)\s*[:=]\s*[\"']?(?!\$\{|<|your-|example|replace)[A-Za-z0-9_-]{24,}"
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")
SKILL_FRONTMATTER = re.compile(r"\A---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\."
    r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
HEX_COLOR = re.compile(r"^#[0-9A-F]{6}$", re.IGNORECASE)
TODO_MARKER = "[TODO:"
IGNORED_REPOSITORY_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    ".wrangler",
    "__pycache__",
    "dist",
    "node_modules",
}
PLUGIN_MANIFEST_FIELDS = {
    "id",
    "name",
    "version",
    "description",
    "skills",
    "apps",
    "mcpServers",
    "interface",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
}
PLUGIN_AUTHOR_FIELDS = {"name", "email", "url"}
PLUGIN_INTERFACE_FIELDS = {
    "displayName",
    "shortDescription",
    "longDescription",
    "developerName",
    "category",
    "capabilities",
    "websiteURL",
    "privacyPolicyURL",
    "termsOfServiceURL",
    "brandColor",
    "composerIcon",
    "logo",
    "logoDark",
    "screenshots",
    "defaultPrompt",
    "default_prompt",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def is_ignored_repository_path(path: Path) -> bool:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    return any(part in IGNORED_REPOSITORY_PARTS for part in relative.parts)


def require_non_empty_string(payload: dict[str, object], field: str, *, prefix: str = "") -> str:
    value = payload.get(field)
    qualified = f"{prefix}.{field}" if prefix else field
    if not isinstance(value, str) or not value.strip():
        fail(f"Codex plugin {qualified} must be a non-empty string")
    return value


def validate_optional_non_empty_string(
    payload: dict[str, object], field: str, *, prefix: str = ""
) -> None:
    if payload.get(field) is not None:
        require_non_empty_string(payload, field, prefix=prefix)


def validate_optional_https_url(
    payload: dict[str, object], field: str, *, prefix: str = ""
) -> None:
    value = payload.get(field)
    if value is None:
        return
    qualified = f"{prefix}.{field}" if prefix else field
    parsed = urlparse(value) if isinstance(value, str) else None
    if parsed is None or parsed.scheme != "https" or not parsed.netloc:
        fail(f"Codex plugin {qualified} must be an absolute https URL")


def reject_unknown_fields(payload: dict[str, object], allowed: set[str], *, prefix: str = "") -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        qualified = f"{prefix} fields" if prefix else "fields"
        fail(f"Codex plugin has unsupported {qualified}: {', '.join(unknown)}")


def reject_todo_markers(value: object, path: str = "$") -> None:
    if isinstance(value, str):
        if TODO_MARKER in value:
            fail(f"Codex plugin {path} still contains a TODO placeholder")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_todo_markers(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_todo_markers(item, f"{path}.{key}")


def normalize_contract_path(raw_path: object) -> str | None:
    if not isinstance(raw_path, str):
        return None
    path = Path(raw_path)
    if path.is_absolute():
        return None
    normalized = path.as_posix().rstrip("/")
    return normalized or None


def validate_optional_contract_path(
    payload: dict[str, object], field: str, expected: str
) -> None:
    value = payload.get(field)
    if value is not None and normalize_contract_path(value) != expected:
        fail(f"Codex plugin {field} must resolve to {expected}")


def validate_asset_path(raw_path: object, field: str) -> None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        fail(f"Codex plugin {field} must be a non-empty relative path")
    candidate = PurePosixPath(raw_path.replace("\\", "/"))
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        fail(f"Codex plugin {field} must stay inside the plugin archive")
    resolved = (ROOT / candidate.as_posix()).resolve()
    if not resolved.is_relative_to(ROOT.resolve()):
        fail(f"Codex plugin {field} must stay inside the plugin archive")
    if not resolved.is_file():
        fail(f"Codex plugin {field} points to a missing file")


def validate_optional_asset_path(payload: dict[str, object], field: str) -> None:
    value = payload.get(field)
    if value is not None:
        validate_asset_path(value, f"interface.{field}")


def validate_prompt_list(value: object, field: str) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 3:
        fail(f"Codex plugin {field} must contain 1 to 3 prompts")
    if not all(
        isinstance(item, str) and item.strip() and len(item) <= 128 for item in value
    ):
        fail(f"Codex plugin {field} prompts must be non-empty strings up to 128 characters")


def validate_default_prompts(interface: dict[str, object]) -> None:
    if "defaultPrompt" not in interface and "default_prompt" not in interface:
        fail("Codex plugin interface.defaultPrompt or interface.default_prompt is required")
    # The public plugin spec defines the camelCase field as 1–3 strings capped at
    # 128 characters. The legacy snake_case alias is accepted by the canonical
    # ingestion validator based on key presence alone, so do not narrow it here.
    if "defaultPrompt" in interface:
        validate_prompt_list(interface.get("defaultPrompt"), "interface.defaultPrompt")


def load_companion_json(path: Path, label: str) -> dict[str, object]:
    if not path.is_file():
        fail(f"Codex plugin {label} is required when its manifest field is present")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(f"Codex plugin {label} must contain valid JSON")
    if not isinstance(payload, dict):
        fail(f"Codex plugin {label} must contain a JSON object")
    return payload


def validate_mcp_server_entries(servers: object, label: str) -> None:
    if not isinstance(servers, dict):
        fail(f"Codex plugin {label} must be an object")
    for key, value in servers.items():
        if not isinstance(key, str) or not key.strip():
            fail(f"Codex plugin {label} server names must be non-empty strings")
        if not isinstance(value, dict):
            fail(f"Codex plugin {label} server {key!r} must be an object")


def validate_manifest_mcp_servers(manifest: dict[str, object]) -> None:
    value = manifest.get("mcpServers")
    if value is None:
        return
    if isinstance(value, str):
        validate_optional_contract_path(manifest, "mcpServers", ".mcp.json")
        payload = load_companion_json(ROOT / ".mcp.json", ".mcp.json")
        reject_unknown_fields(payload, {"mcpServers"}, prefix=".mcp.json")
        validate_mcp_server_entries(payload.get("mcpServers"), ".mcp.json mcpServers")
        return
    if isinstance(value, dict):
        validate_mcp_server_entries(value, "mcpServers")
        return
    fail("Codex plugin mcpServers must be a string path or object")


def validate_app_manifest() -> None:
    payload = load_companion_json(ROOT / ".app.json", ".app.json")
    reject_unknown_fields(payload, {"apps"}, prefix=".app.json")
    apps = payload.get("apps")
    if not isinstance(apps, dict):
        fail("Codex plugin .app.json apps must be an object")
    for key, value in apps.items():
        if not isinstance(value, dict):
            fail(f"Codex plugin .app.json app {key!r} must be an object")
        reject_unknown_fields(value, {"id", "category"}, prefix=f".app.json app {key}")
        require_non_empty_string(value, "id", prefix=f".app.json app {key}")
        validate_optional_non_empty_string(value, "category", prefix=f".app.json app {key}")


def check_secrets() -> None:
    for path in ROOT.rglob("*"):
        if not path.is_file() or is_ignored_repository_path(path):
            continue
        if path.suffix.lower() not in {".md", ".json", ".yaml", ".yml", ".py", ".sh", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if TOKEN_ASSIGNMENT.search(text):
            fail(f"possible hard-coded credential in {path.relative_to(ROOT)}")


def check_local_links() -> None:
    for path in ROOT.rglob("*.md"):
        if is_ignored_repository_path(path):
            continue
        text = path.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK.findall(text):
            target = target.strip().strip("<>").split("#", 1)[0]
            if not target or "://" in target or target.startswith(("mailto:", "#")):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                fail(f"broken local link in {path.relative_to(ROOT)}: {target}")


def check_skill_packaging() -> None:
    repo_skill_path = ROOT / ".agents" / "skills" / "lucky" / "SKILL.md"
    plugin_skill_path = ROOT / "skills" / "lucky" / "SKILL.md"
    for path in (repo_skill_path, plugin_skill_path):
        if not path.is_file():
            fail(f"Lucky skill is missing from {path.relative_to(ROOT)}")
    if repo_skill_path.read_bytes() != plugin_skill_path.read_bytes():
        fail("repository and plugin Lucky SKILL.md copies must remain byte-identical")

    text = repo_skill_path.read_text(encoding="utf-8")
    match = SKILL_FRONTMATTER.match(text)
    if not match:
        fail("Lucky SKILL.md is missing YAML frontmatter")

    metadata: dict[str, str] = {}
    for line in match.group("body").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            fail(f"invalid Lucky SKILL.md frontmatter line: {line}")
        metadata[key.strip()] = value.strip()

    if metadata.get("name") != "lucky":
        fail("Lucky SKILL.md name must be 'lucky'")
    description = metadata.get("description", "")
    if not description:
        fail("Lucky SKILL.md description is required")
    if len(description) > 1024:
        fail("Lucky SKILL.md description exceeds the 1024-character host limit")

    manifest_path = ROOT / ".codex-plugin" / "plugin.json"
    if not manifest_path.is_file():
        fail("Codex plugin manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        fail("Codex plugin manifest must be a JSON object")
    reject_todo_markers(manifest)
    reject_unknown_fields(manifest, PLUGIN_MANIFEST_FIELDS)
    validate_optional_non_empty_string(manifest, "id")
    if require_non_empty_string(manifest, "name") != "lucky-skills":
        fail("Codex plugin name must be 'lucky-skills'")
    version = require_non_empty_string(manifest, "version")
    if not SEMVER.fullmatch(version):
        fail("Codex plugin version must use strict semver")
    require_non_empty_string(manifest, "description")

    author = manifest.get("author")
    if not isinstance(author, dict):
        fail("Codex plugin author must be an object")
    reject_unknown_fields(author, PLUGIN_AUTHOR_FIELDS, prefix="author")
    require_non_empty_string(author, "name", prefix="author")
    validate_optional_non_empty_string(author, "email", prefix="author")
    validate_optional_https_url(author, "url", prefix="author")

    validate_optional_contract_path(manifest, "skills", "skills")
    validate_optional_contract_path(manifest, "apps", ".app.json")
    validate_manifest_mcp_servers(manifest)
    if manifest.get("apps") is not None:
        validate_app_manifest()

    interface = manifest.get("interface")
    if not isinstance(interface, dict):
        fail("Codex plugin interface metadata is required")
    reject_unknown_fields(interface, PLUGIN_INTERFACE_FIELDS, prefix="interface")
    for field in (
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
    ):
        require_non_empty_string(interface, field, prefix="interface")
    validate_default_prompts(interface)
    capabilities = interface.get("capabilities")
    if not isinstance(capabilities, list) or not all(
        isinstance(item, str) and item.strip() for item in capabilities
    ):
        fail("Codex plugin interface.capabilities must be an array of strings")
    for field in ("websiteURL", "privacyPolicyURL", "termsOfServiceURL"):
        validate_optional_https_url(interface, field, prefix="interface")
    brand_color = interface.get("brandColor")
    if brand_color is not None and (
        not isinstance(brand_color, str) or HEX_COLOR.fullmatch(brand_color) is None
    ):
        fail("Codex plugin interface.brandColor must use #RRGGBB")
    for field in ("composerIcon", "logo", "logoDark"):
        validate_optional_asset_path(interface, field)
    screenshots = interface.get("screenshots", [])
    if not isinstance(screenshots, list):
        fail("Codex plugin interface.screenshots must be an array")
    for index, raw_path in enumerate(screenshots):
        validate_asset_path(raw_path, f"interface.screenshots[{index}]")


def check_runtime_verification(snapshot_path: Path, snapshot: dict[str, object]) -> None:
    runtime_path = snapshot_path.with_name("lucky-v3-runtime-verification.json")
    if not runtime_path.is_file():
        fail("runtime route verification file is missing")
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    if runtime.get("schema_version") != 1:
        fail("runtime route verification schema is unsupported")
    target = snapshot.get("target", {})
    runtime_target = runtime.get("target", {})
    if not isinstance(target, dict) or not isinstance(runtime_target, dict):
        fail("runtime route verification target is malformed")
    if runtime_target.get("version") != target.get("version"):
        fail("runtime route verification version does not match endpoint snapshot")
    snapshot_sha256 = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    if runtime.get("static_snapshot_sha256") != snapshot_sha256:
        fail("runtime route verification is not bound to the exact endpoint snapshot")

    suppress = runtime.get("suppress_literals")
    if not isinstance(suppress, list) or not all(
        isinstance(path, str) and path.startswith("/api/") for path in suppress
    ):
        fail("runtime suppress_literals must contain /api/... paths")
    if len(suppress) != len(set(suppress)):
        fail("runtime suppress_literals contains duplicates")
    suppression_evidence = runtime.get("suppression_evidence")
    if not isinstance(suppression_evidence, dict):
        fail("runtime suppression_evidence must be an object")
    prefix_evidence = suppression_evidence.get("same_bundle_prefix_artifacts")
    no_route_evidence = suppression_evidence.get("no_route_literals")
    if not isinstance(prefix_evidence, dict) or not isinstance(no_route_evidence, dict):
        fail("runtime suppression_evidence categories are missing")
    no_route_paths = no_route_evidence.get("paths")
    if not isinstance(no_route_paths, list) or not all(
        isinstance(path, str) and path in suppress for path in no_route_paths
    ):
        fail("runtime no-route suppression paths must be suppressed API paths")
    if no_route_evidence.get("count") != len(no_route_paths):
        fail("runtime no-route suppression count is stale")
    prefix_count = prefix_evidence.get("count")
    if not isinstance(prefix_count, int) or prefix_count + len(no_route_paths) != len(suppress):
        fail("runtime suppression evidence counts do not cover suppress_literals")

    model_evidence = runtime.get("model_evidence")
    if not isinstance(model_evidence, dict):
        fail("runtime model_evidence must be an object")
    ipdb_evidence = model_evidence.get("ipdb_behavior")
    if not isinstance(ipdb_evidence, dict):
        fail("IPDB behavior evidence is missing")
    if ipdb_evidence.get("confidence") != "runtime-verified":
        fail("IPDB behavior evidence must remain runtime-verified")
    ipdb_model = ipdb_evidence.get("model")
    required_ipdb_model = {
        "upload",
        "item_lifecycle",
        "enable_route",
        "query",
        "database_files",
    }
    if not isinstance(ipdb_model, dict) or set(ipdb_model) != required_ipdb_model:
        fail("IPDB behavior model regressed")
    for field in required_ipdb_model:
        if not isinstance(ipdb_model.get(field), str) or not ipdb_model[field].strip():
            fail(f"IPDB behavior model field is missing: {field}")
    ipdb_observations = ipdb_evidence.get("observations")
    if not isinstance(ipdb_observations, dict) or set(ipdb_observations) != {
        "formats",
        "enable_get_side_effect",
        "query_result_privacy",
        "cleanup",
    }:
        fail("IPDB runtime observations regressed")
    for field in ("verification", "security"):
        value = ipdb_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"IPDB evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_ipdb_probe.py").is_file():
        fail("IPDB runtime probe tool is missing")

    ssl_acme_evidence = model_evidence.get("ssl_acme_behavior")
    if not isinstance(ssl_acme_evidence, dict):
        fail("SSL ACME behavior evidence is missing")
    if ssl_acme_evidence.get("confidence") != "runtime-verified":
        fail("SSL ACME behavior evidence must remain runtime-verified")
    ssl_acme_model = ssl_acme_evidence.get("model")
    required_ssl_acme_model = {
        "lifecycle",
        "issuance",
        "mapping",
        "flush",
        "manual_sync",
    }
    if not isinstance(ssl_acme_model, dict) or set(ssl_acme_model) != required_ssl_acme_model:
        fail("SSL ACME behavior model regressed")
    ssl_acme_observations = ssl_acme_evidence.get("observations")
    if not isinstance(ssl_acme_observations, dict) or set(ssl_acme_observations) != {
        "mapping_namespace",
        "mapping_lifecycle",
        "flush",
        "cleanup",
    }:
        fail("SSL ACME runtime observations regressed")
    for field in ("verification", "security"):
        value = ssl_acme_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"SSL ACME evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_ssl_acme_probe.py").is_file():
        fail("SSL ACME runtime probe tool is missing")

    ssl_sync_evidence = model_evidence.get("ssl_sync_client_behavior")
    if not isinstance(ssl_sync_evidence, dict):
        fail("SSL sync-client behavior evidence is missing")
    if ssl_sync_evidence.get("confidence") != "runtime-verified":
        fail("SSL sync-client behavior evidence must remain runtime-verified")
    ssl_sync_model = ssl_sync_evidence.get("model")
    if not isinstance(ssl_sync_model, dict) or set(ssl_sync_model) != {
        "setting_model",
        "selection_model",
        "linuxssh",
        "authorization_gate",
        "e2e_status",
    }:
        fail("SSL sync-client behavior model regressed")
    ssl_sync_observations = ssl_sync_evidence.get("observations")
    if not isinstance(ssl_sync_observations, dict) or set(ssl_sync_observations) != {
        "instance_user_level",
        "manual_sync_error",
        "ssh_prerequisite",
        "cleanup",
    }:
        fail("SSL sync-client runtime observations regressed")
    for field in ("verification", "security"):
        value = ssl_sync_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"SSL sync-client evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_ssl_sync_probe.py").is_file():
        fail("SSL sync-client runtime probe tool is missing")

    webterminal_evidence = model_evidence.get("webterminal_behavior")
    if not isinstance(webterminal_evidence, dict):
        fail("WebTerminal behavior evidence is missing")
    if webterminal_evidence.get("confidence") != "runtime-verified":
        fail("WebTerminal behavior evidence must remain runtime-verified")
    webterminal_model = webterminal_evidence.get("model")
    if not isinstance(webterminal_model, dict) or set(webterminal_model) != {
        "local_websocket",
        "session_lifecycle",
        "ssh_host_key",
        "sftp_core",
        "uploads",
        "archive",
    }:
        fail("WebTerminal behavior model regressed")
    webterminal_observations = webterminal_evidence.get("observations")
    if not isinstance(webterminal_observations, dict) or set(webterminal_observations) != {
        "websocket_packetization",
        "host_key_confirmation",
        "multipart_upload_failure",
        "streaming_upload_failure",
        "cleanup",
    }:
        fail("WebTerminal runtime observations regressed")
    for field in ("verification", "security"):
        value = webterminal_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"WebTerminal evidence field is missing: {field}")
    for probe_name in ("lucky_webterminal_probe.py", "lucky_webterminal_sftp_probe.py"):
        if not (ROOT / "tools" / probe_name).is_file():
            fail(f"WebTerminal runtime probe tool is missing: {probe_name}")

    storage_evidence = model_evidence.get("storagemanagement_local_behavior")
    if not isinstance(storage_evidence, dict):
        fail("StorageManagement local behavior evidence is missing")
    if storage_evidence.get("confidence") != "runtime-verified":
        fail("StorageManagement local behavior evidence must remain runtime-verified")
    storage_model = storage_evidence.get("model")
    if not isinstance(storage_model, dict) or set(storage_model) != {
        "list_model",
        "lifecycle",
        "enable_route",
        "create_normalization",
        "litelist",
        "system_mount",
    }:
        fail("StorageManagement local behavior model regressed")
    storage_observations = storage_evidence.get("observations")
    if not isinstance(storage_observations, dict) or set(storage_observations) != {
        "create_forces_enable_true",
        "readback_shape",
        "litelist_filter",
        "cleanup",
    }:
        fail("StorageManagement runtime observations regressed")
    for field in ("verification", "security"):
        value = storage_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"StorageManagement evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_storage_probe.py").is_file():
        fail("StorageManagement runtime probe tool is missing")

    webdav_evidence = model_evidence.get("webdav_storage_behavior")
    if not isinstance(webdav_evidence, dict):
        fail("WebDAV + Storage behavior evidence is missing")
    if webdav_evidence.get("confidence") != "runtime-verified":
        fail("WebDAV + Storage behavior evidence must remain runtime-verified")
    webdav_model = webdav_evidence.get("model")
    if not isinstance(webdav_model, dict) or set(webdav_model) != {
        "service_lifecycle",
        "principal_model",
        "protocol",
        "storage_writable_enforcement",
        "isolation",
    }:
        fail("WebDAV + Storage behavior model regressed")
    webdav_observations = webdav_evidence.get("observations")
    if not isinstance(webdav_observations, dict) or set(webdav_observations) != {
        "writable_mount",
        "readonly_mount",
        "readback",
        "cleanup",
    }:
        fail("WebDAV + Storage runtime observations regressed")
    for field in ("verification", "security"):
        value = webdav_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"WebDAV + Storage evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_webdav_probe.py").is_file():
        fail("WebDAV runtime probe tool is missing")

    ftp_evidence = model_evidence.get("ftp_ci_behavior")
    if not isinstance(ftp_evidence, dict):
        fail("FTP CI behavior evidence is missing")
    if ftp_evidence.get("confidence") != "runtime-verified":
        fail("FTP CI behavior evidence must remain runtime-verified")
    ftp_model = ftp_evidence.get("model")
    if not isinstance(ftp_model, dict) or set(ftp_model) != {
        "service_lifecycle",
        "principal_model",
        "protocol",
        "root_mapping",
        "passive_range",
        "isolation",
    }:
        fail("FTP CI behavior model regressed")
    ftp_observations = ftp_evidence.get("observations")
    if not isinstance(ftp_observations, dict) or set(ftp_observations) != {
        "authentication",
        "list_and_transfer",
        "readback",
        "cleanup",
    }:
        fail("FTP CI behavior observations regressed")
    for field in ("verification", "security"):
        value = ftp_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"FTP CI behavior evidence field is missing: {field}")
    if "127.0.0.1" not in str(ftp_model.get("isolation")):
        fail("FTP CI loopback isolation evidence regressed")
    if "difference" not in str(ftp_model.get("passive_range")):
        fail("FTP passive-range behavior evidence regressed")
    if "FTP root" not in str(ftp_model.get("root_mapping")):
        fail("FTP single-mount root behavior evidence regressed")
    if "STOR" not in str(ftp_model.get("protocol")) or "RETR" not in str(ftp_model.get("protocol")):
        fail("FTP transfer behavior evidence regressed")
    if not (ROOT / "tools" / "lucky_ftp_ci_probe.py").is_file():
        fail("FTP CI runtime probe tool is missing")
    if not (ROOT / ".github" / "workflows" / "lucky-ftp-ci.yml").is_file():
        fail("FTP CI workflow is missing")

    wol_evidence = model_evidence.get("wol_ci_behavior")
    if not isinstance(wol_evidence, dict):
        fail("WOL CI behavior evidence is missing")
    if wol_evidence.get("confidence") != "runtime-verified":
        fail("WOL CI behavior evidence must remain runtime-verified")
    wol_model = wol_evidence.get("model")
    if not isinstance(wol_model, dict) or set(wol_model) != {
        "device_lifecycle",
        "service_lifecycle",
        "wake_packet",
        "destination_port",
        "state_boundary",
        "isolation",
    }:
        fail("WOL CI behavior model regressed")
    wol_observations = wol_evidence.get("observations")
    if not isinstance(wol_observations, dict) or set(wol_observations) != {
        "packet",
        "port",
        "device_state",
        "schema",
        "cleanup",
    }:
        fail("WOL CI behavior observations regressed")
    for field in ("verification", "security"):
        value = wol_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"WOL CI behavior evidence field is missing: {field}")
    if "102-byte" not in str(wol_model.get("wake_packet")):
        fail("WOL standard magic-packet evidence regressed")
    if "UDP destination port 9" not in str(wol_model.get("destination_port")):
        fail("WOL UDP/9 destination evidence regressed")
    if "--internal" not in str(wol_model.get("isolation")):
        fail("WOL internal-network isolation evidence regressed")
    if "shutdown" not in str(wol_model.get("state_boundary")).lower():
        fail("WOL shutdown safety boundary evidence regressed")
    if not (ROOT / "tools" / "lucky_wol_ci_probe.py").is_file():
        fail("WOL CI runtime probe tool is missing")
    if not (ROOT / ".github" / "workflows" / "lucky-wol-ci.yml").is_file():
        fail("WOL CI workflow is missing")

    natpmp_evidence = model_evidence.get("stun_natpmp_ci_behavior")
    if not isinstance(natpmp_evidence, dict):
        fail("STUN NAT-PMP CI behavior evidence is missing")
    if natpmp_evidence.get("confidence") != "runtime-verified":
        fail("STUN NAT-PMP CI behavior evidence must remain runtime-verified")
    natpmp_model = natpmp_evidence.get("model")
    if not isinstance(natpmp_model, dict) or set(natpmp_model) != {
        "topology",
        "control_plane",
        "public_endpoint",
        "mapping_data_plane",
        "renewal",
        "delete",
    }:
        fail("STUN NAT-PMP CI behavior model regressed")
    natpmp_observations = natpmp_evidence.get("observations")
    if not isinstance(natpmp_observations, dict) or set(natpmp_observations) != {
        "protocol",
        "data_plane",
        "logs",
        "cleanup",
    }:
        fail("STUN NAT-PMP CI behavior observations regressed")
    for field in ("verification", "security"):
        value = natpmp_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"STUN NAT-PMP CI behavior evidence field is missing: {field}")
    if "UDP/5351" not in str(natpmp_model.get("control_plane")):
        fail("STUN NAT-PMP UDP/5351 evidence regressed")
    if "mapping relay" not in str(natpmp_model.get("mapping_data_plane")):
        fail("STUN NAT-PMP mapping-relay evidence regressed")
    if "lifetime=0" not in str(natpmp_model.get("delete")):
        fail("STUN NAT-PMP deletion evidence regressed")
    if "network namespace" not in str(natpmp_model.get("topology")):
        fail("STUN NAT-PMP WAN isolation evidence regressed")
    if not (ROOT / "tools" / "lucky_natpmp_ci_probe.py").is_file():
        fail("STUN NAT-PMP CI runtime probe tool is missing")
    if not (ROOT / ".github" / "workflows" / "lucky-natpmp-ci.yml").is_file():
        fail("STUN NAT-PMP CI workflow is missing")

    upnp_evidence = model_evidence.get("stun_upnp_ci_behavior")
    if not isinstance(upnp_evidence, dict):
        fail("STUN UPnP CI behavior evidence is missing")
    if upnp_evidence.get("confidence") != "runtime-verified":
        fail("STUN UPnP CI behavior evidence must remain runtime-verified")
    upnp_model = upnp_evidence.get("model")
    if not isinstance(upnp_model, dict) or set(upnp_model) != {
        "topology",
        "discovery",
        "control_plane",
        "mapping_data_plane",
        "public_endpoint",
        "delete",
    }:
        fail("STUN UPnP CI behavior model regressed")
    upnp_observations = upnp_evidence.get("observations")
    if not isinstance(upnp_observations, dict) or set(upnp_observations) != {
        "soap",
        "mapping",
        "data_plane",
        "stun_binding",
        "cleanup",
    }:
        fail("STUN UPnP CI behavior observations regressed")
    for field in ("verification", "security"):
        value = upnp_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"STUN UPnP CI behavior evidence field is missing: {field}")
    if "SSDP" not in str(upnp_model.get("discovery")):
        fail("STUN UPnP SSDP discovery evidence regressed")
    if "AddPortMapping" not in str(upnp_model.get("control_plane")):
        fail("STUN UPnP AddPortMapping evidence regressed")
    if "mapping relay" not in str(upnp_model.get("mapping_data_plane")):
        fail("STUN UPnP mapping-relay evidence regressed")
    if "DeletePortMapping" not in str(upnp_model.get("delete")):
        fail("STUN UPnP deletion evidence regressed")
    if "network namespace" not in str(upnp_model.get("topology")):
        fail("STUN UPnP WAN isolation evidence regressed")
    if "zero requests" not in str(upnp_observations.get("stun_binding")):
        fail("STUN UPnP STUN-binding observation regressed")
    if not (ROOT / "tools" / "lucky_upnp_ci_probe.py").is_file():
        fail("STUN UPnP CI runtime probe tool is missing")
    if not (ROOT / ".github" / "workflows" / "lucky-upnp-ci.yml").is_file():
        fail("STUN UPnP CI workflow is missing")

    smb_evidence = model_evidence.get("smb_loopback_behavior")
    if not isinstance(smb_evidence, dict):
        fail("SMB loopback behavior evidence is missing")
    if smb_evidence.get("confidence") != "runtime-verified":
        fail("SMB loopback behavior evidence must remain runtime-verified")
    smb_model = smb_evidence.get("model")
    if not isinstance(smb_model, dict) or set(smb_model) != {
        "service_lifecycle",
        "guest_protocol",
        "share_model",
        "file_lifecycle",
        "runtime",
        "isolation",
    }:
        fail("SMB loopback behavior model regressed")
    smb_observations = smb_evidence.get("observations")
    if not isinstance(smb_observations, dict) or set(smb_observations) != {
        "dialect",
        "guest_session",
        "curl_boundary",
        "backing_file",
        "cleanup",
    }:
        fail("SMB loopback behavior observations regressed")
    for field in ("verification", "security"):
        value = smb_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"SMB loopback behavior evidence field is missing: {field}")
    if "0x0210" not in str(smb_model.get("guest_protocol")):
        fail("SMB2 dialect evidence regressed")
    if "127.0.0.1" not in str(smb_model.get("isolation")):
        fail("SMB loopback isolation evidence regressed")
    if "delete-on-close" not in str(smb_model.get("file_lifecycle")):
        fail("SMB delete-on-close behavior evidence regressed")
    if not (ROOT / "tools" / "lucky_smb_probe.py").is_file():
        fail("SMB runtime probe tool is missing")

    dlna_evidence = model_evidence.get("dlna_isolated_behavior")
    if not isinstance(dlna_evidence, dict):
        fail("DLNA isolated behavior evidence is missing")
    if dlna_evidence.get("confidence") != "runtime-verified":
        fail("DLNA isolated behavior evidence must remain runtime-verified")
    dlna_model = dlna_evidence.get("model")
    if not isinstance(dlna_model, dict) or set(dlna_model) != {
        "service_lifecycle",
        "mount_model",
        "device_description",
        "content_directory",
        "interface_boundary",
        "ssdp_boundary",
    }:
        fail("DLNA isolated behavior model regressed")
    dlna_observations = dlna_evidence.get("observations")
    if not isinstance(dlna_observations, dict) or set(dlna_observations) != {
        "loopback_rejected",
        "http_upnp",
        "friendly_name",
        "ssdp",
        "cleanup",
    }:
        fail("DLNA isolated behavior observations regressed")
    for field in ("verification", "security"):
        value = dlna_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"DLNA isolated behavior evidence field is missing: {field}")
    if "ContentDirectory" not in str(dlna_model.get("content_directory")):
        fail("DLNA ContentDirectory runtime behavior evidence regressed")
    if "zero attached veths" not in str(dlna_model.get("interface_boundary")):
        fail("DLNA empty-bridge isolation evidence regressed")
    if not (ROOT / "tools" / "lucky_dlna_probe.py").is_file():
        fail("DLNA runtime probe tool is missing")

    frp_visitor_evidence = model_evidence.get("frp_stcp_visitor_behavior")
    if not isinstance(frp_visitor_evidence, dict):
        fail("FRP STCP visitor behavior evidence is missing")
    if frp_visitor_evidence.get("confidence") != "runtime-verified":
        fail("FRP STCP visitor behavior evidence must remain runtime-verified")
    frp_visitor_model = frp_visitor_evidence.get("model")
    if not isinstance(frp_visitor_model, dict) or set(frp_visitor_model) != {
        "topology",
        "provider_proxy",
        "visitor",
        "data_plane",
        "transport_update",
        "status_boundary",
    }:
        fail("FRP STCP visitor behavior model regressed")
    frp_visitor_observations = frp_visitor_evidence.get("observations")
    if not isinstance(frp_visitor_observations, dict) or set(frp_visitor_observations) != {
        "visitor_readback",
        "roundtrip",
        "status",
        "cleanup",
    }:
        fail("FRP STCP visitor observations regressed")
    for field in ("verification", "security"):
        value = frp_visitor_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"FRP STCP visitor evidence field is missing: {field}")
    if "127.0.0.1" not in str(frp_visitor_model.get("visitor")):
        fail("FRP visitor loopback binding evidence regressed")
    if "visitorStatuses" not in str(frp_visitor_model.get("status_boundary")):
        fail("FRP visitor status-boundary evidence regressed")
    if not (ROOT / "tools" / "lucky_frp_visitor_probe.py").is_file():
        fail("FRP STCP visitor runtime probe tool is missing")

    filebrowser_evidence = model_evidence.get("filebrowser_local_behavior")
    if not isinstance(filebrowser_evidence, dict):
        fail("FileBrowser local behavior evidence is missing")
    if filebrowser_evidence.get("confidence") != "runtime-verified":
        fail("FileBrowser local behavior evidence must remain runtime-verified")
    filebrowser_model = filebrowser_evidence.get("model")
    if not isinstance(filebrowser_model, dict) or set(filebrowser_model) != {
        "service_lifecycle",
        "mount_model",
        "fresh_database_auth",
        "resource_api",
        "single_mount_root",
        "isolation",
    }:
        fail("FileBrowser local behavior model regressed")
    filebrowser_observations = filebrowser_evidence.get("observations")
    if not isinstance(filebrowser_observations, dict) or set(filebrowser_observations) != {
        "config_readback",
        "auth",
        "file_lifecycle",
        "delete_semantics",
        "cleanup",
    }:
        fail("FileBrowser local behavior observations regressed")
    for field in ("verification", "security"):
        value = filebrowser_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"FileBrowser local behavior evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_filebrowser_probe.py").is_file():
        fail("FileBrowser runtime probe tool is missing")

    rclone_evidence = model_evidence.get("rclone_local_sync_behavior")
    if not isinstance(rclone_evidence, dict):
        fail("Rclone local sync behavior evidence is missing")
    if rclone_evidence.get("confidence") != "runtime-verified":
        fail("Rclone local sync behavior evidence must remain runtime-verified")
    rclone_model = rclone_evidence.get("model")
    if not isinstance(rclone_model, dict) or set(rclone_model) != {
        "task_model",
        "real_sync",
        "file_copy",
        "stop",
        "system_mount_boundary",
        "dry_run",
        "state",
        "scope",
    }:
        fail("Rclone local sync behavior model regressed")
    rclone_observations = rclone_evidence.get("observations")
    if not isinstance(rclone_observations, dict) or set(rclone_observations) != {
        "real_run",
        "file_copy",
        "stop",
        "system_mount_blocked",
        "dry_run",
        "detail_vs_list",
        "cleanup",
    }:
        fail("Rclone local sync runtime observations regressed")
    for field in ("verification", "security"):
        value = rclone_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Rclone local sync evidence field is missing: {field}")
    if "SyncMode=sync" not in str(rclone_model.get("file_copy")):
        fail("Rclone file-copy evidence must remain tied to the verified sync mode")
    if "Cron" not in str(rclone_model.get("file_copy")):
        fail("Rclone file-copy evidence must retain the owned Cron helper boundary")
    if "State.Status=success" not in str(rclone_model.get("stop")):
        fail("Rclone stop evidence must preserve the post-stop success-state caveat")
    system_mount_boundary = str(rclone_model.get("system_mount_boundary"))
    if "operation not permitted" not in system_mount_boundary or "SYS_ADMIN" not in system_mount_boundary:
        fail("Rclone SystemMount blocked-runtime evidence regressed")
    if not (ROOT / "tools" / "lucky_rclone_stop_probe.py").is_file():
        fail("Rclone stop runtime probe tool is missing")
    if not (ROOT / "tools" / "lucky_rclone_sync_probe.py").is_file():
        fail("Rclone local sync runtime probe tool is missing")

    cron_evidence = model_evidence.get("cron_shell_behavior")
    if not isinstance(cron_evidence, dict):
        fail("Cron shell behavior evidence is missing")
    if cron_evidence.get("confidence") != "runtime-verified":
        fail("Cron shell behavior evidence must remain runtime-verified")
    cron_model = cron_evidence.get("model")
    if not isinstance(cron_model, dict) or set(cron_model) != {
        "job_model",
        "manual_task_trigger",
        "single_job_trigger",
        "scheduled_execution",
        "failure_logging",
        "scope",
    }:
        fail("Cron shell behavior model regressed")
    cron_observations = cron_evidence.get("observations")
    if not isinstance(cron_observations, dict) or set(cron_observations) != {
        "manual_execution",
        "scheduled_execution",
        "failure_execution",
        "shape",
        "cleanup",
    }:
        fail("Cron shell runtime observations regressed")
    for field in ("verification", "security"):
        value = cron_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Cron shell evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_cron_probe.py").is_file():
        fail("Cron shell runtime probe tool is missing")

    compose_evidence = model_evidence.get("docker_compose_behavior")
    if not isinstance(compose_evidence, dict):
        fail("Docker Compose behavior evidence is missing")
    if compose_evidence.get("confidence") != "runtime-verified":
        fail("Docker Compose behavior evidence must remain runtime-verified")
    compose_model = compose_evidence.get("model")
    if not isinstance(compose_model, dict) or set(compose_model) != {
        "fresh_sync_create",
        "current_ui_async_flow",
        "lifecycle",
        "inspection",
        "task_history",
        "isolation",
    }:
        fail("Docker Compose behavior model regressed")
    compose_observations = compose_evidence.get("observations")
    if not isinstance(compose_observations, dict) or set(compose_observations) != {
        "sync_name_collision",
        "async_tasks",
        "container_isolation",
        "read_paths",
        "cleanup",
    }:
        fail("Docker Compose runtime observations regressed")
    for field in ("verification", "security"):
        value = compose_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Docker Compose evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_docker_compose_probe.py").is_file():
        fail("Docker Compose runtime probe tool is missing")

    docker_image_evidence = model_evidence.get("docker_image_import_load_behavior")
    if not isinstance(docker_image_evidence, dict):
        fail("Docker image import/load behavior evidence is missing")
    if docker_image_evidence.get("confidence") != "runtime-verified":
        fail("Docker image import/load behavior evidence must remain runtime-verified")
    docker_image_model = docker_image_evidence.get("model")
    if not isinstance(docker_image_model, dict) or set(docker_image_model) != {
        "import",
        "tag_and_save",
        "frontend_upload",
        "load",
        "scope",
    }:
        fail("Docker image import/load behavior model regressed")
    docker_image_observations = docker_image_evidence.get("observations")
    if not isinstance(docker_image_observations, dict) or set(docker_image_observations) != {
        "import",
        "save",
        "upload_temp",
        "load",
        "cleanup",
    }:
        fail("Docker image import/load runtime observations regressed")
    for field in ("verification", "security"):
        value = docker_image_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Docker image import/load evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_docker_image_import_probe.py").is_file():
        fail("Docker image import/load runtime probe tool is missing")

    docker_build_evidence = model_evidence.get("docker_image_build_behavior")
    if not isinstance(docker_build_evidence, dict):
        fail("Docker image build behavior evidence is missing")
    if docker_build_evidence.get("confidence") != "runtime-verified":
        fail("Docker image build behavior evidence must remain runtime-verified")
    docker_build_model = docker_build_evidence.get("model")
    if not isinstance(docker_build_model, dict) or set(docker_build_model) != {
        "dockerfile_text",
        "zip_context",
        "git_context",
        "response",
        "isolation",
        "cleanup",
    }:
        fail("Docker image build behavior model regressed")
    docker_build_observations = docker_build_evidence.get("observations")
    if not isinstance(docker_build_observations, dict) or set(docker_build_observations) != {
        "zip",
        "git",
        "admin_auth",
        "cleanup",
    }:
        fail("Docker image build runtime observations regressed")
    for field in ("verification", "security"):
        value = docker_build_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Docker image build evidence field is missing: {field}")
    if "GitHub Actions" not in str(docker_build_evidence.get("security")):
        fail("Docker image build evidence lost its GitHub Actions-only safety boundary")
    git_context_evidence = str(docker_build_model.get("git_context"))
    if not all(marker in git_context_evidence for marker in ("fake git", "clone", "external Git")):
        fail("Docker image build evidence lost its no-external-Git isolation model")
    if not (ROOT / "tools" / "lucky_docker_build_ci_probe.py").is_file():
        fail("Docker image build CI probe tool is missing")
    if not (ROOT / ".github" / "workflows" / "lucky-docker-build-ci.yml").is_file():
        fail("Docker image build CI workflow is missing")

    security_group_evidence = model_evidence.get("security_group_webauth_behavior")
    if not isinstance(security_group_evidence, dict):
        fail("Security Group + WebAuth behavior evidence is missing")
    if security_group_evidence.get("confidence") != "runtime-verified":
        fail("Security Group + WebAuth behavior evidence must remain runtime-verified")
    security_group_model = security_group_evidence.get("model")
    if not isinstance(security_group_model, dict) or set(security_group_model) != {
        "principals",
        "basic_auth",
        "webauth_login",
        "authorization",
        "grant_runtime",
        "access_mode",
    }:
        fail("Security Group + WebAuth behavior model regressed")
    security_group_observations = security_group_evidence.get("observations")
    if not isinstance(security_group_observations, dict) or set(security_group_observations) != {
        "basic_auth",
        "webauth_protocol",
        "group_enforcement",
        "grant",
        "cleanup",
    }:
        fail("Security Group + WebAuth runtime observations regressed")
    for field in ("verification", "security"):
        value = security_group_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"Security Group + WebAuth evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_security_group_probe.py").is_file():
        fail("Security Group + WebAuth runtime probe tool is missing")

    ddns_evidence = model_evidence.get("ddns_cloudflare_behavior")
    if not isinstance(ddns_evidence, dict):
        fail("DDNS Cloudflare behavior evidence is missing")
    if ddns_evidence.get("confidence") != "runtime-verified":
        fail("DDNS Cloudflare behavior evidence must remain runtime-verified")
    ddns_model = ddns_evidence.get("model")
    required_ddns_model = {
        "write_model",
        "ipv4_record_template",
        "url_query",
        "manual_sync",
        "webhook_test",
    }
    if not isinstance(ddns_model, dict) or set(ddns_model) != required_ddns_model:
        fail("DDNS Cloudflare behavior model regressed")
    for field in required_ddns_model:
        if not isinstance(ddns_model.get(field), str) or not ddns_model[field].strip():
            fail(f"DDNS Cloudflare behavior model field is missing: {field}")
    ddns_observations = ddns_evidence.get("observations")
    if not isinstance(ddns_observations, dict) or set(ddns_observations) != {
        "create_validation",
        "template_semantics",
        "manual_sync",
        "cleanup",
    }:
        fail("DDNS Cloudflare runtime observations regressed")
    for field in ("verification", "security"):
        value = ddns_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"DDNS Cloudflare evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_ddns_probe.py").is_file():
        fail("DDNS runtime probe tool is missing")

    reverse_proxy_evidence = model_evidence.get("webservice_reverseproxy_semantics")
    if not isinstance(reverse_proxy_evidence, dict):
        fail("WebService reverse-proxy model evidence is missing")
    if reverse_proxy_evidence.get("confidence") != "runtime-verified":
        fail("WebService reverse-proxy model evidence must remain runtime-verified")
    reverse_proxy_model = reverse_proxy_evidence.get("model")
    if not isinstance(reverse_proxy_model, dict):
        fail("WebService reverse-proxy model is malformed")
    nginx_model = reverse_proxy_model.get("NginxConf")
    if not isinstance(nginx_model, dict) or nginx_model.get("type") != "string":
        fail("WebService NginxConf model must remain a string configuration field")
    if nginx_model.get("directives") != [
        "proxy_set_header",
        "proxy_hide_header",
        "add_header",
        "proxy_redirect",
        "location",
        "path",
    ]:
        fail("WebService NginxConf directive evidence regressed")
    variables = nginx_model.get("variables")
    required_variables = {
        "$host",
        "$http_host",
        "$scheme",
        "$request",
        "$request_method",
        "$request_uri",
        "$uri",
        "$document_uri",
        "$args",
        "$query_string",
        "$is_args",
        "$remote_addr",
        "$remote_port",
        "$server_port",
        "$http_upgrade",
        "$connection_upgrade",
        "$proxy_add_x_forwarded_for",
        "$http_<request-header-name>",
    }
    if not isinstance(variables, list) or set(variables) != required_variables:
        fail("WebService NginxConf variable evidence regressed")
    for field in (
        "write_model",
        "UseTargetHost",
        "AutoProxyLocation",
        "AutoProxyLocationWithoutSameHost",
        "AddProtoToHeader",
        "AddRemoteIPToHeader",
        "path_matching",
    ):
        value = reverse_proxy_model.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"WebService reverse-proxy model field is missing: {field}")
    observations = reverse_proxy_evidence.get("observations")
    if not isinstance(observations, dict) or set(observations) != {
        "add_header",
        "proxy_redirect",
        "auto_proxy_location",
        "connection_upgrade",
    }:
        fail("WebService reverse-proxy runtime observations regressed")
    for field in ("frontend_evidence", "verification", "security"):
        value = reverse_proxy_evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"WebService reverse-proxy evidence field is missing: {field}")
    if not (ROOT / "tools" / "lucky_web_reverseproxy_probe.py").is_file():
        fail("WebService reverse-proxy runtime probe tool is missing")

    verified = runtime.get("routes")
    if not isinstance(verified, list):
        fail("runtime verified routes must be an array")
    keys: list[tuple[str, str]] = []
    for item in verified:
        if not isinstance(item, dict):
            fail("runtime verified route must be an object")
        path = item.get("path")
        method = item.get("method")
        risk = item.get("risk")
        if not isinstance(path, str) or not path.startswith("/api/"):
            fail("runtime verified route has invalid path")
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            fail(f"runtime verified route has invalid method: {method}")
        if risk not in {item.value for item in OperationRisk if item is not OperationRisk.UNKNOWN}:
            fail(f"runtime verified route has invalid risk: {risk}")
        for field in ("query_keys", "body_keys"):
            value = item.get(field)
            if value is not None and (
                not isinstance(value, list) or not all(isinstance(key, str) and key for key in value)
            ):
                fail(f"runtime verified route {field} must be an array of non-empty strings")
        for field in ("request_body_schema", "response_schema"):
            value = item.get(field)
            if value is not None and not isinstance(value, dict):
                fail(f"runtime verified route {field} must be an object")
        for field in ("request_content_type", "response_content_type", "schema_evidence"):
            value = item.get(field)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                fail(f"runtime verified route {field} must be a non-empty string")
        success_response_markers = item.get("success_response_markers")
        if success_response_markers is not None:
            if not isinstance(success_response_markers, list) or not success_response_markers:
                fail("runtime success_response_markers must be a non-empty array")
            normalized_markers: list[tuple[int, str]] = []
            for marker in success_response_markers:
                if (
                    not isinstance(marker, dict)
                    or set(marker) != {"ret", "msg"}
                    or type(marker.get("ret")) is not int
                    or marker["ret"] <= 0
                    or not isinstance(marker.get("msg"), str)
                    or not marker["msg"]
                ):
                    fail(
                        "runtime success_response_markers entries require positive integer ret and non-empty msg"
                    )
                normalized_markers.append((marker["ret"], marker["msg"]))
            if len(normalized_markers) != len(set(normalized_markers)):
                fail("runtime success_response_markers must be unique")
            response_schema = item.get("response_schema")
            properties = response_schema.get("properties", {}) if isinstance(response_schema, dict) else {}
            if (
                properties.get("ret") != {"type": "integer"}
                or properties.get("msg") != {"type": "string"}
                or not item.get("schema_evidence")
            ):
                fail(
                    "runtime success_response_markers require integer ret/string msg response schema and schema evidence"
                )
        keys.append((path, str(method)))
    if len(keys) != len(set(keys)):
        fail("runtime verified routes contain duplicate path/method entries")

    schema_patches = runtime.get("schema_patches", [])
    if not isinstance(schema_patches, list):
        fail("runtime schema_patches must be an array")
    patch_keys = []
    for patch in schema_patches:
        if not isinstance(patch, dict):
            fail("runtime schema patch must be an object")
        path = patch.get("path")
        method = patch.get("method")
        at = patch.get("at")
        value = patch.get("value")
        evidence = patch.get("evidence")
        if not isinstance(path, str) or not path.startswith("/api/"):
            fail("runtime schema patch has invalid path")
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            fail("runtime schema patch has invalid method")
        if not isinstance(at, list) or not at or not all(isinstance(key, str) and key for key in at):
            fail("runtime schema patch at must be a non-empty string path")
        if not isinstance(value, dict) or not value:
            fail("runtime schema patch value must be a non-empty object")
        if not isinstance(evidence, str) or not evidence.strip():
            fail("runtime schema patch requires evidence")
        patch_keys.append((path, method, tuple(at)))
    if len(patch_keys) != len(set(patch_keys)):
        fail("runtime schema_patches contain duplicate targets")

    patched_merged = RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)
    merged = RouteCatalog.from_file(
        snapshot_path,
        runtime_verification=runtime_path,
        apply_schema_patches=False,
    )
    unknown = patched_merged.search(risk=OperationRisk.UNKNOWN)
    if unknown:
        fail(f"runtime route verification leaves {len(unknown)} unknown route(s)")
    unknown_response_types = [
        route for route in patched_merged.routes if route.response_type == "unknown"
    ]
    if unknown_response_types:
        fail(
            "runtime route verification leaves "
            f"{len(unknown_response_types)} unknown response type(s)"
        )

    expected_body_schema_gaps: set[tuple[str, str]] = set()
    actual_body_schema_gaps = {
        (route.method, route.path)
        for route in merged.routes
        if route.method in {"POST", "PUT", "PATCH"}
        and route.has_body
        and not route.body_keys
        and route.request_body_schema is None
    }
    if actual_body_schema_gaps != expected_body_schema_gaps:
        missing = sorted(expected_body_schema_gaps - actual_body_schema_gaps)
        added = sorted(actual_body_schema_gaps - expected_body_schema_gaps)
        fail(
            "request-body schema gap set changed; "
            f"resolved={missing or 'none'} new={added or 'none'}"
        )

    legacy_docker_schemas = {
        ("POST", "/api/docker/containers/{param}/upgrade"): {
            "type": "object",
            "properties": {},
        },
        ("POST", "/api/docker/images/build"): {
            "type": "object",
            "properties": {"dockerfile": {"type": "string"}},
            "required": ["dockerfile"],
        },
        ("POST", "/api/docker/images/build-from-git"): {
            "type": "object",
            "properties": {"git_url": {"type": "string"}},
            "required": ["git_url"],
        },
        ("POST", "/api/docker/images/build-from-zip"): {
            "type": "object",
            "properties": {"zip_path": {"type": "string"}},
            "required": ["zip_path"],
        },
        ("POST", "/api/docker/images/import"): {
            "type": "object",
            "properties": {"source": {"type": "string"}},
            "required": ["source"],
        },
        ("POST", "/api/docker/prune"): {
            "type": "object",
            "properties": {
                "all": {"type": "boolean"},
                "volumes": {"type": "boolean"},
            },
        },
    }
    merged_by_key = {(route.method, route.path): route for route in merged.routes}
    patched_by_key = {(route.method, route.path): route for route in patched_merged.routes}

    conservative_get_risks = {
        ("GET", "/api/docker/volumes/export"): OperationRisk.DANGEROUS,
        ("GET", "/api/ipfliter/oneclickrecord"): OperationRisk.MUTATING,
        ("GET", "/api/ipfliter/porttrap/blockedips/export"): OperationRisk.DANGEROUS,
        ("GET", "/api/third/filebrowser/resetadmin"): OperationRisk.DANGEROUS,
        ("GET", "/api/webservice/statistics/export"): OperationRisk.DANGEROUS,
        ("GET", "/api/ddns/getipfromcmdtest"): OperationRisk.DANGEROUS,
    }
    for route_key, expected_risk in conservative_get_risks.items():
        route = merged_by_key.get(route_key)
        if route is None or route.risk is not expected_risk:
            fail(f"conservative GET risk classification regressed for {route_key}: {getattr(route, 'risk', None)}")
    for route_key in {
        ("GET", "/api/docker/compose/backup/status"),
        ("GET", "/api/docker/volumes/backup/status"),
        ("GET", "/api/webservice/statistics/import/status"),
    }:
        route = merged_by_key.get(route_key)
        if route is None or route.risk is not OperationRisk.READ_ONLY:
            fail(f"read-only status GET was over-classified by action-name hardening: {route_key}")

    for key, expected_schema in legacy_docker_schemas.items():
        route = merged_by_key.get(key)
        if route is None or route.request_body_schema != expected_schema:
            fail(f"legacy Docker schema evidence changed unexpectedly for {key[0]} {key[1]}")

    docker_build_response = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "output": {"type": "string"},
        },
    }
    for route_key in {
        ("POST", "/api/docker/images/build-from-git"),
        ("POST", "/api/docker/images/build-from-zip"),
    }:
        route = merged_by_key[route_key]
        if route.response_schema != docker_build_response:
            fail(f"Docker image build runtime response schema regressed for {route_key}")
        if route.confidence != "runtime-verified":
            fail(f"Docker image build route must remain runtime-verified for {route_key}")

    untyped_request_routes = [
        route
        for route in merged.routes
        if route.method in {"POST", "PUT", "PATCH"}
        and route.has_body
        and route.body_keys
        and route.request_body_schema is None
    ]
    if untyped_request_routes:
        fail(
            "typed request-schema coverage regressed; "
            f"expected zero field-bearing write routes without explicit schemas, got {len(untyped_request_routes)}"
        )

    coraza_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"},
            "Name": {"type": "string"},
            "Enable": {"type": "boolean"},
            "InboundScoreThreshold": {"type": "integer"},
            "OutboundScoreThreshold": {"type": "integer"},
            "CorazaWAFConfigList": {"type": "array", "items": {}},
            "RuleExclusions": {"type": "array", "items": {}},
        },
    }
    ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {
        ("POST", "/api/coraza/list"),
        ("PUT", "/api/coraza/list"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != coraza_request:
            fail(f"Coraza disposable-instance request schema regressed for {route_key}")
        if set(route.body_keys) != set(coraza_request["properties"]):
            fail(f"Coraza request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"Coraza request schema must not invent required fields for {route_key}")
        if route.response_schema != ret_only:
            fail(f"Coraza disposable-instance ret-only response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/coraza/list/{param}")].response_schema != ret_only:
        fail("Coraza disposable-instance delete response schema regressed")

    coraza_list = merged_by_key[("GET", "/api/coraza/list")].response_schema
    coraza_item_props = (
        coraza_list.get("properties", {}).get("list", {}).get("items", {}).get("properties", {})
        if isinstance(coraza_list, dict)
        else {}
    )
    expected_coraza_item_props = {
        "Key": {"type": "string"},
        "Name": {"type": "string"},
        "Enable": {"type": "boolean"},
        "InboundScoreThreshold": {"type": "integer"},
        "OutboundScoreThreshold": {"type": "integer"},
        "EnabledRulesCount": {"type": "integer"},
        "TotalRulesCount": {"type": "integer"},
        "ExclusionsCount": {"type": "integer"},
    }
    if coraza_item_props != expected_coraza_item_props:
        fail("Coraza safe list item schema regressed")

    expected_coraza_detail = {
        "type": "object",
        "properties": {
            "instance": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Name": {"type": "string"},
                    "Enable": {"type": "boolean"},
                    "InboundScoreThreshold": {"type": "integer"},
                    "OutboundScoreThreshold": {"type": "integer"},
                    "CorazaWAFConfigList": {"type": "array", "items": {}},
                    "RuleExclusions": {"type": "array", "items": {}},
                },
            },
            "ret": {"type": "integer"},
        },
    }
    if merged_by_key[("GET", "/api/coraza/list/{param}")].response_schema != expected_coraza_detail:
        fail("Coraza disposable detail response schema regressed")
    coraza_toggle = merged_by_key[("GET", "/api/coraza/list/{param}/{param2}")]
    if coraza_toggle.risk is not OperationRisk.MUTATING:
        fail("Coraza enable/disable GET must remain classified as mutating")
    if coraza_toggle.response_schema != ret_only:
        fail("Coraza enable/disable GET ret-only response schema regressed")

    ipdb_item_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"},
            "Remark": {"type": "string"},
            "Enable": {"type": "boolean"},
            "Format": {"type": "string"},
            "FilePath": {"type": "string"},
            "SupportTypes": {"type": "integer"},
            "BufferType": {"type": "integer"},
            "DBParam1": {"type": "string"},
        },
    }
    for route_key in {
        ("POST", "/api/ipdb/item"),
        ("PUT", "/api/ipdb/item"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != ipdb_item_request:
            fail(f"IPDB parser-verified item request schema regressed for {route_key}")
        if set(route.body_keys) != set(ipdb_item_request["properties"]):
            fail(f"IPDB item request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"IPDB item request schema must not invent required fields for {route_key}")
        if route.response_schema is not None:
            fail(f"IPDB parser-only schema evidence must not claim a success response for {route_key}")

    rclone_remote_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"},
            "Type": {"type": "string"},
            "Enable": {"type": "boolean"},
            "Remark": {"type": "string"},
            "Root": {"type": "string"},
            "Params": {"type": "object", "additionalProperties": {}},
            "HttpClienInsecureSkipVerify": {"type": "boolean"},
            "HttpClientProxyType": {"type": "string"},
            "HttpClientProxyAddr": {"type": "string"},
            "HttpClientProxyUser": {"type": "string"},
            "HttpClientProxyPassword": {"type": "string"},
            "SystemMount": {"type": "object"},
        },
    }
    for route_key in {
        ("POST", "/api/rclone/remotelist"),
        ("PUT", "/api/rclone/remotelist"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != rclone_remote_request:
            fail(f"Rclone parser-verified remote request schema regressed for {route_key}")
        if set(route.body_keys) != set(rclone_remote_request["properties"]):
            fail(f"Rclone remote request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"Rclone remote request schema must not invent required fields for {route_key}")
        if route.response_schema != {"type": "object", "properties": {"ret": {"type": "integer"}}}:
            fail(f"Rclone disposable remote ret-only response schema regressed for {route_key}")

    rclone_sync_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Enable": {"type": "boolean"}, "Remark": {"type": "string"},
            "SourceType": {"type": "string"}, "SourceRemoteKey": {"type": "string"}, "SourcePath": {"type": "string"},
            "DestType": {"type": "string"}, "DestRemoteKey": {"type": "string"}, "DestPath": {"type": "string"},
            "SyncMode": {"type": "string"}, "DeleteOnDest": {"type": "boolean"}, "DryRun": {"type": "boolean"},
            "CreateEmptyDirs": {"type": "boolean"}, "IgnoreExisting": {"type": "boolean"}, "IgnoreErrors": {"type": "boolean"},
            "CheckFirst": {"type": "boolean"}, "Transfers": {"type": "integer"}, "Checkers": {"type": "integer"},
            "BandwidthLimit": {"type": "string"}, "MinAge": {"type": "string"}, "MaxAge": {"type": "string"},
            "MinSize": {"type": "string"}, "MaxSize": {"type": "string"}, "IncludePatterns": {"type": "string"},
            "ExcludePatterns": {"type": "string"}, "ExtraArgs": {"type": "string"}, "ScheduleEnable": {"type": "boolean"},
            "ScheduleCron": {"type": "string"}, "ScheduleInterval": {"type": "integer"}, "BisyncResync": {"type": "boolean"},
            "BisyncCheckAccess": {"type": "boolean"}, "BisyncForce": {"type": "boolean"},
        },
    }
    storage_item_request = {
        "type": "object",
        "properties": {
            "Type": {"type": "string"}, "Enable": {"type": "boolean"}, "Key": {"type": "string"},
            "Remark": {"type": "string"}, "Writable": {"type": "boolean"}, "Log": {"type": "boolean"},
            "Params": {"type": "object", "additionalProperties": {}}, "SystemMount": {"type": "object"},
        },
    }
    third_party_user_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Type": {"type": "string"}, "Enable": {"type": "boolean"},
            "Remark": {"type": "string"}, "ID": {"type": "string"}, "Name": {"type": "string"},
            "Avatar": {"type": "string"}, "EMail": {"type": "string"}, "Phone": {"type": "string"},
            "RefreshToken": {"type": "string"}, "AccessToken": {"type": "string"},
            "CreateTime": {"type": "integer"}, "UpdateTime": {"type": "integer"}, "TwoFAKey": {"type": "string"},
        },
    }
    rclone_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/rclone/sync/list"), ("PUT", "/api/rclone/sync/list")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != rclone_sync_request:
            fail(f"Rclone disposable sync request schema regressed for {route_key}")
        if set(route.body_keys) != set(rclone_sync_request["properties"]):
            fail(f"Rclone sync request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"Rclone sync request schema must not invent required fields for {route_key}")
        if route.response_schema != rclone_ret_only:
            fail(f"Rclone disposable sync ret-only response schema regressed for {route_key}")

    for route_key in {
        ("DELETE", "/api/rclone/remotelist"),
        ("DELETE", "/api/rclone/sync/list"),
    }:
        if merged_by_key[route_key].response_schema != rclone_ret_only:
            fail(f"Rclone disposable cleanup response schema regressed for {route_key}")

    for route_key in {
        ("GET", "/api/rclone/remotelist/option"),
        ("GET", "/api/rclone/sync/option"),
    }:
        route = merged_by_key[route_key]
        if route.risk is not OperationRisk.MUTATING:
            fail(f"Rclone enable/disable GET must remain mutating for {route_key}")
        if route.response_schema != rclone_ret_only:
            fail(f"Rclone enable/disable GET response schema regressed for {route_key}")

    rclone_run = merged_by_key[("POST", "/api/rclone/sync/run/{param}")]
    if rclone_run.response_schema != rclone_ret_only:
        fail("Rclone runtime run response schema regressed")
    if "resync" not in rclone_run.query_keys:
        fail("Rclone runtime run must retain the resync query parameter")
    rclone_stop = merged_by_key[("POST", "/api/rclone/sync/stop/{param}")]
    if rclone_stop.response_schema != rclone_ret_only:
        fail("Rclone runtime stop response schema regressed")
    if rclone_stop.risk is not OperationRisk.DANGEROUS:
        fail("Rclone runtime stop must remain dangerous")
    if merged_by_key[("PUT", "/api/rclone/globalconfig")].response_schema != rclone_ret_only:
        fail("Rclone global-config runtime response schema regressed")

    rclone_remote_detail = merged_by_key[("GET", "/api/rclone/remote/{param}")].response_schema
    rclone_remote_props = (
        rclone_remote_detail.get("properties", {}).get("remote", {}).get("properties", {})
        if isinstance(rclone_remote_detail, dict)
        else {}
    )
    for field, expected in {
        "Key": {"type": "string"},
        "Type": {"type": "string"},
        "Enable": {"type": "boolean"},
        "Remark": {"type": "string"},
        "HttpClienInsecureSkipVerify": {"type": "boolean"},
        "HttpClientProxyType": {"type": "string"},
    }.items():
        if rclone_remote_props.get(field) != expected:
            fail(f"Rclone safe remote detail field regressed: {field}")

    rclone_sync_detail = merged_by_key[("GET", "/api/rclone/sync/{param}")].response_schema
    rclone_sync_props = (
        rclone_sync_detail.get("properties", {}).get("task", {}).get("properties", {})
        if isinstance(rclone_sync_detail, dict)
        else {}
    )
    for field, expected in {
        "Key": {"type": "string"},
        "Enable": {"type": "boolean"},
        "Remark": {"type": "string"},
        "SourceType": {"type": "string"},
        "DestType": {"type": "string"},
        "SyncMode": {"type": "string"},
        "DryRun": {"type": "boolean"},
        "ScheduleEnable": {"type": "boolean"},
    }.items():
        if rclone_sync_props.get(field) != expected:
            fail(f"Rclone safe sync detail field regressed: {field}")

    storage_runtime_models = {
        ("POST", "/api/storagemanagement/list"): storage_item_request,
        ("PUT", "/api/storagemanagement/list"): storage_item_request,
    }
    storage_success_response = {
        "type": "object",
        "properties": {"ret": {"type": "integer"}},
    }
    for route_key, expected in storage_runtime_models.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != expected:
            fail(f"StorageManagement resource request schema regressed for {route_key}")
        if set(route.body_keys) != set(expected["properties"]):
            fail(f"StorageManagement request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"StorageManagement request schema must not invent required fields for {route_key}")
        if route.response_schema != storage_success_response:
            fail(f"StorageManagement runtime success response regressed for {route_key}")
    for route_key in {
        ("GET", "/api/storagemanagement/enable"),
        ("DELETE", "/api/storagemanagement/list"),
    }:
        if merged_by_key[route_key].response_schema != storage_success_response:
            fail(f"StorageManagement runtime mutation response regressed for {route_key}")

    cron_item_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Name": {"type": "string"}, "Enable": {"type": "boolean"},
            "OtherKey": {"type": "string"}, "Type": {"type": "integer"}, "TypeParams": {"type": "string"},
            "GroupKey": {"type": "string"}, "ExecSecond": {"type": "integer"},
            "ExecMinute": {"type": "integer"}, "ExecHour": {"type": "integer"},
            "Jobs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "Type": {"type": "string"},
                        "Options": {"type": "object", "additionalProperties": {}},
                        "Remark": {"type": "string"},
                    },
                },
            },
            "Parallel": {"type": "boolean"},
            "IOT_DianDeng_Enable": {"type": "boolean"}, "IOT_DianDeng_AUTHKEY": {"type": "string"},
            "IOT_DianDeng_InsecureSkipVerify": {"type": "boolean"},
            "IOT_DianDengVoiceAssistantTriggerCondition": {"type": "string"},
            "IOT_DianDengBindComponentEnable": {"type": "boolean"},
            "IOT_DianDengBindComponentTriggerCondition": {"type": "string"},
            "IOT_DianDengBindComponent": {"type": "string"},
            "IOT_DianDengBindComponentState": {"type": "string"},
            "IOT_DianDengBindComponentType": {"type": "string"},
            "IOT_Bemfa_Enable": {"type": "boolean"}, "IOT_Bemfa_SecretKey": {"type": "string"},
            "IOT_Bemfa_Topic": {"type": "string"},
            "IOT_BemfaVoiceAssistantTriggerCondition": {"type": "string"},
            "IOT_Bemfa_InsecureSkipVerify": {"type": "boolean"},
        },
    }
    for route_key in {
        ("POST", "/api/cron/list"),
        ("PUT", "/api/cron/list"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != cron_item_request:
            fail(f"Cron runtime task request schema regressed for {route_key}")
        if set(route.body_keys) != set(cron_item_request["properties"]):
            fail(f"Cron task request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"Cron task request schema must not invent required fields for {route_key}")
        if route.response_schema != {"type": "object", "properties": {"ret": {"type": "integer"}}}:
            fail(f"Cron disposable-task ret-only response schema regressed for {route_key}")
    cron_trigger = merged_by_key[("POST", "/api/cron/jobs/trigger")]
    if cron_trigger.request_body_schema != {
        "type": "object", "properties": {"cronKey": {"type": "string"}, "jobIndex": {"type": "integer"}}
    }:
        fail("Cron runtime trigger request schema regressed")
    if isinstance(cron_trigger.request_body_schema, dict) and "required" in cron_trigger.request_body_schema:
        fail("Cron trigger request schema must not invent required fields")
    cron_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    if cron_trigger.response_schema != cron_ret_only:
        fail("Cron runtime job-trigger response schema regressed")
    cron_dojobs = merged_by_key[("GET", "/api/cron/dojobs")]
    if cron_dojobs.risk is not OperationRisk.MUTATING:
        fail("Cron dojobs GET must remain mutating")
    if cron_dojobs.response_schema != cron_ret_only:
        fail("Cron runtime dojobs response schema regressed")

    parser_only_small_requests = {
        ("POST", "/api/webservice/webauth/sessions/clear-subrule"): {
            "type": "object", "properties": {"ruleKey": {"type": "string"}, "subRuleKey": {"type": "string"}}
        },
        ("POST", "/api/webservice/webauth/sessions/delete"): {
            "type": "object", "properties": {"sessionIds": {"type": "array", "items": {"type": "string"}}}
        },
        ("PUT", "/api/webservice/{param}/subrulegrouporderupdate"): {
            "type": "object",
            "properties": {
                "subRulesMap": {"type": "object", "additionalProperties": {"type": "string"}},
                "orderList": {"type": "array", "items": {"type": "string"}},
                "defaultProxyGroupKey": {"type": "string"},
            },
        },
        ("POST", "/api/webservice/{param}/{param2}/updatefolder/confirm"): {
            "type": "object", "properties": {"tempId": {"type": "string"}}
        },
        ("POST", "/api/security-groups/grants/delete"): {
            "type": "object", "properties": {"grantKeys": {"type": "array", "items": {"type": "string"}}}
        },
    }
    for route_key, expected in parser_only_small_requests.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != expected:
            fail(f"parser-only small request schema regressed for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"parser-only small request schema must not invent required fields for {route_key}")
        if route.response_schema is not None:
            fail(f"parser-only small request must not claim a success response for {route_key}")

    docker_parser_requests = {
        ("PUT", "/api/docker/container-groups/collapsed"): {
            "type": "object", "properties": {"collapsed": {"type": "boolean"}, "key": {"type": "string"}}
        },
        ("PUT", "/api/docker/containers/group"): {
            "type": "object", "properties": {"containerName": {"type": "string"}, "groupKey": {"type": "string"}}
        },
        ("PUT", "/api/docker/containers/sort/flat"): {
            "type": "object", "properties": {"orderList": {"type": "array", "items": {"type": "string"}}}
        },
        ("PUT", "/api/docker/containers/sort/compose"): {
            "type": "object",
            "properties": {
                "containerOrders": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
                "groupOrder": {"type": "array", "items": {"type": "string"}},
            },
        },
        ("PUT", "/api/docker/containers/sort/custom"): {
            "type": "object",
            "properties": {
                "containerGroupMap": {"type": "object", "additionalProperties": {"type": "string"}},
                "containerOrders": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
                "groupOrder": {"type": "array", "items": {"type": "string"}},
            },
        },
        ("POST", "/api/docker/containers/switch-version"): {
            "type": "object", "properties": {"container_ids": {"type": "array", "items": {"type": "string"}}, "target_image_ref": {"type": "string"}}
        },
    }
    for route_key, expected in docker_parser_requests.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != expected:
            fail(f"Docker parser-only request schema regressed for {route_key}")
        if set(route.body_keys) != set(expected["properties"]):
            fail(f"Docker parser-only request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"Docker parser-only request schema must not invent required fields for {route_key}")
        if route.response_schema is not None:
            fail(f"Docker parser-only request must not claim a success response for {route_key}")

    docker_compose_up_request = {
        "type": "object",
        "properties": {
            "project_name": {"type": "string"}, "project_path": {"type": "string"}, "config_file_name": {"type": "string"},
            "working_dir": {"type": "string"}, "compose_content": {"type": "string"},
            "force_recreate": {"type": "boolean"}, "build": {"type": "boolean"},
        },
    }
    compose_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    compose_task_response = {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "task_id": {"type": "string"}},
    }
    compose_up_responses = {
        ("POST", "/api/docker/compose/up"): compose_ret_only,
        ("POST", "/api/docker/compose/up-async"): compose_task_response,
    }
    for route_key, expected_response in compose_up_responses.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != docker_compose_up_request:
            fail(f"Docker Compose-up request schema regressed for {route_key}")
        if set(route.body_keys) != set(docker_compose_up_request["properties"]):
            fail(f"Docker Compose-up request schema must cover exactly the frontend body fields for {route_key}")
        if route.request_body_schema["properties"]["config_file_name"] != {"type": "string"}:
            fail("Docker Compose-up config_file_name client contract must remain string")
        if route.response_schema != expected_response:
            fail(f"Docker Compose-up runtime response schema regressed for {route_key}")

    docker_backup_restore = {"type": "object", "properties": {"backup": {"type": "string"}}}
    for route_key in {("POST", "/api/docker/compose/{param}/backups/restore"), ("POST", "/api/docker/volumes/{param}/backups/restore")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != docker_backup_restore:
            fail(f"Docker backup-restore request schema regressed for {route_key}")
        if route.response_schema is not None:
            fail(f"Docker backup-restore missing-backup evidence must not claim a success response for {route_key}")
    for route_key in {("DELETE", "/api/docker/compose/{param}/backups"), ("DELETE", "/api/docker/volumes/{param}/backups")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != docker_backup_restore:
            fail(f"Docker backup-delete request schema regressed for {route_key}")

    docker_compose_logs = merged_by_key[("POST", "/api/docker/compose/{param}/logs")]
    expected_compose_logs_request = {
        "type": "object",
        "properties": {
            "project_name": {"type": "string"}, "project_path": {"type": "string"},
            "services": {"type": "array", "items": {"type": "string"}}, "tail": {"type": "string"},
            "timestamps": {"type": "boolean"}, "follow": {"type": "boolean"},
        },
    }
    expected_compose_logs_response = {
        "type": "object", "properties": {"ret": {"type": "integer"}, "logs": {"type": "array", "items": {"type": "string"}}}
    }
    if docker_compose_logs.request_body_schema != expected_compose_logs_request:
        fail("Docker Compose logs request schema regressed")
    if docker_compose_logs.response_schema != expected_compose_logs_response:
        fail("Docker Compose logs response schema regressed")
    if docker_compose_logs.confidence != "runtime-verified":
        fail("Docker Compose logs must remain runtime-verified")

    docker_upgrade_request = {
        "type": "object",
        "properties": {
            "container_ids": {"type": "array", "items": {"type": "string"}}, "image_ref": {"type": "string"},
            "upgrade_compose": {"type": "boolean"}, "upgrade_standalone": {"type": "boolean"},
        },
    }
    for route_key in {("POST", "/api/docker/images/upgrade-containers"), ("POST", "/api/docker/images/upgrade-containers-async")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != docker_upgrade_request:
            fail(f"Docker upgrade request schema regressed for {route_key}")
        if route.response_schema is not None:
            fail(f"Docker fake-image upgrade evidence must not claim a success response for {route_key}")

    docker_mirror_request = {"type": "object", "properties": {"mirror": {"type": "string"}}}
    docker_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/docker/registry/mirrors"), ("DELETE", "/api/docker/registry/mirrors")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != docker_mirror_request or route.response_schema != docker_ret_only:
            fail(f"Docker disposable registry-mirror schema regressed for {route_key}")
    expected_mirror_list = {
        "type": "object", "properties": {"ret": {"type": "integer"}, "mirrors": {"type": ["array", "null"], "items": {"type": "string"}}}
    }
    if merged_by_key[("GET", "/api/docker/registry/mirrors")].response_schema != expected_mirror_list:
        fail("Docker registry-mirror list schema regressed")

    webservice_cgi_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Name": {"type": "string"}, "Enable": {"type": "boolean"},
            "CGIType": {"type": "string"}, "Network": {"type": "string"}, "Address": {"type": "string"},
            "MaxConns": {"type": "integer"}, "ConnectTimeout": {"type": "integer"},
            "ForbiddenPaths": {"type": "string"}, "DefaultDocRoot": {"type": "string"},
            "DefaultIndexNames": {"type": "string"}, "FileExtensions": {"type": "string"},
        },
    }
    webservice_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/webservice/cgi"), ("PUT", "/api/webservice/cgi/{param}")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != webservice_cgi_request:
            fail(f"WebService disposable CGI request schema regressed for {route_key}")
        if set(route.body_keys) != set(webservice_cgi_request["properties"]):
            fail(f"WebService CGI request schema must cover exactly the frontend body fields for {route_key}")
        if route.response_schema != webservice_ret_only:
            fail(f"WebService disposable CGI ret-only response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/webservice/cgi/{param}")].response_schema != webservice_ret_only:
        fail("WebService disposable CGI delete response schema regressed")

    cgi_list_schema = merged_by_key[("GET", "/api/webservice/cgi/list")].response_schema
    cgi_item_props = (
        cgi_list_schema.get("properties", {}).get("list", {}).get("items", {}).get("properties", {})
        if isinstance(cgi_list_schema, dict)
        else {}
    )
    expected_cgi_item_props = {
        "Key": {"type": "string"}, "Name": {"type": "string"}, "Enable": {"type": "boolean"},
        "Remark": {"type": "string"}, "CGIType": {"type": "string"}, "Network": {"type": "string"},
        "Address": {"type": "string"}, "MaxConns": {"type": "integer"}, "ConnectTimeout": {"type": "integer"},
        "ReadTimeout": {"type": "integer"}, "WriteTimeout": {"type": "integer"},
        "ForbiddenPaths": {"type": "string"}, "DefaultDocRoot": {"type": "string"},
        "DefaultIndexNames": {"type": "string"}, "FileExtensions": {"type": "string"},
        "ActiveConns": {"type": "integer"}, "LastError": {"type": "string"},
    }
    if cgi_item_props != expected_cgi_item_props:
        fail("WebService disposable CGI list item schema regressed")

    discovery_cancel = merged_by_key[("POST", "/api/webservice/discovery/cancel")]
    if discovery_cancel.request_body_schema != {"type": "object", "properties": {"jobId": {"type": "string"}}}:
        fail("WebService discovery-cancel request schema regressed")
    if discovery_cancel.response_schema is not None:
        fail("WebService nonexistent-job cancel evidence must not claim a success response")

    discovery_request = {
        "type": "object",
        "properties": {
            "ruleKey": {"type": "string"},
            "targets": {"type": "string"},
            "ports": {"type": "string"},
            "excludePorts": {"type": "string"},
            "domainSuffix": {"type": "string"},
            "timeoutMs": {"type": "integer"},
            "maxScanDurationMs": {"type": "integer"},
            "maxHostRetriesPerEndpoint": {"type": "integer"},
            "allowedRedirectHosts": {"type": "array", "items": {"type": "string"}},
            "maxHosts": {"type": "integer"},
            "maxPortTargets": {"type": "integer"},
            "tcpConcurrency": {"type": "integer"},
            "probeConcurrency": {"type": "integer"},
            "tcpCompatibilityMode": {"type": "boolean"},
            "maxRedirects": {"type": "integer"},
        },
    }
    discovery_summary = {
        "type": "object",
        "properties": {
            "parsedHosts": {"type": "integer"},
            "parsedPorts": {"type": "integer"},
            "checkedPortPairs": {"type": "integer"},
            "openPorts": {"type": "integer"},
            "probeAttempts": {"type": "integer"},
            "discovered": {"type": "integer"},
            "mergedResults": {"type": "integer"},
            "alreadyAddedCount": {"type": "integer"},
        },
    }
    discovery_response = {
        "type": "object",
        "properties": {
            "active": {"type": "boolean"},
            "elapsedMs": {"type": "integer"},
            "error": {"type": "string"},
            "jobId": {"type": "string"},
            "results": {"type": ["array", "null"], "items": {}},
            "ret": {"type": "integer"},
            "reused": {"type": "boolean"},
            "ruleKey": {"type": "string"},
            "runtimePlatform": {"type": "string"},
            "startedAt": {"type": "integer"},
            "status": {"type": "string"},
            "summary": discovery_summary,
            "tcpCompatibilityModeSupported": {"type": "boolean"},
        },
    }
    discovery_start = merged_by_key[("POST", "/api/webservice/discovery/start")]
    if discovery_start.request_body_schema != discovery_request:
        fail("WebService discovery-start request schema regressed")
    if set(discovery_start.body_keys) != set(discovery_request["properties"]):
        fail("WebService discovery-start request schema must cover exactly the frontend body fields")
    if discovery_start.risk is not OperationRisk.DANGEROUS:
        fail("WebService discovery-start must remain dangerous")
    if discovery_start.response_schema != discovery_response:
        fail("WebService discovery-start success response schema regressed")
    discovery_status = merged_by_key[("GET", "/api/webservice/discovery/status/{param}")]
    if discovery_status.risk is not OperationRisk.READ_ONLY:
        fail("WebService discovery-status GET must remain read-only")
    if discovery_status.response_schema != discovery_response:
        fail("WebService discovery-status success response schema regressed")

    cloudflared_instance_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Remark": {"type": "string"}, "Enable": {"type": "boolean"},
            "Type": {"type": "string"}, "Params": {"type": "object"},
        },
    }
    cloudflared_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/cloudflared/list"), ("PUT", "/api/cloudflared/list")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != cloudflared_instance_request:
            fail(f"Cloudflared semantic-sentinel request schema regressed for {route_key}")
        if set(route.body_keys) != set(cloudflared_instance_request["properties"]):
            fail(f"Cloudflared instance request schema must cover exactly the frontend body fields for {route_key}")
        if route.response_schema != cloudflared_ret_only:
            fail(f"Cloudflared disposable access instance ret-only response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/cloudflared/list/{param}")].response_schema != cloudflared_ret_only:
        fail("Cloudflared disposable access instance delete response schema regressed")

    cloudflared_toggle = merged_by_key[("GET", "/api/cloudflared/list/{param}/{param2}")]
    if cloudflared_toggle.risk is not OperationRisk.MUTATING:
        fail("Cloudflared enable/disable GET must remain classified as mutating")
    if cloudflared_toggle.response_schema != cloudflared_ret_only:
        fail("Cloudflared enable/disable GET ret-only response schema regressed")

    expected_cloudflared_list = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "list": {
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {
                        "Key": {"type": "string"},
                        "Remark": {"type": "string"},
                        "Type": {"type": "string"},
                        "Enable": {"type": "boolean"},
                        "RunErrorMsg": {"type": "string"},
                        "Running": {"type": "boolean"},
                        "Connected": {"type": "boolean"},
                        "Reconnecting": {"type": "boolean"},
                        "LocalURL": {"type": "string"},
                        "AccessTarget": {"type": "string"},
                    },
                },
            },
        },
    }
    if merged_by_key[("GET", "/api/cloudflared/list")].response_schema != expected_cloudflared_list:
        fail("Cloudflared disposable access list summary schema regressed")

    expected_cloudflared_detail = {
        "type": "object",
        "properties": {
            "instance": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Enable": {"type": "boolean"},
                    "Remark": {"type": "string"},
                    "Type": {"type": "string"},
                    "Params": {
                        "type": "object",
                        "properties": {
                            "Hostname": {"type": "string"},
                            "Network": {"type": "string"},
                            "ListenIP": {"type": "string"},
                            "ListenPort": {"type": "integer"},
                            "NoTlsVerify": {"type": "boolean"},
                            "Destination": {"type": "string"},
                            "ConnectTo": {"type": "string"},
                            "UserAgent": {"type": "string"},
                        },
                    },
                },
            },
            "ret": {"type": "integer"},
        },
    }
    if merged_by_key[("GET", "/api/cloudflared/list/{param}")].response_schema != expected_cloudflared_detail:
        fail("Cloudflared disposable access detail response schema regressed")

    shared_module_log_item = {
        "type": "object",
        "properties": {
            "LogContent": {"type": "string"},
            "LogTime": {"type": "string"},
            "ShowTime": {"type": "boolean"},
            "Level": {"type": "string"},
        },
    }
    cloudflared_nullable_logs = {
        "type": ["array", "null"],
        "items": shared_module_log_item,
    }
    expected_cloudflared_reads = {
        ("GET", "/api/cloudflared/{param}/lastlogs"): {
            "type": "object", "properties": {"lastLogs": cloudflared_nullable_logs, "ret": {"type": "integer"}}
        },
        ("GET", "/api/cloudflared/{param}/logs"): {
            "type": "object",
            "properties": {
                "logs": cloudflared_nullable_logs,
                "page": {"type": "integer"},
                "pageSize": {"type": "integer"},
                "ret": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
    }
    for route_key, expected_schema in expected_cloudflared_reads.items():
        if merged_by_key[route_key].response_schema != expected_schema:
            fail(f"Cloudflared disposable access read response schema regressed for {route_key}")

    cloudflared_ingress_rule = {
        "type": "object",
        "properties": {
            "hostname": {"type": "string"}, "path": {"type": "string"},
            "service": {"type": "string"}, "originRequest": {"type": "object"},
        },
    }
    cloudflared_ingress_post = merged_by_key[("POST", "/api/cloudflared/{param}/ingress")]
    if cloudflared_ingress_post.request_body_schema != cloudflared_ingress_rule:
        fail("Cloudflared ingress POST request schema regressed")
    if cloudflared_ingress_post.response_schema is not None:
        fail("Cloudflared missing-instance ingress POST must not claim a success response")

    cloudflared_ingress_put = merged_by_key[("PUT", "/api/cloudflared/{param}/ingress")]
    expected_cloudflared_ingress_put = {
        "type": "object",
        "properties": {
            "oldHostname": {"type": "string"}, "oldPath": {"type": "string"},
            "newRule": cloudflared_ingress_rule,
        },
    }
    if cloudflared_ingress_put.request_body_schema != expected_cloudflared_ingress_put:
        fail("Cloudflared ingress PUT request schema regressed")
    if cloudflared_ingress_put.response_schema is not None:
        fail("Cloudflared missing-instance ingress PUT must not claim a success response")

    global_2fa_request = {
        "type": "object",
        "properties": {
            "TwoFAEnable": {"type": "boolean"},
            "TwoFAKey": {"type": "string"},
            "TwoFACode": {"type": "string"},
        },
    }
    global_2fa = merged_by_key[("PUT", "/api/2fa/setting")]
    if global_2fa.request_body_schema != global_2fa_request:
        fail("global 2FA cross-evidence request schema regressed")
    if set(global_2fa.body_keys) != set(global_2fa_request["properties"]):
        fail("global 2FA request schema must cover exactly the frontend body fields")
    if global_2fa.response_schema is not None:
        fail("global 2FA cross-evidence must not claim a success response")

    module_2fa_request = {
        "type": "object",
        "properties": {
            "enable": {"type": "boolean"},
            "key": {"type": "string"},
            "secret": {"type": "string"},
            "validated": {"type": "boolean"},
            "code": {"type": "string"},
            "oldSecret": {"type": "string"},
            "oldCode": {"type": "string"},
        },
    }
    module_2fa = merged_by_key[("PUT", "/api/modules/{param}/2fa/config")]
    if module_2fa.request_body_schema != module_2fa_request:
        fail("module 2FA cross-evidence request schema regressed")
    if set(module_2fa.body_keys) != set(module_2fa_request["properties"]):
        fail("module 2FA request schema must cover exactly the frontend body fields")
    if module_2fa.response_schema is not None:
        fail("module 2FA cross-evidence must not claim a success response")

    module_verify = merged_by_key[("POST", "/api/modules/{param}/verify2fa")]
    if module_verify.request_body_schema != {"type": "object", "properties": {"code": {"type": "string"}}}:
        fail("module verify2fa request schema regressed")
    if module_verify.response_schema is not None:
        fail("module verify2fa request-only evidence must not claim a success response")

    expected_module_2fa_config_response = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "config": {"type": "object", "properties": {
                "enable": {"type": "boolean"},
                "hasKey": {"type": "boolean"},
                "validated": {"type": "boolean"},
            }},
        },
    }
    if merged_by_key[("GET", "/api/modules/{param}/2fa/config")].response_schema != expected_module_2fa_config_response:
        fail("module 2FA safe config response schema regressed")

    stun_rule_request = {
        "type": "object",
        "properties": {
            "Name": {"type": "string"}, "Key": {"type": "string"}, "Enable": {"type": "boolean"},
            "UseGlobalStunServerList": {"type": "boolean"}, "DiaglogShowMode": {"type": "string"},
            "StunHeartbeatInterval": {"type": "integer"}, "StunTimeout": {"type": "integer"},
            "StunRetryInterval": {"type": "integer"}, "StunAutoRetry": {"type": "boolean"},
            "AutoAddPubAddrWhiteList": {"type": "boolean"}, "StunType": {"type": "string"},
            "StunListenType": {"type": "string"}, "SpecifyNetworkInterface": {"type": "string"},
            "NetworkInterfaceReg": {"type": "string"}, "ListenIP": {"type": "string"},
            "AutoOptionsFirewall": {"type": "boolean"}, "ListenPort": {"type": "integer"},
            "NatPMP": {"type": "boolean"}, "UPnPGawayIP": {"type": "string"},
            "NatPMPGateway": {"type": "string"}, "UPnP": {"type": "boolean"},
            "UPnPLocalPort": {"type": "integer"}, "UPnpLocalHost": {"type": "string"},
            "UPnPInternalClientIP": {"type": "string"}, "UpnPDiyControlAPIUrl": {"type": "string"},
            "DisableStunAvalidCheck": {"type": "boolean"}, "DisablePortForward": {"type": "boolean"},
            "TargetAddressList": {"type": "array", "items": {"type": "string"}}, "TargetPort": {"type": "integer"},
            "LogLevel": {"type": "integer"}, "LogOutputToConsole": {"type": "boolean"},
            "AccessLogMaxNum": {"type": "integer"}, "WebListShowLastLogMaxCount": {"type": "integer"},
            "Options": {"type": "object"}, "StunServerList": {"type": "array", "items": {"type": "string"}},
            "TcpKeepAliveServerList": {"type": "array", "items": {"type": "string"}}, "GlobalWebhook": {"type": "boolean"},
            "WebhookEnable": {"type": "boolean"}, "WebhookOnlyAddrChange": {"type": "boolean"},
            "WebhookURL": {"type": "string"}, "WebhookMethod": {"type": "string"},
            "WebhookHeaders": {"type": "array", "items": {"type": "string"}}, "WebhookRequestBody": {"type": "string"},
            "WebhookDisableCallbackSuccessContentCheck": {"type": "boolean"},
            "WebhookSuccessContent": {"type": "array", "items": {"type": "string"}},
            "WebhookProxy": {"type": "string"}, "WebhookProxyAddr": {"type": "string"},
            "WebhookProxyUser": {"type": "string"}, "WebhookProxyPassword": {"type": "string"},
            "CallScript": {"type": "boolean"}, "CallScriptContent": {"type": "string"},
            "RetryCount": {"type": "integer"}, "RetryInterval": {"type": "integer"},
            "LogStreamSettings": {"type": "object"},
        },
    }
    stun_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    stun_create_response = {
        "type": "object",
        "properties": {"key": {"type": "string"}, "ret": {"type": "integer"}},
    }
    for route_key, expected_response in {
        ("POST", "/api/stunrule"): stun_create_response,
        ("PUT", "/api/stunrule"): stun_ret_only,
    }.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != stun_rule_request:
            fail(f"STUN parser-verified request schema regressed for {route_key}")
        if set(route.body_keys) != set(stun_rule_request["properties"]):
            fail(f"STUN request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"STUN request schema must not invent required fields for {route_key}")
        if route.response_schema != expected_response:
            fail(f"STUN disposable rule success response schema regressed for {route_key}")

    if merged_by_key[("DELETE", "/api/stunrule")].response_schema != stun_ret_only:
        fail("STUN disposable rule delete response schema regressed")
    stun_toggle = merged_by_key[("GET", "/api/stunrule/enable")]
    if stun_toggle.risk is not OperationRisk.MUTATING:
        fail("STUN enable/disable GET must remain mutating")
    if stun_toggle.response_schema != stun_ret_only:
        fail("STUN enable/disable GET ret-only response schema regressed")

    stun_safe_rule_props = {
        "Name": {"type": "string"},
        "Key": {"type": "string"},
        "Enable": {"type": "boolean"},
        "DiaglogShowMode": {"type": "string"},
        "StunType": {"type": "string"},
        "UseGlobalStunServerList": {"type": "boolean"},
        "StunServerList": {"type": "array", "items": {"type": "string"}},
        "TcpKeepAliveServerList": {"type": "array", "items": {"type": "string"}},
        "StunListenType": {"type": "string"},
        "SpecifyNetworkInterface": {"type": "string"},
        "NetworkInterfaceReg": {"type": "string"},
        "ListenIP": {"type": "string"},
        "ListenPort": {"type": "integer"},
        "AutoOptionsFirewall": {"type": "boolean"},
        "DisableStunAvalidCheck": {"type": "boolean"},
        "DisablePortForward": {"type": "boolean"},
        "TargetAddressList": {"type": "array", "items": {"type": "string"}},
        "TargetPort": {"type": "integer"},
        "NatPMP": {"type": "boolean"},
        "UPnP": {"type": "boolean"},
        "UPnPGawayIP": {"type": "string"},
        "UPnPLocalPort": {"type": "integer"},
        "UPnpLocalHost": {"type": "string"},
        "UPnPInternalClientIP": {"type": "string"},
        "NatPMPGateway": {"type": "string"},
        "StunHeartbeatInterval": {"type": "integer"},
        "StunTimeout": {"type": "integer"},
        "StunRetryInterval": {"type": "integer"},
        "StunAutoRetry": {"type": "boolean"},
        "GlobalWebhook": {"type": "boolean"},
        "WebhookEnable": {"type": "boolean"},
        "WebhookOnlyAddrChange": {"type": "boolean"},
        "AutoAddPubAddrWhiteList": {"type": "boolean"},
        "LogLevel": {"type": "integer"},
        "LogOutputToConsole": {"type": "boolean"},
        "AccessLogMaxNum": {"type": "integer"},
        "WebListShowLastLogMaxCount": {"type": "integer"},
        "CallScript": {"type": "boolean"},
    }
    expected_stun_detail = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "rule": {"type": "object", "properties": stun_safe_rule_props},
        },
    }
    if merged_by_key[("GET", "/api/stun/{param}")].response_schema != expected_stun_detail:
        fail("STUN disposable rule safe detail response schema regressed")

    stun_nullable_logs = {
        "type": ["array", "null"],
        "items": shared_module_log_item,
    }
    if merged_by_key[("GET", "/api/stun/{param}/lastlogs")].response_schema != {
        "type": "object",
        "properties": {"lastLogs": stun_nullable_logs, "ret": {"type": "integer"}},
    }:
        fail("STUN disposable rule lastlogs response schema regressed")
    if merged_by_key[("GET", "/api/stun/{param}/logs")].response_schema != {
        "type": "object",
        "properties": {
            "logs": stun_nullable_logs,
            "page": {"type": "integer"},
            "pageSize": {"type": "integer"},
            "ret": {"type": "integer"},
            "total": {"type": "integer"},
        },
    }:
        fail("STUN disposable rule paginated logs response schema regressed")

    expected_stun_list = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "ModuleEnable": {"type": "boolean"},
            "list": {
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {
                        "Key": {"type": "string"},
                        "Name": {"type": "string"},
                        "StunType": {"type": "string"},
                        "Enable": {"type": "boolean"},
                        "DisablePortForward": {"type": "boolean"},
                        "WebhookEnable": {"type": "boolean"},
                        "GlobalWebhook": {"type": "boolean"},
                    },
                },
            },
            "statistics": {"type": "object"},
        },
    }
    if merged_by_key[("GET", "/api/stunrulelist")].response_schema != expected_stun_list:
        fail("STUN disposable rule list safe summary schema regressed")
    expected_stun_lite = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "ModuleEnable": {"type": "boolean"},
            "list": {
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {"Name": {"type": "string"}, "Key": {"type": "string"}},
                },
            },
        },
    }
    if merged_by_key[("GET", "/api/stunrulelist_lite")].response_schema != expected_stun_lite:
        fail("STUN disposable rule lite-list schema regressed")

    stun_webhook_request = {
        "type": "object",
        "properties": {
            "WebhookURL": {"type": "string"}, "WebhookMethod": {"type": "string"},
            "WebhookRequestBody": {"type": "string"}, "WebhookProxy": {"type": "string"},
            "WebhookProxyAddr": {"type": "string"}, "WebhookProxyUser": {"type": "string"},
            "RetryCount": {"type": "integer"}, "RetryInterval": {"type": "integer"},
            "WebhookProxyPassword": {"type": "string"},
            "WebhookHeaders": {"type": "array", "items": {"type": "string"}},
            "WebhookSuccessContent": {"type": "array", "items": {"type": "string"}},
            "WebhookDisableCallbackSuccessContentCheck": {"type": "boolean"},
        },
    }
    stun_webhook_route = merged_by_key[("POST", "/api/stunrule/webhooktest")]
    if stun_webhook_route.request_body_schema != stun_webhook_request:
        fail("STUN webhook-test request schema regressed")
    if set(stun_webhook_route.body_keys) != set(stun_webhook_request["properties"]):
        fail("STUN webhook-test request schema must cover exactly the frontend body fields")
    if isinstance(stun_webhook_route.request_body_schema, dict) and "required" in stun_webhook_route.request_body_schema:
        fail("STUN webhook-test request schema must not invent required fields")
    if stun_webhook_route.response_schema is not None:
        fail("STUN webhook-test request-only evidence must not claim a success response")

    webterminal_connection_request = {
        "type": "object",
        "properties": {
            "key": {"type": "string"}, "name": {"type": "string"}, "type": {"type": "string"},
            "remark": {"type": "string"}, "localConfig": {"type": "object"}, "sshConfig": {"type": "object"},
            "telnetConfig": {"type": "object"}, "shortcuts": {"type": "array", "items": {"type": "object"}},
            "quickAccessDirs": {"type": "array", "items": {"type": "string"}},
        },
    }
    webterminal_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/webterminal/connections"), ("PUT", "/api/webterminal/connections"), ("POST", "/api/webterminal/connections/test")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != webterminal_connection_request:
            fail(f"WebTerminal connection request schema regressed for {route_key}")
        if set(route.body_keys) != set(webterminal_connection_request["properties"]):
            fail(f"WebTerminal connection request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"WebTerminal connection request schema must not invent required fields for {route_key}")
        if route_key[1] == "/api/webterminal/connections" and route.response_schema != webterminal_ret_only:
            fail(f"WebTerminal disposable CRUD ret-only response schema regressed for {route_key}")
        if route_key[1].endswith("/test") and route.response_schema is not None:
            fail("WebTerminal connection test was not executed and must not claim a success response")

    webterminal_quickaccess = merged_by_key[("PUT", "/api/webterminal/connections/{param}/quickaccess")]
    expected_quickaccess = {"type": "object", "properties": {"quickAccessDirs": {"type": "array", "items": {"type": "string"}}}}
    if webterminal_quickaccess.request_body_schema != expected_quickaccess or webterminal_quickaccess.response_schema != webterminal_ret_only:
        fail("WebTerminal quick-access schema regressed")

    webterminal_ssh_host_key = merged_by_key[("PUT", "/api/webterminal/connections/{param}/ssh-host-key")]
    expected_ssh_host_key = {
        "type": "object",
        "properties": {
            "host": {"type": "string"}, "port": {"type": "integer"}, "hostname": {"type": "string"},
            "hostKey": {"type": "string"}, "hostKeyFingerprint": {"type": "string"},
            "hostKeyTrustedAt": {"type": "string"}, "keyType": {"type": "string"},
            "previousHostKeyFingerprint": {"type": "string"}, "changed": {"type": "boolean"},
        },
    }
    if webterminal_ssh_host_key.request_body_schema != expected_ssh_host_key:
        fail("WebTerminal SSH host-key request schema regressed")
    if webterminal_ssh_host_key.response_schema is not None:
        fail("WebTerminal dummy-connection SSH host-key evidence must not claim a success response")

    expected_connection_list = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "list": {"type": ["array", "null"], "items": {"type": "object", "properties": {
                "key": {"type": "string"}, "name": {"type": "string"}, "type": {"type": "string"},
                "remark": {"type": "string"}, "target": {"type": "string"},
            }}},
        },
    }
    if merged_by_key[("GET", "/api/webterminal/connections")].response_schema != expected_connection_list:
        fail("WebTerminal safe connection-list response schema regressed")

    expected_connection_detail = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "connection": {"type": "object", "properties": {
                "key": {"type": "string"}, "name": {"type": "string"}, "type": {"type": "string"},
                "remark": {"type": "string"}, "localConfig": {"type": "object"}, "sshConfig": {"type": "object"},
                "telnetConfig": {"type": "object"}, "shortcuts": {"type": "array", "items": {"type": "object"}},
                "quickAccessDirs": {"type": "array", "items": {"type": "string"}},
            }},
        },
    }
    if merged_by_key[("GET", "/api/webterminal/connections/{param}")].response_schema != expected_connection_detail:
        fail("WebTerminal safe connection-detail response schema regressed")
    for nested_name in {"localConfig", "sshConfig", "telnetConfig"}:
        nested = expected_connection_detail["properties"]["connection"]["properties"][nested_name]
        if "properties" in nested:
            fail(f"WebTerminal {nested_name} response must stay opaque to avoid credential disclosure")
    if merged_by_key[("DELETE", "/api/webterminal/connections/{param}")].response_schema != webterminal_ret_only:
        fail("WebTerminal disposable connection delete response schema regressed")

    webterminal_missing_session_requests = {
        ("PUT", "/api/webterminal/sessions/{param}/remark"): {
            "type": "object", "properties": {"remark": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/chmod"): {
            "type": "object", "properties": {"path": {"type": "string"}, "permissions": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/compress"): {
            "type": "object", "properties": {
                "output_name": {"type": "string"}, "output_path": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}},
            }
        },
        ("POST", "/api/webterminal/sftp/{param}/copy"): {
            "type": "object", "properties": {"dst_path": {"type": "string"}, "src_path": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/decompress"): {
            "type": "object", "properties": {"file_path": {"type": "string"}, "output_path": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/mkdir"): {
            "type": "object", "properties": {"path": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/rename"): {
            "type": "object", "properties": {"newPath": {"type": "string"}, "oldPath": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/touch"): {
            "type": "object", "properties": {"path": {"type": "string"}}
        },
        ("POST", "/api/webterminal/sftp/{param}/write"): {
            "type": "object", "properties": {"content": {"type": "string"}, "path": {"type": "string"}}
        },
    }
    for route_key, expected in webterminal_missing_session_requests.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != expected:
            fail(f"WebTerminal zero-session request schema regressed for {route_key}")
        if set(route.body_keys) != set(expected["properties"]):
            fail(f"WebTerminal zero-session request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"WebTerminal zero-session request schema must not invent required fields for {route_key}")
        if route.response_schema is not None:
            fail(f"WebTerminal session-not-found evidence must not claim a success response for {route_key}")

    ipfilter_subrule_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"}, "Remark": {"type": "string"}, "Enable": {"type": "boolean"},
            "Type": {"type": "string"}, "LongTermValid": {"type": "boolean"}, "ValidTimestamp": {"type": "integer"},
            "IPTextSets": {"type": "string"}, "IPDBKeyWords": {"type": "string"},
            "AutoDeleteOnExpiry": {"type": "boolean"}, "InvalidIPTextEntryCount": {"type": "integer"},
            "InvalidIPTextEntriesPreview": {"type": "array", "items": {"type": "string"}},
            "IPInfoKeywordFilter": {"type": "object"},
        },
    }
    ipfilter_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {("POST", "/api/ipfliter/list/{param}"), ("PUT", "/api/ipfliter/list/{param}/{param2}")}:
        route = merged_by_key[route_key]
        if route.request_body_schema != ipfilter_subrule_request:
            fail(f"IPFilter parser-verified SubRule request schema regressed for {route_key}")
        if set(route.body_keys) != set(ipfilter_subrule_request["properties"]):
            fail(f"IPFilter SubRule request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"IPFilter SubRule request schema must not invent required fields for {route_key}")
        if route.response_schema != ipfilter_ret_only:
            fail(f"IPFilter disposable SubRule ret-only response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/ipfliter/list/{param}/{param2}")].response_schema != ipfilter_ret_only:
        fail("IPFilter disposable SubRule delete response schema regressed")

    ipfilter_keyword_filter = {
        "type": "object",
        "properties": {
            "Source": {"type": "string"},
            "IncludeMode": {"type": "string"},
            "IncludeKeywords": {"type": ["array", "null"], "items": {"type": "string"}},
            "ExcludeMode": {"type": "string"},
            "ExcludeKeywords": {"type": ["array", "null"], "items": {"type": "string"}},
            "CaseSensitive": {"type": "boolean"},
        },
    }
    ipfilter_subrule_props = {
        "Key": {"type": "string"},
        "Enable": {"type": "boolean"},
        "Remark": {"type": "string"},
        "Type": {"type": "string"},
        "LongTermValid": {"type": "boolean"},
        "ValidTimestamp": {"type": "integer"},
        "IPTextSets": {"type": "string"},
        "InvalidIPTextEntryCount": {"type": "integer"},
        "InvalidIPTextEntriesPreview": {"type": ["array", "null"], "items": {"type": "string"}},
        "IPDBKeyWords": {"type": "string"},
        "AutoDeleteOnExpiry": {"type": "boolean"},
        "IPInfoKeywordFilter": ipfilter_keyword_filter,
    }
    expected_ipfilter_detail = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "subRule": {"type": "object", "properties": ipfilter_subrule_props},
        },
    }
    if merged_by_key[("GET", "/api/ipfliter/list/{param}/{param2}")].response_schema != expected_ipfilter_detail:
        fail("IPFilter disposable SubRule detail response schema regressed")

    expected_ipfilter_subrule_list = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "subRuleList": {
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {**ipfilter_subrule_props, "IPTextSetsCount": {"type": "integer"}},
                },
            },
        },
    }
    if merged_by_key[("GET", "/api/ipfliter/list/subrulelist/{param}")].response_schema != expected_ipfilter_subrule_list:
        fail("IPFilter disposable SubRule list item schema regressed")

    ipfilter_toggle = merged_by_key[("GET", "/api/ipfliter/list/{param}/{param2}/{param3}")]
    if ipfilter_toggle.risk is not OperationRisk.MUTATING:
        fail("IPFilter SubRule enable/disable GET must remain classified as mutating")
    if ipfilter_toggle.response_schema != ipfilter_ret_only:
        fail("IPFilter SubRule enable/disable GET ret-only response schema regressed")

    ipfilter_match = merged_by_key[("POST", "/api/ipfliter/list/{param}/{param2}/match")]
    if ipfilter_match.request_body_schema != {"type": "object", "properties": {"ip": {"type": "string"}}}:
        fail("IPFilter subrule-match request schema regressed")
    if ipfilter_match.response_schema is not None:
        fail("IPFilter dummy-rule match evidence must not claim a success response")

    ipfilter_batch_delete = merged_by_key[("POST", "/api/ipfliter/porttrap/blockedips/batch-delete")]
    expected_ipfilter_batch_delete = {
        "type": "object", "properties": {"ips": {"type": "array", "items": {"type": "string"}}}
    }
    if ipfilter_batch_delete.request_body_schema != expected_ipfilter_batch_delete:
        fail("IPFilter blocked-IP batch-delete request schema regressed")
    if ipfilter_batch_delete.response_schema != {"type": "object", "properties": {"ret": {"type": "integer"}}}:
        fail("IPFilter blocked-IP empty-baseline ret-only response schema regressed")

    explicit_small_request_schemas = {
        ("PUT", "/api/frontend-preferences"): {
            "type": "object", "properties": {"theme": {"type": "string"}, "language": {"type": "string"}}
        },
        ("POST", "/api/cloudflared/{param}/cname/create"): {
            "type": "object", "properties": {"hostname": {"type": "string"}, "proxied": {"type": "boolean"}}
        },
        ("PUT", "/api/ipdb/configure"): {
            "type": "object", "properties": {"CustomIPDBPath": {"type": "string"}}
        },
        ("POST", "/api/login"): {
            "type": "object", "properties": {"challengeId": {"type": "string"}, "cipherText": {"type": "string"}}
        },
        ("POST", "/api/oauth/login"): {
            "type": "object", "properties": {"challengeId": {"type": "string"}, "cipherText": {"type": "string"}}
        },
        ("PUT", "/api/password/verify"): {
            "type": "object", "properties": {"oldPassword": {"type": "string"}}
        },
        ("POST", "/api/v2l"): {
            "type": "object", "properties": {"v2l": {"type": "string"}}
        },
        ("PUT", "/api/cron/taskgrouporderupdate"): {
            "type": "object",
            "properties": {
                "tasksMap": {"type": "object", "additionalProperties": {"type": "string"}},
                "orderList": {"type": "array", "items": {"type": "string"}},
            },
        },
        ("POST", "/api/webservice/statistics/geo/rebuild"): {
            "type": "object", "properties": {"mode": {"type": "string"}}
        },
        ("POST", "/api/webservice/statistics/ip-info-refresh"): {
            "type": "object", "properties": {"mode": {"type": "string"}}
        },
        ("POST", "/api/docker/images/load"): {
            "type": "object", "properties": {"path": {"type": "string"}, "cleanup": {"type": "boolean"}}
        },
    }
    for route_key, expected in explicit_small_request_schemas.items():
        request_schema = merged_by_key[route_key].request_body_schema
        if request_schema != expected:
            fail(f"explicit small request schema regressed for {route_key}")
        if isinstance(request_schema, dict) and "required" in request_schema:
            fail(f"explicit small request schema must not invent required fields for {route_key}")

    docker_image_upload_temp = merged_by_key[("POST", "/api/docker/images/upload-temp")]
    if not docker_image_upload_temp.has_body:
        fail("Docker image upload-temp direct frontend call must retain request body semantics")
    if docker_image_upload_temp.request_content_type != "multipart/form-data":
        fail("Docker image upload-temp direct frontend call must remain multipart/form-data")
    if docker_image_upload_temp.request_body_schema != {
        "type": "object",
        "properties": {"file": {"type": "string", "format": "binary"}},
    }:
        fail("Docker image upload-temp multipart file schema regressed")
    if docker_image_upload_temp.confidence != "runtime-verified":
        fail("Docker image upload-temp handler evidence must remain runtime-verified")

    docker_image_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {
        ("POST", "/api/docker/images/import"),
        ("POST", "/api/docker/images/load"),
        ("POST", "/api/docker/images/{param}/tag"),
        ("DELETE", "/api/docker/images/{param}"),
    }:
        route = merged_by_key[route_key]
        if route.confidence != "runtime-verified":
            fail(f"Docker disposable image route must remain runtime-verified for {route_key}")
        if route.response_schema != docker_image_ret_only:
            fail(f"Docker disposable image ret-only response schema regressed for {route_key}")

    docker_image_save = merged_by_key[("GET", "/api/docker/images/save.withoutcompression")]
    if docker_image_save.response_type != "blob":
        fail("Docker image save route must remain a binary response")
    if docker_image_save.response_content_type != "application/x-tar":
        fail("Docker image save runtime media type regressed")
    if docker_image_save.confidence != "runtime-verified":
        fail("Docker image save route must remain runtime-verified")

    frontend_preferences_response = {
        "type": "object",
        "properties": {
            "preferences": {
                "type": "object",
                "properties": {
                    "BackgroundBlur": {"type": "integer"},
                    "BackgroundColor": {"type": "string"},
                    "BackgroundImage": {"type": "string"},
                    "EnableCustomBackgroundColor": {"type": "boolean"},
                    "EnableCustomBackgroundImage": {"type": "boolean"},
                    "FrontendDisableAutoExpandLeftMenu": {"type": "boolean"},
                    "FrontendLanguage": {"type": "string"},
                    "FrontendTheme": {"type": "string"},
                },
            },
            "ret": {"type": "integer"},
        },
    }
    if merged_by_key[("PUT", "/api/frontend-preferences")].response_schema != frontend_preferences_response:
        fail("Frontend preferences same-value PUT response schema regressed")

    login_challenge = merged_by_key[("GET", "/api/login/challenge")].response_schema
    challenge_id_schema = (
        login_challenge.get("properties", {}).get("challengeId")
        if isinstance(login_challenge, dict)
        else None
    )
    if challenge_id_schema != {"type": "string"}:
        fail("login challengeId runtime evidence regressed")

    ipdb_config = merged_by_key[("GET", "/api/ipdb/configure")].response_schema
    custom_ipdb_path_schema = (
        ipdb_config.get("properties", {}).get("customIPDBPath")
        if isinstance(ipdb_config, dict)
        else None
    )
    if custom_ipdb_path_schema != {"type": "string"}:
        fail("IPDB custom path runtime evidence regressed")

    base_put_route = merged_by_key[("PUT", "/api/baseconfigure")]
    base_put = base_put_route.request_body_schema
    base_props = base_put.get("properties", {}) if isinstance(base_put, dict) else {}
    if not isinstance(base_put, dict) or base_put.get("type") != "object":
        fail("baseconfigure PUT request schema must remain an object")
    if set(base_props) != set(base_put_route.body_keys):
        fail("baseconfigure PUT request schema must cover exactly the frontend body fields")
    base_string_fields = {
        "AdminAccount", "AdminPassword", "AdminWebListenIP", "BackendServerListBackup",
        "BackgroundColor", "BackgroundImage", "CustomDNSA", "CustomDNSB", "CustomDNSC",
        "CustomDNSD", "CustomDNSList", "DeviceID", "FrontendLanguage", "FrontendTheme",
        "GlobalNoLimitCIDRs", "OldPassword", "OpenToken", "OriginsList",
        "ProxyProtocolTrustedCIDRs", "SafeURL", "TimeZone", "TwoFAKey",
    }
    base_integer_fields = {
        "AdminWebListenHttpsPort", "AdminWebListenPort", "BackgroundBlur", "ConfVer",
        "FirewallInitDelay", "GCPercent", "GOMAXPROCS", "HttpClientTimeout", "LogMaxSize",
        "MaxConsecutiveLoginFailures", "StatusHistoryRetentionDays",
        "StatusHistorySampleIntervalSeconds", "TokenExpirationHour", "TwoFADigits",
    }
    base_boolean_fields = {
        "AdminWebListenTLS", "AllowAllThirdAuthUsers", "AllowInternetaccess",
        "AutoOptionsFirewall", "CatchPanic", "DisableAllowAllOrigins", "DisableNTPSync",
        "DisableNTPSyncLog", "EnableCustomBackgroundColor", "EnableCustomBackgroundImage",
        "EnableOpenToken", "EnableStatusHistory", "EnableThirdAuthLogin", "ForceHTTPS",
        "FrontendDisableAutoExpandLeftMenu", "GlobalDisableFirewallOpt", "IgnoreAuthInfoCheck",
        "IgnoreSafeURLCheck", "InsecureSkipVerify", "OpenTokenConfirmed", "RestartAfterPanic",
        "SetGCPercent", "ThirdAuthLoginSkipTwoFA", "TwoFAEnable",
    }
    for field in base_string_fields:
        if base_props.get(field) != {"type": "string"}:
            fail(f"baseconfigure string request type regressed for {field}")
    for field in base_integer_fields:
        if base_props.get(field) != {"type": "integer"}:
            fail(f"baseconfigure integer request type regressed for {field}")
    for field in base_boolean_fields:
        if base_props.get(field) != {"type": "boolean"}:
            fail(f"baseconfigure boolean request type regressed for {field}")
    for field in ("DisableModules", "Keys"):
        if base_props.get(field) != {}:
            fail(f"baseconfigure null-only runtime field must remain untyped for {field}")
    nullable_string_array = {"type": ["array", "null"], "items": {"type": "string"}}
    for field in ("StatNetInterfaceList", "ThirdAuthLoginUserList"):
        if base_props.get(field) != nullable_string_array:
            fail(f"baseconfigure frontend-constructed nullable string-array type regressed for {field}")
    if base_props.get("hiddenModules") != {"type": ["array", "null"], "items": {}}:
        fail("baseconfigure hiddenModules request type must reuse verified module model")
    if "required" in base_put:
        fail("baseconfigure PUT request schema must not invent required fields")

    ddns_record_delete = merged_by_key[("DELETE", "/api/ddns/{param}/{param2}")]
    if ddns_record_delete.request_body_schema != {
        "type": "object", "properties": {"deleteFromProvider": {"type": "boolean"}}
    }:
        fail("DDNS record delete request schema regressed")

    filebrowser_put_route = merged_by_key[("PUT", "/api/third/filebrowser/configure")]
    filebrowser_put = filebrowser_put_route.request_body_schema
    filebrowser_get_route = patched_by_key[("GET", "/api/third/filebrowser/configure")]
    filebrowser_get = filebrowser_get_route.response_schema
    filebrowser_get_props = (
        filebrowser_get.get("properties", {}).get("configure", {}).get("properties", {})
        if isinstance(filebrowser_get, dict)
        else {}
    )
    expected_filebrowser_props = dict(filebrowser_get_props)
    expected_filebrowser_props["MountList"] = {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "Type": {"type": "string"},
                "Param": {"type": "string"},
                "DisplayName": {"type": "string"},
                "Writable": {"type": "boolean"},
                "DisableChangeWriteTable": {"type": "boolean"},
            },
        },
    }
    expected_filebrowser_props["RedisCacheUrl"] = {"type": "string"}
    if filebrowser_put != {"type": "object", "properties": expected_filebrowser_props}:
        fail("FileBrowser PUT request schema must match the verified editable configuration model")
    if isinstance(filebrowser_put, dict) and "required" in filebrowser_put:
        fail("FileBrowser PUT request schema must not invent required fields")
    filebrowser_get_mount = filebrowser_get_props.get("MountList")
    if filebrowser_get_mount != {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "DisplayName": {"type": "string"},
                "InvalidMsg": {"type": "string"},
                "IsLocalDir": {"type": "boolean"},
                "Param": {"type": "string"},
                "Type": {"type": "string"},
                "Writable": {"type": "boolean"},
            },
        },
    }:
        fail("FileBrowser GET MountList runtime item model regressed")
    if filebrowser_put_route.confidence != "runtime-verified":
        fail("FileBrowser PUT configuration behavior must remain runtime-verified")
    if filebrowser_put_route.response_schema != {
        "type": "object", "properties": {"ret": {"type": "integer"}}
    }:
        fail("FileBrowser PUT ret-only response schema regressed")
    if filebrowser_get_route.confidence != "runtime-verified":
        fail("FileBrowser GET configuration behavior must remain runtime-verified")

    wol_webhook = merged_by_key[("POST", "/api/wol/webhooktest")].request_body_schema
    wol_get = merged_by_key[("GET", "/api/wol/service/configure")].response_schema
    wol_server_props = (
        wol_get.get("properties", {}).get("configure", {}).get("properties", {}).get("Server", {}).get("properties", {})
        if isinstance(wol_get, dict)
        else {}
    )
    wol_webhook_fields = tuple(merged_by_key[("POST", "/api/wol/webhooktest")].body_keys)
    expected_wol_webhook_props = {
        field: ({"type": "string"} if field == "WebhookProxyPassword" else wol_server_props.get(field))
        for field in wol_webhook_fields
    }
    if any(value is None for value in expected_wol_webhook_props.values()):
        fail("WOL webhook request fields must remain backed by the verified Server read model")
    if wol_webhook != {"type": "object", "properties": expected_wol_webhook_props}:
        fail("WOL webhook-test request schema regressed")
    if isinstance(wol_webhook, dict) and "required" in wol_webhook:
        fail("WOL webhook-test request schema must not invent required fields")

    wol_device_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"},
            "DeviceName": {"type": "string"},
            "MacList": {"type": "array", "items": {"type": "string"}},
            "BroadcastIPs": {"type": "array", "items": {"type": "string"}},
            "ProbeTargets": {"type": "array", "items": {}},
            "Port": {"type": "integer"},
            "Relay": {"type": "boolean"},
            "Repeat": {"type": "integer"},
            "IOT_DianDeng_Enable": {"type": "boolean"},
            "IOT_DianDeng_AUTHKEY": {"type": "string"},
            "IOT_DianDeng_InsecureSkipVerify": {"type": "boolean"},
            "IOT_DianDengBindComponentEnable": {"type": "boolean"},
            "IOT_DianDengBindComponent": {"type": "string"},
            "IOT_Bemfa_Enable": {"type": "boolean"},
            "IOT_Bemfa_SecretKey": {"type": "string"},
            "IOT_Bemfa_Topic": {"type": "string"},
            "IOT_Bemfa_InsecureSkipVerify": {"type": "boolean"},
        },
    }
    for route_key in {
        ("POST", "/api/wol/device"),
        ("PUT", "/api/wol/device"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != wol_device_request:
            fail(f"WOL disposable-device request schema regressed for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"WOL device request schema must not invent required fields for {route_key}")
        if route.response_schema != {"type": "object", "properties": {"ret": {"type": "integer"}}}:
            fail(f"WOL disposable-device ret-only response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/wol/device")].response_schema != {
        "type": "object", "properties": {"ret": {"type": "integer"}}
    }:
        fail("WOL disposable-device delete response schema regressed")

    wol_devices = merged_by_key[("GET", "/api/wol/devices")].response_schema
    wol_device_props = (
        wol_devices.get("properties", {}).get("list", {}).get("items", {}).get("properties", {})
        if isinstance(wol_devices, dict)
        else {}
    )
    for secret_field in ("IOT_DianDeng_AUTHKEY", "IOT_Bemfa_SecretKey"):
        if secret_field in wol_device_props:
            fail(f"WOL device response schema must omit secret field {secret_field}")
    for field, expected in {
        "Key": {"type": "string"},
        "DeviceName": {"type": "string"},
        "MacList": {"type": "array", "items": {"type": "string"}},
        "BroadcastIPs": {"type": "array", "items": {"type": "string"}},
        "ProbeTargets": {"type": "array", "items": {}},
        "Port": {"type": "integer"},
        "Relay": {"type": "boolean"},
        "Repeat": {"type": "integer"},
        "Probe": {"type": "object"},
        "CanShutdown": {"type": "boolean"},
        "CanWakeup": {"type": "boolean"},
    }.items():
        if wol_device_props.get(field) != expected:
            fail(f"WOL device safe response type regressed for {field}")
    wol_wakeup = merged_by_key[("GET", "/api/wol/device/wakeup")]
    if wol_wakeup.confidence != "runtime-verified":
        fail("WOL wakeup behavior must remain runtime-verified")
    if tuple(wol_wakeup.query_keys) != ("key",):
        fail("WOL wakeup query-key evidence regressed")
    if wol_wakeup.response_schema != {
        "type": "object", "properties": {"ret": {"type": "integer"}}
    }:
        fail("WOL wakeup ret-only response schema regressed")

    update_confirm = merged_by_key[("PUT", "/api/update/comfire")].request_body_schema
    expected_update_confirm = {
        "type": "object",
        "properties": {
            "Name": {"type": "string"},
            "ARCH": {"type": "string"},
            "OS": {"type": "string"},
            "Version": {"type": "string"},
            "GoVersion": {"type": "string"},
            "Date": {"type": "string"},
            "MD5": {"type": "string"},
        },
    }
    if update_confirm != expected_update_confirm:
        fail("program-update confirm request schema regressed")
    info_schema = merged_by_key[("GET", "/api/info")].response_schema
    info_props = (
        info_schema.get("properties", {}).get("info", {}).get("properties", {})
        if isinstance(info_schema, dict)
        else {}
    )
    for field in ("ARCH", "OS", "Version", "GoVersion", "Date", "MD5"):
        if info_props.get(field) != {"type": "string"}:
            fail(f"/api/info string evidence regressed for update field {field}")

    lightpanel_template = merged_by_key[("POST", "/api/webservice/lightpanel/configtemplate")].request_body_schema
    expected_lightpanel = {
        "type": "object",
        "properties": {
            "type": {"type": "string"},
            "path": {"type": "string"},
            "rcloneKey": {"type": "string"},
            "rcloneRoot": {"type": "string"},
            "storeKey": {"type": "string"},
            "storeRoot": {"type": "string"},
        },
    }
    if lightpanel_template != expected_lightpanel:
        fail("WebService lightpanel config-template request schema regressed")
    icon_sources = merged_by_key[("GET", "/api/iconlib/sources")].response_schema
    icon_source_props = (
        icon_sources.get("properties", {}).get("sources", {}).get("items", {}).get("properties", {})
        if isinstance(icon_sources, dict)
        else {}
    )
    expected_icon_source_props = {
        "Alias": {"type": "string"},
        "Type": {"type": "string"},
        "Path": {"type": "string"},
        "RcloneKey": {"type": "string"},
        "RcloneRoot": {"type": "string"},
        "StoreKey": {"type": "string"},
        "StoreRoot": {"type": "string"},
        "Enable": {"type": "boolean"},
        "Description": {"type": "string"},
    }
    if icon_source_props != expected_icon_source_props:
        fail("IconLib safe source item schema regressed")

    icon_source_request = {"type": "object", "properties": expected_icon_source_props}
    icon_ret_only_schema = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {
        ("POST", "/api/iconlib/sources"),
        ("PUT", "/api/iconlib/sources"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != icon_source_request:
            fail(f"IconLib source request schema regressed for {route_key}")
        if set(route.body_keys) != set(expected_icon_source_props):
            fail(f"IconLib source body keys regressed for {route_key}")
        if route.response_schema != icon_ret_only_schema:
            fail(f"IconLib source ret-only response schema regressed for {route_key}")
    for route_key in {
        ("DELETE", "/api/iconlib/sources/{param}"),
        ("GET", "/api/iconlib/sources/{param}/enable/{param2}"),
    }:
        if merged_by_key[route_key].response_schema != icon_ret_only_schema:
            fail(f"IconLib disposable-source ret-only response schema regressed for {route_key}")

    crosschecked_resource_request_schemas = {
        ("PUT", "/api/modules/hidden"): {
            "type": "object", "properties": {"hiddenModules": {"type": ["array", "null"], "items": {}}}
        },
        ("POST", "/api/docker/images/pull-async"): {
            "type": "object", "properties": {"architecture": {"type": "string"}, "image": {"type": "string"}, "tag": {"type": "string"}}
        },
        ("POST", "/api/docker/images/pull-with-backup"): {
            "type": "object", "properties": {"architecture": {"type": "string"}, "backup_tag": {"type": "string"}, "image_ref": {"type": "string"}}
        },
        ("POST", "/api/docker/images/pull-with-backup-async"): {
            "type": "object", "properties": {"architecture": {"type": "string"}, "backup_tag": {"type": "string"}, "image_ref": {"type": "string"}}
        },
        ("POST", "/api/docker/images/push"): {
            "type": "object", "properties": {"image": {"type": "string"}, "tag": {"type": "string"}}
        },
        ("POST", "/api/docker/images/remove-saved-digest"): {
            "type": "object", "properties": {"image_id": {"type": "string"}}
        },
        ("POST", "/api/docker/images/backup-tag"): {
            "type": "object", "properties": {"image_ref": {"type": "string"}}
        },
        ("POST", "/api/docker/images/upgrade-check"): {
            "type": "object", "properties": {"image_ref": {"type": "string"}}
        },
        ("POST", "/api/docker/images/upgrade-dismiss"): {
            "type": "object", "properties": {"image_id": {"type": "string"}, "image_ref": {"type": "string"}}
        },
        ("POST", "/api/docker/images/{param}/tag"): {
            "type": "object", "properties": {"repository": {"type": "string"}, "tag": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/commit"): {
            "type": "object", "properties": {"repository": {"type": "string"}, "tag": {"type": "string"}, "comment": {"type": "string"}}
        },
    }
    for route_key, expected in crosschecked_resource_request_schemas.items():
        request_schema = merged_by_key[route_key].request_body_schema
        if request_schema != expected:
            fail(f"cross-checked resource request schema regressed for {route_key}")
        if isinstance(request_schema, dict) and "required" in request_schema:
            fail(f"cross-checked resource request schema must not invent required fields for {route_key}")

    modules_list = merged_by_key[("GET", "/api/modules/list")].response_schema
    hidden_modules_schema = (
        modules_list.get("properties", {}).get("hiddenModules")
        if isinstance(modules_list, dict)
        else None
    )
    if hidden_modules_schema != {"type": ["array", "null"], "items": {}}:
        fail("modules hiddenModules runtime evidence regressed")

    docker_images = merged_by_key[("GET", "/api/docker/images")].response_schema
    docker_image_props = (
        docker_images.get("properties", {}).get("images", {}).get("items", {}).get("properties", {})
        if isinstance(docker_images, dict)
        else {}
    )
    for field in ("Id", "Architecture"):
        if docker_image_props.get(field) != {"type": "string"}:
            fail(f"Docker image metadata string evidence regressed for {field}")
    if docker_image_props.get("RepoTags") != {"type": "array", "items": {"type": "string"}}:
        fail("Docker image RepoTags evidence regressed")

    docker_search = merged_by_key[("POST", "/api/docker/images/search")]
    if docker_search.risk is not OperationRisk.READ_ONLY:
        fail("Docker image search must remain runtime-verified read-only")
    if docker_search.request_body_schema != {
        "type": "object",
        "properties": {"limit": {"type": "integer"}, "term": {"type": "string"}},
    }:
        fail("Docker image search request schema regressed")
    if docker_search.response_schema != {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "star_count": {"type": "integer"},
                        "is_official": {"type": "boolean"},
                        "name": {"type": "string"},
                        "is_automated": {"type": "boolean"},
                        "description": {"type": "string"},
                    },
                },
            },
        },
    }:
        fail("Docker image search response schema regressed")

    compose_identity_schema = {
        "type": "object",
        "properties": {
            "project_name": {"type": "string"},
            "project_path": {"type": "string"},
            "config_file_name": {"type": "string"},
        },
    }
    compose_down_schema = {
        "type": "object",
        "properties": {
            **compose_identity_schema["properties"],
            "remove_volumes": {"type": "boolean"},
        },
    }
    compose_identity_responses = {
        ("POST", "/api/docker/compose/restart"): compose_ret_only,
        ("POST", "/api/docker/compose/start"): compose_ret_only,
        ("POST", "/api/docker/compose/stop"): None,
        ("POST", "/api/docker/compose/stop-async"): compose_task_response,
    }
    for route_key, expected_response in compose_identity_responses.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != compose_identity_schema:
            fail(f"Docker Compose project identity request schema regressed for {route_key}")
        if route.response_schema != expected_response:
            fail(f"Docker Compose project identity response schema regressed for {route_key}")
    compose_down_responses = {
        ("POST", "/api/docker/compose/down"): compose_ret_only,
        ("POST", "/api/docker/compose/down-async"): compose_task_response,
    }
    for route_key, expected_response in compose_down_responses.items():
        route = merged_by_key[route_key]
        if route.request_body_schema != compose_down_schema:
            fail(f"Docker Compose down request schema regressed for {route_key}")
        if route.response_schema != expected_response:
            fail(f"Docker Compose down response schema regressed for {route_key}")

    compose_projects_route = merged_by_key[("GET", "/api/docker/compose/projects")]
    if compose_projects_route.confidence != "runtime-verified":
        fail("Docker Compose projects readback must remain runtime-verified")
    compose_projects = compose_projects_route.response_schema
    compose_project_props = (
        compose_projects.get("properties", {}).get("projects", {}).get("items", {}).get("properties", {})
        if isinstance(compose_projects, dict)
        else {}
    )
    for field in ("name", "path", "configFileName"):
        if compose_project_props.get(field) != {"type": "string"}:
            fail(f"Docker Compose project string evidence regressed for {field}")
    compose_container_detail = (
        compose_project_props.get("containerDetails", {}).get("items", {}).get("properties", {})
    )
    if compose_container_detail != {
        "name": {"type": "string"},
        "state": {"type": "string"},
    }:
        fail("Docker Compose containerDetails response schema regressed")
    compose_ps_route = merged_by_key[("GET", "/api/docker/compose/{param}/ps")]
    if compose_ps_route.confidence != "runtime-verified":
        fail("Docker Compose ps readback must remain runtime-verified")

    compose_file_request_schemas = {
        ("POST", "/api/docker/compose/backup"): {
            "type": "object", "properties": {"project_name": {"type": "string"}, "project_path": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/config"): {
            "type": "object", "properties": {"project_path": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/discover"): {
            "type": "object", "properties": {"scan_path": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/dockerfile"): {
            "type": "object", "properties": {"project_path": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/read-file"): {
            "type": "object", "properties": {"filename": {"type": "string"}, "working_dir": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/update-config"): {
            "type": "object", "properties": {"content": {"type": "string"}, "project_path": {"type": "string"}}
        },
        ("POST", "/api/docker/compose/update-dockerfile"): {
            "type": "object", "properties": {"content": {"type": "string"}, "project_path": {"type": "string"}}
        },
    }
    for route_key, expected in compose_file_request_schemas.items():
        request_schema = merged_by_key[route_key].request_body_schema
        if request_schema != expected:
            fail(f"Docker Compose file request schema regressed for {route_key}")
        if isinstance(request_schema, dict) and "required" in request_schema:
            fail(f"Docker Compose file request schema must not invent required fields for {route_key}")
    compose_config_response = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "content": {"type": "string"},
            "filename": {"type": "string"},
            "msg": {"type": "string"},
        },
    }
    compose_config_route = merged_by_key[("POST", "/api/docker/compose/config")]
    if compose_config_route.response_schema != compose_config_response:
        fail("Docker Compose config runtime response schema regressed")
    if compose_config_route.confidence != "runtime-verified":
        fail("Docker Compose config must remain runtime-verified")

    local_path_list = merged_by_key[("GET", "/api/local-path-browser/list")].response_schema
    local_path_data = (
        local_path_list.get("properties", {}).get("data", {}).get("properties", {})
        if isinstance(local_path_list, dict)
        else {}
    )
    local_path_entry = local_path_data.get("entries", {}).get("items", {}).get("properties", {})
    if local_path_data.get("path") != {"type": "string"}:
        fail("Local Path Browser path string evidence regressed")
    for field in ("name", "path"):
        if local_path_entry.get(field) != {"type": "string"}:
            fail(f"Local Path Browser entry string evidence regressed for {field}")

    docker_create_request = merged_by_key[("POST", "/api/docker/containers")].request_body_schema
    docker_create_props = docker_create_request.get("properties", {}) if isinstance(docker_create_request, dict) else {}
    expected_edit_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "config": docker_create_props.get("config"),
            "hostConfig": docker_create_props.get("hostConfig"),
            "auto_start": {"type": "boolean"},
            "remove_old": {"type": "boolean"},
        },
    }
    docker_edit = merged_by_key[("POST", "/api/docker/containers/{param}/edit")].request_body_schema
    if docker_edit != expected_edit_schema:
        fail("Docker container edit request schema must reuse the verified create-container config/hostConfig model")
    if isinstance(docker_edit, dict) and "required" in docker_edit:
        fail("Docker container edit request schema must not invent required fields")

    container_copy_rename_schema = {"type": "object", "properties": {"name": {"type": "string"}}}
    for route_key in {
        ("POST", "/api/docker/containers/{param}/copy"),
        ("POST", "/api/docker/containers/{param}/rename"),
    }:
        if merged_by_key[route_key].request_body_schema != container_copy_rename_schema:
            fail(f"Docker container name request schema regressed for {route_key}")
    docker_container = merged_by_key[("GET", "/api/docker/containers/{param}")].response_schema
    docker_container_name = (
        docker_container.get("properties", {}).get("data", {}).get("properties", {}).get("container", {}).get("properties", {}).get("Name")
        if isinstance(docker_container, dict)
        else None
    )
    if docker_container_name != {"type": "string"}:
        fail("Docker container Name runtime evidence regressed")

    dlna_put_route = merged_by_key[("PUT", "/api/dlnaservice/configure")]
    dlna_get_route = patched_by_key[("GET", "/api/dlnaservice/configure")]
    dlna_put = dlna_put_route.request_body_schema
    dlna_get = dlna_get_route.response_schema
    dlna_config_props = (
        dlna_get.get("properties", {}).get("configure", {}).get("properties", {})
        if isinstance(dlna_get, dict)
        else {}
    )
    expected_dlna_put = {
        "type": "object",
        "properties": {
            "Enable": dlna_config_props.get("Enable"),
            "ListenIP": dlna_config_props.get("ListenIP"),
            "ListenPort": dlna_config_props.get("ListenPort"),
            "NetInterfaceList": {"type": ["array", "null"], "items": {"type": "string"}},
            "FriendlyName": dlna_config_props.get("FriendlyName"),
            "DeviceUUID": dlna_config_props.get("DeviceUUID"),
            "MountList": {
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {
                        "Type": {"type": "string"},
                        "Param": {"type": "string"},
                        "DisplayName": {"type": "string"},
                        "Writable": {"type": "boolean"},
                        "DisableChangeWriteTable": {"type": "boolean"},
                    },
                },
            },
        },
    }
    if dlna_put != expected_dlna_put:
        fail("DLNA PUT request schema must match the verified editable configuration model")
    if isinstance(dlna_put, dict) and "required" in dlna_put:
        fail("DLNA PUT request schema must not invent required fields")
    if dlna_config_props.get("MountList") != {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "DisplayName": {"type": "string"},
                "InvalidMsg": {"type": "string"},
                "IsLocalDir": {"type": "boolean"},
                "Param": {"type": "string"},
                "Type": {"type": "string"},
                "Writable": {"type": "boolean"},
            },
        },
    }:
        fail("DLNA GET MountList runtime item model regressed")
    if dlna_config_props.get("NetInterfaceList") != {
        "type": ["array", "null"], "items": {"type": "string"}
    }:
        fail("DLNA NetInterfaceList runtime item model regressed")
    if dlna_put_route.response_schema != {
        "type": "object", "properties": {"ret": {"type": "integer"}}
    }:
        fail("DLNA PUT ret-only response schema regressed")
    if dlna_put_route.confidence != "runtime-verified":
        fail("DLNA PUT behavior must remain runtime-verified")
    if dlna_get_route.confidence != "runtime-verified":
        fail("DLNA GET configuration behavior must remain runtime-verified")

    read_model_put_schemas = {
        "/api/webterminal/config": "config",
        "/api/rclone/globalconfig": "globalConfig",
        "/api/ipfliter/list/{param}": "rule",
        "/api/thirdPartyAuthManager/config": "config",
        "/api/webdav/configure": "configure",
        "/api/wol/service/configure": "configure",
    }
    for path, response_field in read_model_put_schemas.items():
        put_schema = merged_by_key[("PUT", path)].request_body_schema
        get_schema = merged_by_key[("GET", path)].response_schema
        expected = (
            get_schema.get("properties", {}).get(response_field)
            if isinstance(get_schema, dict)
            else None
        )
        if put_schema != expected:
            fail(f"PUT request schema must match verified GET {response_field} model for {path}")
        if isinstance(put_schema, dict) and "required" in put_schema:
            fail(f"read-model-derived PUT schema must not invent required fields for {path}")

    smb_get_route = patched_by_key[("GET", "/api/smb/configure")]
    smb_unpatched_get_route = merged_by_key[("GET", "/api/smb/configure")]
    smb_put_route = merged_by_key[("PUT", "/api/smb/configure")]
    smb_get_props = (
        smb_get_route.response_schema.get("properties", {})
        .get("configure", {})
        .get("properties", {})
        if isinstance(smb_get_route.response_schema, dict)
        else {}
    )
    expected_smb_mount = {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "Type": {"type": "string"},
                "Param": {"type": "string"},
                "DisplayName": {"type": "string"},
                "Writable": {"type": "boolean"},
                "DisableChangeWriteTable": {"type": "boolean"},
            },
        },
    }
    if smb_get_props.get("PublicMountList") != expected_smb_mount:
        fail("SMB PublicMountList runtime item model regressed")
    smb_put_props = (
        smb_put_route.request_body_schema.get("properties", {})
        if isinstance(smb_put_route.request_body_schema, dict)
        else {}
    )
    if smb_put_props.get("PublicMountList") != expected_smb_mount:
        fail("SMB PUT PublicMountList editable model regressed")
    smb_unpatched_get_props = (
        smb_unpatched_get_route.response_schema.get("properties", {})
        .get("configure", {})
        .get("properties", {})
        if isinstance(smb_unpatched_get_route.response_schema, dict)
        else {}
    )
    if smb_put_props.get("Users") != smb_unpatched_get_props.get("Users"):
        fail("SMB credential-bearing Users model must stay aligned and unspecified")
    if smb_get_route.confidence != "runtime-verified":
        fail("SMB GET configuration behavior must remain runtime-verified")
    if smb_put_route.confidence != "runtime-verified":
        fail("SMB PUT configuration behavior must remain runtime-verified")
    if smb_put_route.response_schema != {
        "type": "object", "properties": {"ret": {"type": "integer"}}
    }:
        fail("SMB PUT ret-only response schema regressed")

    wol_put = merged_by_key[("PUT", "/api/wol/service/configure")].request_body_schema
    wol_server_props = (
        wol_put.get("properties", {}).get("Server", {}).get("properties", {})
        if isinstance(wol_put, dict)
        else {}
    )
    if "WebhookProxyPassword" in wol_server_props:
        fail("WOL safe read-model PUT schema must not document request-only proxy password")
    wol_put_response = merged_by_key[("PUT", "/api/wol/service/configure")].response_schema
    expected_wol_put_response = {
        "type": "object",
        "properties": {
            "configure": wol_get.get("properties", {}).get("configure"),
            "ret": {"type": "integer"},
        },
    }
    if wol_put_response != expected_wol_put_response:
        fail("WOL same-value PUT safe response schema regressed")


    about_put = merged_by_key[("PUT", "/api/about-content")].request_body_schema
    about_get = merged_by_key[("GET", "/api/about-content")].response_schema
    if about_put != about_get:
        fail("About-content PUT request schema must match verified GET public-content model")
    if isinstance(about_put, dict) and "required" in about_put:
        fail("About-content PUT schema must not invent required fields")
    about_route = merged_by_key[("PUT", "/api/about-content")]
    if about_route.response_schema != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "msg": {"type": "string"}},
    }:
        fail("About-content same-value PUT response schema regressed")
    if about_route.success_response_markers != ((1, "成功"),):
        fail("About-content verified success response marker regressed")

    cron_group_requests = {
        ("POST", "/api/cron/groups"): {
            "type": "object",
            "properties": {"Name": {"type": "string"}},
        },
        ("PUT", "/api/cron/groups"): {
            "type": "object",
            "properties": {"Key": {"type": "string"}, "Name": {"type": "string"}},
        },
        ("PUT", "/api/cron/groups/collapsed"): {
            "type": "object",
            "properties": {"collapsed": {"type": "boolean"}, "key": {"type": "string"}},
        },
    }
    for route_key, expected in cron_group_requests.items():
        if merged_by_key[route_key].request_body_schema != expected:
            fail(f"Cron disposable-group request schema regressed for {route_key}")

    ret_only_schema = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    if merged_by_key[("POST", "/api/cron/groups")].response_schema != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "key": {"type": "string"}},
    }:
        fail("Cron group create response schema regressed")
    for route_key in {
        ("PUT", "/api/cron/groups"),
        ("PUT", "/api/cron/groups/collapsed"),
        ("DELETE", "/api/cron/groups"),
        ("PUT", "/api/cron/groups/orderadjustment"),
        ("PUT", "/api/cron/taskgrouporderupdate"),
        ("GET", "/api/cron/enable"),
        ("DELETE", "/api/cron/list"),
    }:
        if merged_by_key[route_key].response_schema != ret_only_schema:
            fail(f"Cron disposable/no-op ret-only response schema regressed for {route_key}")

    cron_groups = merged_by_key[("GET", "/api/cron/groups")].response_schema
    cron_group_item = (
        cron_groups.get("properties", {}).get("list", {}).get("items")
        if isinstance(cron_groups, dict)
        else None
    )
    if cron_group_item != {
        "type": "object",
        "properties": {"Key": {"type": "string"}, "Name": {"type": "string"}},
    }:
        fail("Cron group list item schema regressed")

    cron_tasks = merged_by_key[("GET", "/api/cron/list")].response_schema
    cron_task_item = (
        cron_tasks.get("properties", {}).get("list", {}).get("items")
        if isinstance(cron_tasks, dict)
        else None
    )
    if cron_task_item != {
        "type": "object",
        "properties": {
            "GroupKey": {"type": "string"},
            "Name": {"type": "string"},
            "Key": {"type": "string"},
            "Enable": {"type": "boolean"},
            "Type": {"type": "integer"},
            "ExecSecond": {"type": "integer"},
            "ExecMinute": {"type": "integer"},
            "ExecHour": {"type": "integer"},
            "Parallel": {"type": "boolean"},
            "IOT_DianDeng_Enable": {"type": "boolean"},
            "IOT_DianDeng_InsecureSkipVerify": {"type": "boolean"},
            "IOT_DianDengBindComponentEnable": {"type": "boolean"},
            "IOT_Bemfa_Enable": {"type": "boolean"},
            "IOT_Bemfa_InsecureSkipVerify": {"type": "boolean"},
            "IOTDianDengOnline": {"type": "boolean"},
            "IOTBemfaOnline": {"type": "boolean"},
        },
    }:
        fail("Cron task list safe item schema regressed")

    collapsed_states = merged_by_key[("GET", "/api/cron/groups/collapsed/states")].response_schema
    states_schema = (
        collapsed_states.get("properties", {}).get("states")
        if isinstance(collapsed_states, dict)
        else None
    )
    if states_schema != {"type": "object", "additionalProperties": {"type": "boolean"}}:
        fail("Cron group collapsed-state map schema regressed")

    empty_order_response_routes = {
        ("PUT", "/api/cloudflared/orderadjustment"),
        ("PUT", "/api/portforward/ruleorderadjustment"),
        ("PUT", "/api/stun/ruleorderadjustment"),
        ("PUT", "/api/frp/orderadjustment"),
        ("PUT", "/api/rclone/itemorderadjustment"),
        ("PUT", "/api/coraza/instanceorderadjustment"),
        ("PUT", "/api/wol/deviceorderadjustment"),
        ("PUT", "/api/storagemanagement/itemorderadjustment"),
        ("PUT", "/api/thirdPartyAuthManager/orderadjustment"),
    }
    empty_order_request_schema = {"type": "array", "items": {"type": "string"}}
    for route_key in empty_order_response_routes:
        route = merged_by_key[route_key]
        if route.request_body_schema != empty_order_request_schema:
            fail(f"empty-baseline order-adjustment request schema regressed for {route_key}")
        if route.response_schema != ret_only_schema:
            fail(f"empty-baseline order-adjustment ret-only response schema regressed for {route_key}")

    host_kill = merged_by_key[("POST", "/api/status/host-process-kill")].request_body_schema
    if host_kill != {
        "type": "object",
        "properties": {"pid": {"type": "integer"}},
    }:
        fail("host-process kill request schema regressed")
    host_processes = merged_by_key[("GET", "/api/status/host-processes")].response_schema
    host_pid_schema = (
        host_processes.get("properties", {}).get("list", {}).get("items", {}).get("properties", {}).get("pid")
        if isinstance(host_processes, dict)
        else None
    )
    if host_pid_schema != {"type": "integer"}:
        fail("host-process list pid evidence regressed")
    host_process_properties = host_processes["properties"]["list"]["items"]["properties"]
    if host_process_properties["listeningPorts"] != {
        "type": ["array", "null"], "items": {"type": "integer"}
    }:
        fail("host-process listeningPorts schema regressed")

    status_history = merged_by_key[("GET", "/api/status/history")]
    if tuple(status_history.query_keys) != ("start", "end", "bucket"):
        fail("status-history query-key evidence regressed")
    expected_status_history = {
        "type": "object",
        "properties": {
            "bucket": {"type": "string"},
            "enabled": {"type": "boolean"},
            "pointCount": {"type": "integer"},
            "recordingStartedAt": {"type": "integer"},
            "ret": {"type": "integer"},
            "retentionDays": {"type": "integer"},
            "series": {"type": "array", "items": {"type": "object"}},
        },
    }
    if status_history.response_schema != expected_status_history:
        fail("status-history response schema regressed")

    local_path_requests = {
        ("POST", "/api/local-path-browser/mkdir"): {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        },
        ("PUT", "/api/local-path-browser/rename"): {
            "type": "object",
            "properties": {"path": {"type": "string"}, "newName": {"type": "string"}},
        },
        ("DELETE", "/api/local-path-browser/path"): {
            "type": "object",
            "properties": {"confirmName": {"type": "string"}, "path": {"type": "string"}},
        },
    }
    for route_key, expected in local_path_requests.items():
        if merged_by_key[route_key].request_body_schema != expected:
            fail(f"Local Path Browser disposable-probe request schema regressed for {route_key}")

    path_response_schema = {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "path": {"type": "string"}},
    }
    for route_key in {
        ("POST", "/api/local-path-browser/mkdir"),
        ("PUT", "/api/local-path-browser/rename"),
    }:
        if merged_by_key[route_key].response_schema != path_response_schema:
            fail(f"Local Path Browser path response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/local-path-browser/path")].response_schema != ret_only_schema:
        fail("Local Path Browser delete response schema regressed")
    if merged_by_key[("DELETE", "/api/local-path-browser/path")].risk is not OperationRisk.DANGEROUS:
        fail("Local Path Browser delete must remain classified dangerous")

    response_schema_count = sum(route.response_schema is not None for route in patched_merged.routes)
    if response_schema_count < 354:
        fail(f"response-schema coverage regressed below 354 routes: {response_schema_count}")

    icon_response = merged_by_key[("GET", "/api/iconlib/icon")]
    if icon_response.response_type != "blob" or icon_response.response_content_type != "image/png":
        fail("IconLib icon response must retain its runtime-verified image/png media type")

    def count_schema_holes(value: object) -> int:
        if value == {}:
            return 1
        if isinstance(value, dict):
            return sum(count_schema_holes(item) for item in value.values())
        if isinstance(value, list):
            return sum(count_schema_holes(item) for item in value)
        return 0

    request_schema_holes = sum(
        count_schema_holes(route.request_body_schema)
        for route in merged.routes
        if route.request_body_schema is not None
    )
    if request_schema_holes > 31:
        fail(f"nested request-schema coverage regressed above 31 holes: {request_schema_holes}")

    response_schema_holes = sum(
        count_schema_holes(route.response_schema)
        for route in patched_merged.routes
        if route.response_schema is not None
    )
    if response_schema_holes != 0:
        fail(f"nested response-schema coverage must remain at zero holes: {response_schema_holes}")

    top_level_untyped_write_routes = []
    for route in merged.routes:
        if route.method not in {"POST", "PUT", "PATCH"} or not route.has_body:
            continue
        schema = route.request_body_schema
        if not isinstance(schema, dict) or schema.get("type") != "object":
            continue
        properties = schema.get("properties", {})
        if isinstance(properties, dict) and any(value == {} for value in properties.values()):
            top_level_untyped_write_routes.append((route.method, route.path))
    if len(top_level_untyped_write_routes) > 1:
        fail(
            "top-level untyped write-schema coverage regressed above 1 route: "
            f"{len(top_level_untyped_write_routes)}"
        )

    safe_utility_response_routes = {
        ("GET", "/api/baseconfigure"),
        ("GET", "/api/docker/info"),
        ("GET", "/api/ipfliter/porttrap/blockedips"),
        ("GET", "/api/ipfliter/porttrap/blockedips/search"),
        ("GET", "/api/cron/expressioncheck"),
        ("GET", "/api/cron/groups"),
        ("GET", "/api/cron/groups/collapsed/states"),
        ("GET", "/api/cron/groups/taskcount"),
        ("GET", "/api/modules/{param}/2fa/status"),
        ("GET", "/api/webservice/cgi/list"),
        ("GET", "/api/webservice/groups/subrulecount"),
        ("GET", "/api/webservice/statistics/ip-profile"),
        ("GET", "/api/login/challenge"),
        ("GET", "/api/ipregtest"),
        ("GET", "/api/webservice/statistics/recent-ips/visits"),
        ("GET", "/api/ssl/lastlogs"),
        ("GET", "/api/ssl/logs"),
        ("GET", "/api/ssl/syncclients"),
        ("GET", "/api/thirdPartyAuthManager/list"),
        ("GET", "/api/thirdPartyAuthManager/config"),
        ("GET", "/api/webservice/webauth/sessions"),
        ("GET", "/api/webterminal/config"),
        ("GET", "/api/webterminal/connections"),
        ("GET", "/api/webterminal/globalshortcuts"),
        ("GET", "/api/webterminal/sessions"),
        ("GET", "/api/webterminal/shells"),
        ("GET", "/api/webterminal/splitlayout"),
    }
    for route_key in safe_utility_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"safe utility response schema missing for {route_key}")

    baseconfigure = merged_by_key[("GET", "/api/baseconfigure")].response_schema
    baseconfigure_props = (
        baseconfigure.get("properties", {}).get("baseconfigure", {}).get("properties", {})
        if isinstance(baseconfigure, dict)
        else {}
    )
    expected_safe_baseconfigure_fields = {
        "AdminWebListenPort", "AdminWebListenTLS", "AdminWebListenHttpsPort", "ForceHTTPS",
        "TokenExpirationHour", "MaxConsecutiveLoginFailures", "TimeZone", "FrontendTheme",
        "FrontendLanguage", "EnableStatusHistory", "StatusHistoryRetentionDays",
        "StatusHistorySampleIntervalSeconds",
    }
    if set(baseconfigure_props) != expected_safe_baseconfigure_fields:
        fail("baseconfigure safe response whitelist regressed")
    forbidden_baseconfigure_fields = {
        "AdminAccount", "AdminPassword", "OpenToken", "TwoFAKey", "SafeURL", "DeviceID",
        "Keys", "ThirdAuthLoginUserList", "BackendServerListBackup", "CustomDNSA", "CustomDNSB",
        "CustomDNSC", "CustomDNSD", "CustomDNSList", "OriginsList", "ProxyProtocolTrustedCIDRs",
        "GlobalNoLimitCIDRs", "StatNetInterfaceList", "DisableModules", "hiddenModules", "BackgroundImage",
    }
    if set(baseconfigure_props) & forbidden_baseconfigure_fields:
        fail("baseconfigure sensitive/network-identifying fields leaked into response schema")

    docker_info = merged_by_key[("GET", "/api/docker/info")].response_schema
    docker_info_props = (
        docker_info.get("properties", {}).get("info", {}).get("properties", {})
        if isinstance(docker_info, dict)
        else {}
    )
    expected_safe_docker_info_fields = {
        "Containers", "ContainersRunning", "ContainersPaused", "ContainersStopped", "Images",
        "MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "CPUShares", "CPUSet",
        "PidsLimit", "IPv4Forwarding", "OomKillDisable", "Debug", "LoggingDriver",
        "CgroupDriver", "CgroupVersion", "KernelVersion", "OperatingSystem", "OSVersion",
        "OSType", "Architecture", "NCPU", "MemTotal", "ExperimentalBuild", "ServerVersion",
        "DefaultRuntime", "LiveRestoreEnabled", "Isolation",
    }
    if set(docker_info_props) != expected_safe_docker_info_fields:
        fail("Docker info safe response whitelist regressed")
    forbidden_docker_info_fields = {
        "ID", "Name", "DockerRootDir", "HttpProxy", "HttpsProxy", "NoProxy", "RegistryConfig",
        "IndexServerAddress", "Runtimes", "Swarm", "Containerd", "CDISpecDirs", "Labels",
        "GenericResources",
    }
    if set(docker_info_props) & forbidden_docker_info_fields:
        fail("Docker info host/network-identifying fields leaked into response schema")

    portforward_response_routes = {
        ("POST", "/api/portforward"),
        ("PUT", "/api/portforward"),
        ("DELETE", "/api/portforward"),
        ("GET", "/api/portforward/{param}"),
        ("GET", "/api/portforward/{param}/lastlogs"),
        ("GET", "/api/portforward/{param}/logs"),
    }
    for route_key in portforward_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"PortForward disposable-probe response schema missing for {route_key}")

    portforward_post = merged_by_key[("POST", "/api/portforward")].response_schema
    if portforward_post != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "key": {"type": "string"}},
    }:
        fail("PortForward create response schema regressed")
    for route_key in {
        ("PUT", "/api/portforward"),
        ("DELETE", "/api/portforward"),
    }:
        if merged_by_key[route_key].response_schema != {
            "type": "object",
            "properties": {"ret": {"type": "integer"}},
        }:
            fail(f"PortForward ret-only write response schema regressed for {route_key}")

    portforward_detail = merged_by_key[("GET", "/api/portforward/{param}")].response_schema
    portforward_rule_props = (
        portforward_detail.get("properties", {}).get("rule", {}).get("properties", {})
        if isinstance(portforward_detail, dict)
        else {}
    )
    if "Options" in portforward_rule_props:
        fail("PortForward Options must remain omitted from response documentation because it contains encryption-key fields")
    for field in ("ForwardTypes", "TargetAddressList"):
        if portforward_rule_props.get(field) != {"type": ["array", "null"], "items": {}}:
            fail(f"PortForward nullable list item schema must remain unspecified: {field}")
    if portforward_rule_props.get("Enable") != {"type": "boolean"}:
        fail("PortForward Enable response schema regressed")

    expected_portforward_request_props = dict(portforward_rule_props)
    expected_portforward_request_props["Options"] = {"type": "object"}
    expected_portforward_request_props["LogStreamSettings"] = {"type": "object"}
    for route_key in {
        ("POST", "/api/portforward"),
        ("PUT", "/api/portforward"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != {"type": "object", "properties": expected_portforward_request_props}:
            fail(f"PortForward request schema regressed for {route_key}")
        if set(route.body_keys) != set(expected_portforward_request_props):
            fail(f"PortForward request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"PortForward request schema must not invent required fields for {route_key}")

    for route_key, field in {
        ("GET", "/api/portforward/{param}/lastlogs"): "lastLogs",
        ("GET", "/api/portforward/{param}/logs"): "logs",
    }.items():
        response_schema = merged_by_key[route_key].response_schema
        collection = response_schema.get("properties", {}).get(field) if isinstance(response_schema, dict) else None
        expected_collection = {
            "type": ["array", "null"],
            "items": {
                "type": "object",
                "properties": {
                    "LogContent": {"type": "string"},
                    "LogTime": {"type": "string"},
                    "ShowTime": {"type": "boolean"},
                    "Level": {"type": "string"},
                },
            },
        }
        if collection != expected_collection:
            fail(f"PortForward shared log item schema regressed for {route_key}")

    for route_key in {
        ("GET", "/api/ipfliter/porttrap/blockedips"),
        ("GET", "/api/ipfliter/porttrap/blockedips/search"),
    }:
        response_schema = merged_by_key[route_key].response_schema
        ips = response_schema.get("properties", {}).get("ips") if isinstance(response_schema, dict) else None
        if ips != {"type": ["array", "null"], "items": {}}:
            fail(f"blocked-IP item schema must remain unspecified for {route_key}")

    ip_profile_schema = merged_by_key[("GET", "/api/webservice/statistics/ip-profile")].response_schema
    if ip_profile_schema != {"type": "object", "properties": {"ret": {"type": "integer"}}}:
        fail("WebService empty IP-profile success schema must remain ret-only")

    login_challenge = merged_by_key[("GET", "/api/login/challenge")].response_schema
    login_challenge_props = login_challenge.get("properties", {}) if isinstance(login_challenge, dict) else {}
    if login_challenge_props != {
        "ret": {"type": "integer"},
        "challengeId": {"type": "string"},
        "expiresIn": {"type": "integer"},
        "nonce": {"type": "string"},
        "publicKey": {"type": "string"},
    }:
        fail("login challenge response schema regressed")

    ipregtest_schema = merged_by_key[("GET", "/api/ipregtest")].response_schema
    if ipregtest_schema != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "ip": {"type": "string"}},
    }:
        fail("IP regex test response schema regressed")

    recent_visits = merged_by_key[("GET", "/api/webservice/statistics/recent-ips/visits")].response_schema
    recent_visit_props = recent_visits.get("properties", {}) if isinstance(recent_visits, dict) else {}
    if recent_visit_props.get("visits") != {"type": "array", "items": {}}:
        fail("WebService recent-IP visit item schema must remain unspecified")
    recent_item_props = recent_visit_props.get("item", {}).get("properties", {})
    if recent_item_props != {
        "clientIP": {"type": "string"},
        "clientIPGeo": {"type": "object"},
    }:
        fail("WebService recent-IP minimal profile schema regressed")

    cgi_schema = merged_by_key[("GET", "/api/webservice/cgi/list")].response_schema
    cgi_list = cgi_schema.get("properties", {}).get("list") if isinstance(cgi_schema, dict) else None
    if cgi_list != {
        "type": ["array", "null"],
        "items": {"type": "object", "properties": expected_cgi_item_props},
    }:
        fail("WebService CGI item schema must remain limited to the verified disposable-item fields")

    twofa_status = merged_by_key[("GET", "/api/modules/{param}/2fa/status")].response_schema
    twofa_props = (
        twofa_status.get("properties", {}).get("data", {}).get("properties", {})
        if isinstance(twofa_status, dict)
        else {}
    )
    if set(twofa_props) != {"enable", "validated", "hasKey"} or any(
        twofa_props.get(field) != {"type": "boolean"} for field in ("enable", "validated", "hasKey")
    ):
        fail("module 2FA status schema must remain boolean-only and secret-free")

    auth_manager_config = merged_by_key[("GET", "/api/thirdPartyAuthManager/config")].response_schema
    auth_manager_props = (
        auth_manager_config.get("properties", {}).get("config", {}).get("properties", {})
        if isinstance(auth_manager_config, dict)
        else {}
    )
    expected_auth_manager_fields = {
        "GithubRedirectURI",
        "GithubClientID",
        "GoogleRedirectURI",
        "GoogleClientID",
        "QQRedirectURI",
        "QQClientID",
        "WeiboRedirectURI",
        "WeiboClientKey",
        "AuthentikRedirectURI",
        "AuthentikClientID",
        "AuthentikServer",
        "OIDCRedirectURI",
        "OIDCClientID",
        "OIDCAuthorizationEndpoint",
    }
    if set(auth_manager_props) != expected_auth_manager_fields or any(
        value != {"type": "string"} for value in auth_manager_props.values()
    ):
        fail("third-party auth public metadata schema regressed or gained secret-bearing fields")
    if any("secret" in field.lower() or "token" in field.lower() or "password" in field.lower() for field in auth_manager_props):
        fail("third-party auth config schema must remain secret/token/password-free")

    auth_user_request = {
        "type": "object",
        "properties": {
            "Key": {"type": "string"},
            "Type": {"type": "string"},
            "Enable": {"type": "boolean"},
            "Remark": {"type": "string"},
            "ID": {"type": "string"},
            "Name": {"type": "string"},
            "Avatar": {"type": "string"},
            "EMail": {"type": "string"},
            "Phone": {"type": "string"},
            "RefreshToken": {"type": "string"},
            "AccessToken": {"type": "string"},
            "CreateTime": {"type": "integer"},
            "UpdateTime": {"type": "integer"},
            "TwoFAKey": {"type": "string"},
        },
    }
    key_ret_schema = {
        "type": "object",
        "properties": {"key": {"type": "string"}, "ret": {"type": "integer"}},
    }
    for route_key in {
        ("POST", "/api/thirdPartyAuthManager/list"),
        ("PUT", "/api/thirdPartyAuthManager/list"),
    }:
        route = merged_by_key[route_key]
        if route.request_body_schema != auth_user_request:
            fail(f"third-party auth disposable-user request schema regressed for {route_key}")
        if set(route.body_keys) != set(auth_user_request["properties"]):
            fail(f"third-party auth request schema must cover exactly the frontend body fields for {route_key}")
        if isinstance(route.request_body_schema, dict) and "required" in route.request_body_schema:
            fail(f"third-party auth request schema must not invent required fields for {route_key}")
        if route.response_schema != key_ret_schema:
            fail(f"third-party auth disposable-user key/ret response schema regressed for {route_key}")
    if merged_by_key[("DELETE", "/api/thirdPartyAuthManager/list/{param}")].response_schema != ret_only_schema:
        fail("third-party auth disposable-user delete response schema regressed")

    safe_auth_user_props = {
        "Key": {"type": "string"},
        "Enable": {"type": "boolean"},
        "Remark": {"type": "string"},
        "CreateTime": {"type": "integer"},
        "UpdateTime": {"type": "integer"},
        "HasTwoFA": {"type": "boolean"},
        "Type": {"type": "string"},
        "ID": {"type": "string"},
        "Name": {"type": "string"},
        "Avatar": {"type": "string"},
        "EMail": {"type": "string"},
        "Phone": {"type": "string"},
    }
    auth_user_list = merged_by_key[("GET", "/api/thirdPartyAuthManager/list")].response_schema
    auth_user_list_schema = (
        auth_user_list.get("properties", {}).get("list")
        if isinstance(auth_user_list, dict)
        else None
    )
    if auth_user_list_schema != {
        "type": ["array", "null"],
        "items": {"type": "object", "properties": safe_auth_user_props},
    }:
        fail("third-party auth safe nullable-list schema regressed")

    auth_user_detail = merged_by_key[("GET", "/api/thirdPartyAuthManager/list/{param}")].response_schema
    auth_user_detail_props = (
        auth_user_detail.get("properties", {}).get("authUser", {}).get("properties", {})
        if isinstance(auth_user_detail, dict)
        else {}
    )
    expected_auth_user_detail_props = dict(safe_auth_user_props)
    expected_auth_user_detail_props["IsNew"] = {"type": "boolean"}
    if auth_user_detail_props != expected_auth_user_detail_props:
        fail("third-party auth safe detail schema regressed")
    if merged_by_key[("GET", "/api/thirdPartyAuthManager/list/{param}/{param2}")].response_schema != ret_only_schema:
        fail("third-party auth two-parameter GET response schema regressed")

    webauth_sessions = merged_by_key[("GET", "/api/webservice/webauth/sessions")].response_schema
    webauth_props = webauth_sessions.get("properties", {}) if isinstance(webauth_sessions, dict) else {}
    if webauth_props.get("list") != {"type": "array", "items": {}}:
        fail("WebAuth session item schema must remain unspecified")
    for field in ("page", "pageSize", "total"):
        if webauth_props.get(field) != {"type": "integer"}:
            fail(f"WebAuth session pagination field regressed: {field}")

    webterminal_config = merged_by_key[("GET", "/api/webterminal/config")].response_schema
    webterminal_config_props = (
        webterminal_config.get("properties", {}).get("config", {}).get("properties", {})
        if isinstance(webterminal_config, dict)
        else {}
    )
    if set(webterminal_config_props) != {
        "idleTimeout",
        "bufferSize",
        "heartbeatInterval",
        "maxSessions",
        "sessionKeepAlive",
    } or any(value != {"type": "integer"} for value in webterminal_config_props.values()):
        fail("WebTerminal safe numeric config schema regressed")

    webterminal_sessions = merged_by_key[("GET", "/api/webterminal/sessions")].response_schema
    webterminal_session_list = (
        webterminal_sessions.get("properties", {}).get("list")
        if isinstance(webterminal_sessions, dict)
        else None
    )
    if webterminal_session_list != {"type": ["array", "null"], "items": {}}:
        fail("WebTerminal session item schema must remain unspecified")

    shortcuts = merged_by_key[("GET", "/api/webterminal/globalshortcuts")].response_schema
    shortcut_items = shortcuts.get("properties", {}).get("shortcuts") if isinstance(shortcuts, dict) else None
    if shortcut_items != {"type": ["array", "null"], "items": {}}:
        fail("WebTerminal shortcut command/key item schema must remain unspecified")

    shells = merged_by_key[("GET", "/api/webterminal/shells")].response_schema
    shell_props = (
        shells.get("properties", {}).get("shells", {}).get("items", {}).get("properties", {})
        if isinstance(shells, dict)
        else {}
    )
    if shell_props != {"name": {"type": "string"}, "platform": {"type": "string"}}:
        fail("WebTerminal shell schema must remain path-free")

    splitlayout = merged_by_key[("GET", "/api/webterminal/splitlayout")].response_schema
    splitlayout_props = splitlayout.get("properties", {}) if isinstance(splitlayout, dict) else {}
    if splitlayout_props.get("layout") != {"type": ["object", "null"]}:
        fail("WebTerminal split-layout details must remain unspecified")

    nullable_list_response_routes = {
        ("GET", "/api/portforwards"): ("list", "Moduledisable"),
        ("GET", "/api/portforwards_lite"): ("list", "Moduledisable"),
        ("GET", "/api/ipdb/avalidDBFiles"): ("list", None),
        ("GET", "/api/ssl/syncclients"): ("list", None),
    }
    for route_key, (list_field, flag_field) in nullable_list_response_routes.items():
        response_schema = merged_by_key[route_key].response_schema
        props = response_schema.get("properties", {}) if isinstance(response_schema, dict) else {}
        if props.get(list_field) != {"type": ["array", "null"], "items": {}}:
            fail(f"nullable list schema regressed for {route_key}")
        if flag_field is not None and props.get(flag_field) != {"type": "boolean"}:
            fail(f"module enable/disable flag schema regressed for {route_key}")

    for route_key in {
        ("GET", "/api/rclone/third/115pan/authuserlist"),
        ("GET", "/api/rclone/third/alipan/authuserlist"),
        ("GET", "/api/rclone/third/baidupan/authuserlist"),
    }:
        response_schema = merged_by_key[route_key].response_schema
        data_schema = response_schema.get("properties", {}).get("data") if isinstance(response_schema, dict) else None
        if data_schema != {"type": ["array", "null"], "items": {}}:
            fail(f"Rclone auth-user item schema must remain unspecified for {route_key}")

    expected_rclone_authurl_schema = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "authurl": {"type": "string"},
            "tmpkey": {"type": "string"},
        },
    }
    for route_key in {
        ("GET", "/api/rclone/third/115pan/authurl"),
        ("GET", "/api/rclone/third/alipan/authurl"),
        ("GET", "/api/rclone/third/baidupan/authurl"),
    }:
        if merged_by_key[route_key].response_schema != expected_rclone_authurl_schema:
            fail(f"Rclone authorization-URL response schema regressed for {route_key}")

    storage_auth_schema = merged_by_key[("GET", "/api/storagemanagement/aliyunpan_auth")].response_schema
    if storage_auth_schema != {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "url": {"type": "string"},
            "key": {"type": "string"},
        },
    }:
        fail("storage-management AliyunPan authorization-URL response schema regressed")

    docker_resource_response_routes = {
        ("POST", "/api/docker/containers"),
        ("POST", "/api/docker/containers/{param}/start"),
        ("DELETE", "/api/docker/containers/{param}"),
        ("DELETE", "/api/docker/images/remove"),
        ("GET", "/api/docker/containers/{param}/processes"),
        ("GET", "/api/docker/containers/{param}/logs"),
        ("POST", "/api/docker/images/pull"),
        ("GET", "/api/docker/images/{param}"),
        ("GET", "/api/docker/images/{param}/history"),
        ("GET", "/api/docker/images/containers"),
        ("GET", "/api/docker/containers/{param}/stats"),
        ("GET", "/api/docker/containers/{param}/stats-cached"),
        ("GET", "/api/docker/container-groups/count"),
        ("GET", "/api/docker/compose/{param}/backups"),
        ("GET", "/api/docker/compose/{param}/ps"),
        ("GET", "/api/docker/labels/{param}/containers"),
        ("GET", "/api/docker/volumes/{param}/backups"),
    }
    for route_key in docker_resource_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"Docker resource response schema missing for {route_key}")

    docker_pull = merged_by_key[("POST", "/api/docker/images/pull")]
    if docker_pull.request_body_schema != {
        "type": "object",
        "properties": {"image": {"type": "string"}, "tag": {"type": "string"}},
    }:
        fail("Docker image pull request schema regressed")
    if docker_pull.response_schema != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "output": {"type": "string"}},
    }:
        fail("Docker image pull response schema regressed")

    docker_create_response = merged_by_key[("POST", "/api/docker/containers")].response_schema
    if docker_create_response != {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "container_id": {"type": "string"},
            "warnings": {"type": "array", "items": {}},
        },
    }:
        fail("Docker disposable create response schema regressed")

    docker_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {
        ("POST", "/api/docker/containers/{param}/start"),
        ("DELETE", "/api/docker/containers/{param}"),
    }:
        if merged_by_key[route_key].response_schema != docker_ret_only:
            fail(f"Docker disposable lifecycle ret-only response schema regressed for {route_key}")

    docker_remove_image = merged_by_key[("DELETE", "/api/docker/images/remove")].response_schema
    if docker_remove_image != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "removed": {"type": "array", "items": {}}},
    }:
        fail("Docker image-remove response schema regressed")

    docker_processes = merged_by_key[("GET", "/api/docker/containers/{param}/processes")].response_schema
    if docker_processes != {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "processes": {
                "type": "object",
                "properties": {
                    "Titles": {"type": "array", "items": {"type": "string"}},
                    "Processes": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
                },
            },
        },
    }:
        fail("Docker process-table response schema regressed")

    docker_logs = merged_by_key[("GET", "/api/docker/containers/{param}/logs")].response_schema
    if docker_logs != {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "logs": {"type": "string"}},
    }:
        fail("Docker logs response schema regressed")

    docker_file_requests = {
        ("POST", "/api/docker/containers/{param}/files/mkdir"): {
            "type": "object", "properties": {"path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/touch"): {
            "type": "object", "properties": {"path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/write"): {
            "type": "object", "properties": {"content": {"type": "string"}, "path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/rename"): {
            "type": "object", "properties": {"new_path": {"type": "string"}, "old_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/copy"): {
            "type": "object", "properties": {"dst_path": {"type": "string"}, "src_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/chmod"): {
            "type": "object", "properties": {"path": {"type": "string"}, "permissions": {"type": "string"}}
        },
        ("DELETE", "/api/docker/containers/{param}/files"): {
            "type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}
        },
        ("POST", "/api/docker/containers/{param}/files/compress"): {
            "type": "object", "properties": {"output_name": {"type": "string"}, "output_path": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}}
        },
        ("POST", "/api/docker/containers/{param}/files/compress-async"): {
            "type": "object", "properties": {"output_name": {"type": "string"}, "output_path": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}}
        },
        ("POST", "/api/docker/containers/{param}/files/decompress"): {
            "type": "object", "properties": {"file_path": {"type": "string"}, "output_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/decompress-async"): {
            "type": "object", "properties": {"file_path": {"type": "string"}, "output_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/search"): {
            "type": "object", "properties": {"file_type": {"type": "string"}, "keyword": {"type": "string"}, "max_depth": {"type": "integer"}, "max_result": {"type": "integer"}, "path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/label"): {
            "type": "object", "properties": {"label": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/restart"): {
            "type": "object", "properties": {"timeout": {"type": "integer"}}
        },
        ("POST", "/api/docker/containers/{param}/stop"): {
            "type": "object", "properties": {"timeout": {"type": "integer"}}
        },
    }
    for route_key, expected in docker_file_requests.items():
        if merged_by_key[route_key].request_body_schema != expected:
            fail(f"Docker disposable file request schema regressed for {route_key}")

    docker_file_path_response = {
        "type": "object",
        "properties": {"ret": {"type": "integer"}, "msg": {"type": "string"}, "path": {"type": "string"}},
    }
    for route_key in {
        ("POST", "/api/docker/containers/{param}/files/mkdir"),
        ("POST", "/api/docker/containers/{param}/files/touch"),
        ("POST", "/api/docker/containers/{param}/files/write"),
        ("DELETE", "/api/docker/containers/{param}/files"),
    }:
        if merged_by_key[route_key].response_schema != docker_file_path_response:
            fail(f"Docker disposable file path response schema regressed for {route_key}")

    docker_file_responses = {
        ("GET", "/api/docker/containers/{param}/files/list"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "output": {"type": "string"}, "path": {"type": "string"}}
        },
        ("GET", "/api/docker/containers/{param}/files/read"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "content": {"type": "string"}, "path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/rename"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "msg": {"type": "string"}, "new_path": {"type": "string"}, "old_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/copy"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "msg": {"type": "string"}, "dst_path": {"type": "string"}, "src_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/chmod"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "msg": {"type": "string"}, "path": {"type": "string"}, "permissions": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/compress"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "command": {"type": "string"}, "msg": {"type": "string"}, "output_name": {"type": "string"}, "output_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/decompress"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "command": {"type": "string"}, "file_path": {"type": "string"}, "msg": {"type": "string"}, "output_path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/files/search"): {
            "type": "object", "properties": {"ret": {"type": "integer"}, "command": {"type": "string"}, "count": {"type": "integer"}, "files": {"type": "array", "items": {}}, "keyword": {"type": "string"}, "limit": {"type": "integer"}, "path": {"type": "string"}}
        },
        ("POST", "/api/docker/containers/{param}/label"): docker_ret_only,
        ("POST", "/api/docker/containers/{param}/restart"): docker_ret_only,
        ("POST", "/api/docker/containers/{param}/stop"): docker_ret_only,
    }
    for route_key, expected in docker_file_responses.items():
        if merged_by_key[route_key].response_schema != expected:
            fail(f"Docker disposable file response schema regressed for {route_key}")

    docker_file_search = merged_by_key[("POST", "/api/docker/containers/{param}/files/search")]
    if docker_file_search.risk is not OperationRisk.READ_ONLY:
        fail("Docker container file search must remain runtime-verified read-only")
    search_files = (
        docker_file_search.response_schema.get("properties", {}).get("files")
        if isinstance(docker_file_search.response_schema, dict)
        else None
    )
    if search_files != {"type": "array", "items": {}}:
        fail("Docker file-search item schema must remain unspecified")
    for route_key in {
        ("POST", "/api/docker/containers/{param}/files/compress-async"),
        ("POST", "/api/docker/containers/{param}/files/decompress-async"),
    }:
        if merged_by_key[route_key].response_schema is not None:
            fail(f"Docker async file route must not claim an unverified response schema for {route_key}")

    image_schema = merged_by_key[("GET", "/api/docker/images/{param}")].response_schema
    image_props = image_schema.get("properties", {}).get("image", {}).get("properties", {}) if isinstance(image_schema, dict) else {}
    if "Config" in image_props:
        fail("Docker image inspect schema must not document Config/env/volume/port details")
    if image_props.get("RepoTags") != {"type": "array", "items": {"type": "string"}}:
        fail("Docker image RepoTags schema regressed")

    history_schema = merged_by_key[("GET", "/api/docker/images/{param}/history")].response_schema
    history_props = (
        history_schema.get("properties", {}).get("history", {}).get("items", {}).get("properties", {})
        if isinstance(history_schema, dict)
        else {}
    )
    if history_props.get("CreatedBy") != {"type": "string"} or history_props.get("Tags") != {
        "type": "array",
        "items": {"type": "string"},
    }:
        fail("Docker image history schema regressed")

    resource_cached_stats = merged_by_key[("GET", "/api/docker/containers/{param}/stats-cached")].response_schema
    resource_cached_props = (
        resource_cached_stats.get("properties", {}).get("data", {}).get("properties", {})
        if isinstance(resource_cached_stats, dict)
        else {}
    )
    if resource_cached_props.get("port_services") != {"type": "object"}:
        fail("Docker per-container cached-stat dynamic port map schema regressed")

    for route_key in {
        ("GET", "/api/docker/compose/{param}/backups"),
        ("GET", "/api/docker/volumes/{param}/backups"),
    }:
        response_schema = merged_by_key[route_key].response_schema
        backups = response_schema.get("properties", {}).get("backups") if isinstance(response_schema, dict) else None
        if backups != {"type": "array", "items": {}}:
            fail(f"Docker backup item schema must remain unspecified for {route_key}")

    label_containers = merged_by_key[("GET", "/api/docker/labels/{param}/containers")].response_schema
    label_container_items = (
        label_containers.get("properties", {}).get("containers")
        if isinstance(label_containers, dict)
        else None
    )
    if label_container_items != {"type": ["array", "null"], "items": {}}:
        fail("Docker label-container item schema must remain unspecified")

    compose_ps = merged_by_key[("GET", "/api/docker/compose/{param}/ps")].response_schema
    compose_ps_props = (
        compose_ps.get("properties", {}).get("containers", {}).get("items", {}).get("properties", {})
        if isinstance(compose_ps, dict)
        else {}
    )
    if set(compose_ps_props) != {"Health", "ID", "Name", "Project", "Service", "State"}:
        fail("Docker compose ps summary schema regressed")

    webservice_stat_response_routes = {
        ("GET", "/api/webservice/statistics/capabilities"),
        ("GET", "/api/webservice/statistics/daily"),
        ("GET", "/api/webservice/statistics/realtime"),
        ("GET", "/api/webservice/statistics/events"),
        ("GET", "/api/webservice/statistics/geo/aggregate"),
        ("GET", "/api/webservice/statistics/geo/rebuild/status"),
        ("GET", "/api/webservice/statistics/history"),
        ("GET", "/api/webservice/statistics/import/status"),
        ("GET", "/api/webservice/statistics/rankings"),
        ("GET", "/api/webservice/statistics/recent-ips"),
        ("GET", "/api/webservice/statistics/waf/events"),
        ("GET", "/api/webservice/statistics/waf/summary"),
        ("GET", "/api/webservice/discovery/active"),
    }
    for route_key in webservice_stat_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"WebService statistics response schema missing for {route_key}")

    for route_key in {
        ("GET", "/api/webservice/statistics/capabilities"),
        ("GET", "/api/webservice/statistics/daily"),
        ("GET", "/api/webservice/statistics/realtime"),
    }:
        response_schema = merged_by_key[route_key].response_schema
        top_props = response_schema.get("properties", {}) if isinstance(response_schema, dict) else {}
        if "meta" in top_props or "settings" in top_props:
            fail(f"WebService statistics sensitive config fields leaked into schema for {route_key}")

    def schema_property_paths(schema: object, prefix: str = "") -> set[str]:
        if not isinstance(schema, dict):
            return set()
        properties = schema.get("properties")
        paths: set[str] = set()
        if not isinstance(properties, dict):
            return paths
        for name, child in properties.items():
            path = f"{prefix}.{name}" if prefix else name
            paths.add(path)
            paths.update(schema_property_paths(child, path))
            if isinstance(child, dict) and "items" in child:
                paths.update(schema_property_paths(child.get("items"), path + "[]"))
        return paths

    statistics_safe_property_paths = {
        ("GET", "/api/webservice/statistics/capabilities"): {
            "ret",
            "capabilities",
            "capabilities.contractVersion",
            "capabilities.timeRangeSemantics",
            "capabilities.bucketBoundary",
            "capabilities.granularities",
            "capabilities.retention",
            "capabilities.retention.minuteHours",
            "capabilities.retention.hourDays",
            "capabilities.retention.dayDays",
            "capabilities.metrics",
            "capabilities.metrics[].key",
            "capabilities.metrics[].label",
            "capabilities.filters",
            "capabilities.filters[].key",
            "capabilities.filters[].availability",
            "capabilities.rankingDimensions",
            "capabilities.rankingDimensions[].key",
            "capabilities.rankingDimensions[].availability",
            "capabilities.rankingDimensions[].candidateLimit",
            "capabilities.geoDimensions",
            "capabilities.geoDimensions[].key",
            "capabilities.geoDimensions[].availability",
        },
        ("GET", "/api/webservice/statistics/daily"): {
            "ret",
            "aggregateGranularity",
            "approximate",
            "days",
            "days[].date",
            "end",
            "quality",
            "quality.complete",
            "quality.estimated",
            "quality.missingFrom",
            "quality.requestedStart",
            "quality.requestedEnd",
            "quality.actualStart",
            "quality.actualEnd",
            "quality.boundaryTruncated",
            "stale",
            "start",
            "summary",
            "summary.date",
        },
        ("GET", "/api/webservice/statistics/realtime"): {
            "ret",
            "connections",
            "lastMinute",
            "point",
            "point.timestamp",
            "traffic",
            "waf",
        },
    }
    for route_key, allowed_paths in statistics_safe_property_paths.items():
        actual_paths = schema_property_paths(merged_by_key[route_key].response_schema)
        if actual_paths != allowed_paths:
            fail(
                f"WebService statistics safe response allowlist regressed for {route_key}: "
                f"expected {sorted(allowed_paths)}, got {sorted(actual_paths)}"
            )

    capabilities = merged_by_key[("GET", "/api/webservice/statistics/capabilities")].response_schema
    capability_props = (
        capabilities.get("properties", {}).get("capabilities", {}).get("properties", {})
        if isinstance(capabilities, dict)
        else {}
    )
    if set(capability_props) != {
        "contractVersion",
        "timeRangeSemantics",
        "bucketBoundary",
        "granularities",
        "retention",
        "metrics",
        "filters",
        "rankingDimensions",
        "geoDimensions",
    }:
        fail("WebService statistics capabilities schema must remain contract-only")

    realtime = merged_by_key[("GET", "/api/webservice/statistics/realtime")].response_schema
    realtime_props = realtime.get("properties", {}) if isinstance(realtime, dict) else {}
    if realtime_props.get("lastMinute") != {"type": "array", "items": {}}:
        fail("WebService realtime lastMinute item schema must remain unspecified")

    for route_key, field in {
        ("GET", "/api/webservice/statistics/events"): "list",
        ("GET", "/api/webservice/statistics/history"): "points",
        ("GET", "/api/webservice/statistics/rankings"): "items",
        ("GET", "/api/webservice/statistics/waf/events"): "list",
    }.items():
        response_schema = merged_by_key[route_key].response_schema
        collection = response_schema.get("properties", {}).get(field) if isinstance(response_schema, dict) else None
        if collection != {"type": "array", "items": {}}:
            fail(f"empty WebService statistics collection must remain untyped for {route_key}")

    recent_ips = merged_by_key[("GET", "/api/webservice/statistics/recent-ips")].response_schema
    recent_ip_props = recent_ips.get("properties", {}) if isinstance(recent_ips, dict) else {}
    if recent_ip_props.get("items") != {"type": "array", "items": {}}:
        fail("WebService recent-IP item schema must remain unspecified")
    activity_items = recent_ip_props.get("activity", {}).get("properties", {}).get("items")
    if activity_items != {"type": "array", "items": {}}:
        fail("WebService recent-IP activity item schema must remain unspecified")

    docker_status_response_routes = {
        ("GET", "/api/netinterfaces"),
        ("GET", "/api/docker/compose/backup/status"),
        ("GET", "/api/docker/compose/containers-for-cron"),
        ("GET", "/api/docker/compose/projects"),
        ("GET", "/api/docker/container-groups"),
        ("GET", "/api/docker/container-groups/collapsed/states"),
        ("GET", "/api/docker/containers/sort-config"),
        ("GET", "/api/docker/containers/stats-cached"),
        ("GET", "/api/docker/disk-usage"),
        ("GET", "/api/docker/images/upgrade-status"),
        ("GET", "/api/docker/registry/mirrors"),
        ("GET", "/api/docker/volumes/backup/status"),
    }
    for route_key in docker_status_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"Docker/status response schema missing for {route_key}")

    cached_stats = merged_by_key[("GET", "/api/docker/containers/stats-cached")].response_schema
    cached_stat_item = (
        cached_stats.get("properties", {})
        .get("data", {})
        .get("additionalProperties", {})
        .get("properties", {})
        if isinstance(cached_stats, dict)
        else {}
    )
    if cached_stat_item.get("cpu_percent") != {"type": "string"} or cached_stat_item.get(
        "port_services"
    ) != {"type": "object"}:
        fail("Docker cached-stat dynamic map schema regressed")

    disk_usage = merged_by_key[("GET", "/api/docker/disk-usage")].response_schema
    disk_usage_props = (
        disk_usage.get("properties", {}).get("disk_usage", {}).get("properties", {})
        if isinstance(disk_usage, dict)
        else {}
    )
    expected_disk_usage_collections = {
        "Images": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Containers": {"type": "integer"},
                    "Created": {"type": "integer"},
                    "SharedSize": {"type": "integer"},
                    "Size": {"type": "integer"},
                },
            },
        },
        "Containers": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Created": {"type": "integer"},
                    "SizeRw": {"type": "integer"},
                    "SizeRootFs": {"type": "integer"},
                    "State": {"type": "string"},
                    "Status": {"type": "string"},
                },
            },
        },
        "Volumes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Driver": {"type": "string"},
                    "Scope": {"type": "string"},
                    "UsageData": {
                        "type": "object",
                        "properties": {
                            "RefCount": {"type": "integer"},
                            "Size": {"type": "integer"},
                        },
                    },
                },
            },
        },
        "BuildCache": {"type": "array", "items": {}},
    }
    for field, expected in expected_disk_usage_collections.items():
        if disk_usage_props.get(field) != expected:
            fail(f"Docker disk-usage resource detail schema regressed: {field}")

    service_response_routes = {
        ("GET", "/api/dlnaservice/configure"),
        ("GET", "/api/dlnaservice/status"),
        ("GET", "/api/dlnaservice/lastlogs"),
        ("GET", "/api/dlnaservice/logs"),
        ("GET", "/api/ftpserver/configure"),
        ("GET", "/api/ftpserver/status"),
        ("GET", "/api/ftpserver/lastlogs"),
        ("GET", "/api/ftpserver/logs"),
        ("GET", "/api/smb/configure"),
        ("GET", "/api/smb/runtime"),
        ("GET", "/api/smb/status"),
        ("GET", "/api/smb/lastlogs"),
        ("GET", "/api/smb/logs"),
        ("GET", "/api/webdav/configure"),
        ("GET", "/api/webdav/status"),
        ("GET", "/api/webdav/lastlogs"),
        ("GET", "/api/webdav/logs"),
        ("GET", "/api/wol/client/state"),
    }
    for route_key in service_response_routes:
        if not isinstance(merged_by_key[route_key].response_schema, dict):
            fail(f"service response schema missing for {route_key}")

    for route_key in {
        ("GET", "/api/smb/configure"),
        ("GET", "/api/webdav/configure"),
    }:
        response_schema = merged_by_key[route_key].response_schema
        configure_props = response_schema.get("properties", {}).get("configure", {}).get("properties", {})
        users = configure_props.get("Users")
        if not isinstance(users, dict) or users.get("items") != {}:
            fail(f"credential-bearing user item schema must remain unspecified for {route_key}")

    ftp_response_schema = patched_by_key[("GET", "/api/ftpserver/configure")].response_schema
    ftp_configure_props = (
        ftp_response_schema.get("properties", {}).get("configure", {}).get("properties", {})
    )
    ftp_users = ftp_configure_props.get("Users")
    expected_ftp_response_user = {
        "type": "object",
        "properties": {
            "Username": {"type": "string"},
            "Dirs": {"type": "string"},
            "ReadOnly": {"type": "boolean"},
            "MountList": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "Type": {"type": "string"},
                        "Param": {"type": "string"},
                        "DisplayName": {"type": "string"},
                        "Writable": {"type": "boolean"},
                        "IsLocalDir": {"type": "boolean"},
                    },
                },
            },
        },
    }
    if not isinstance(ftp_users, dict) or ftp_users.get("items") != expected_ftp_response_user:
        fail("FTP runtime-safe user response schema regressed")
    if "Password" in expected_ftp_response_user["properties"]:
        fail("FTP response schema must not document password values")

    ftp_put = merged_by_key[("PUT", "/api/ftpserver/configure")]
    ftp_put_users = (
        ftp_put.request_body_schema.get("properties", {}).get("Users")
        if isinstance(ftp_put.request_body_schema, dict)
        else None
    )
    expected_ftp_request_users = {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "Username": {"type": "string"},
                "Password": {"type": "string"},
                "MountList": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "Type": {"type": "string"},
                            "Param": {"type": "string"},
                            "DisplayName": {"type": "string"},
                            "Writable": {"type": "boolean"},
                            "DisableChangeWriteTable": {"type": "boolean"},
                        },
                    },
                },
            },
        },
    }
    if ftp_put_users != expected_ftp_request_users:
        fail("FTP runtime-backed user request schema regressed")

    expected_log_item_properties = {
        "LogContent": {"type": "string"},
        "LogTime": {"type": "string"},
        "ShowTime": {"type": "boolean"},
        "Level": {"type": "string"},
    }
    typed_log_routes = {
        ("GET", "/api/cloudflared/{param}/lastlogs"): "lastLogs",
        ("GET", "/api/cloudflared/{param}/logs"): "logs",
        ("GET", "/api/cloudflared/logs"): "logs",
        ("GET", "/api/coraza/logs"): "logs",
        ("GET", "/api/dlnaservice/lastlogs"): "lastLogs",
        ("GET", "/api/dlnaservice/logs"): "logs",
        ("GET", "/api/ftpserver/lastlogs"): "lastLogs",
        ("GET", "/api/ftpserver/logs"): "logs",
        ("GET", "/api/frp/{param}/lastlogs"): "lastLogs",
        ("GET", "/api/frp/{param}/logs"): "logs",
        ("GET", "/api/frp/logs"): "logs",
        ("GET", "/api/ipdb/logs"): "logs",
        ("GET", "/api/smb/lastlogs"): "lastLogs",
        ("GET", "/api/smb/logs"): "logs",
        ("GET", "/api/webdav/lastlogs"): "lastLogs",
        ("GET", "/api/webdav/logs"): "logs",
        ("GET", "/api/cron/lastlogs"): "lastLogs",
        ("GET", "/api/cron/logs"): "logs",
        ("GET", "/api/ddns/lastlogs"): "lastLogs",
        ("GET", "/api/ddns/logs"): "logs",
        ("GET", "/api/docker/logs"): "logs",
        ("GET", "/api/ipfliter/porttrap/logs"): "logs",
        ("GET", "/api/portforward/{param}/lastlogs"): "lastLogs",
        ("GET", "/api/portforward/{param}/logs"): "logs",
        ("GET", "/api/rclone/lastlogs"): "lastLogs",
        ("GET", "/api/rclone/logs"): "logs",
        ("GET", "/api/ssl/lastlogs"): "lastLogs",
        ("GET", "/api/ssl/logs"): "logs",
        ("GET", "/api/storagemanagement/lastlogs"): "lastLogs",
        ("GET", "/api/storagemanagement/logs"): "logs",
        ("GET", "/api/stun/{param}/lastlogs"): "lastLogs",
        ("GET", "/api/stun/{param}/logs"): "logs",
        ("GET", "/api/third/filebrowser/lastlogs"): "lastLogs",
        ("GET", "/api/third/filebrowser/logs"): "logs",
        ("GET", "/api/thirdPartyAuthManager/logs"): "logs",
        ("GET", "/api/webservice/lastlogs"): "lastLogs",
        ("GET", "/api/webservice/logs"): "logs",
        ("GET", "/api/webterminal/logs"): "logs",
        ("GET", "/api/wol/lastlogs"): "lastLogs",
        ("GET", "/api/wol/logs"): "logs",
    }
    for route_key, field in typed_log_routes.items():
        response_schema = merged_by_key[route_key].response_schema
        if not isinstance(response_schema, dict):
            fail(f"typed log response schema missing for {route_key}")
        item_properties = (
            response_schema.get("properties", {})
            .get(field, {})
            .get("items", {})
            .get("properties", {})
        )
        if item_properties != expected_log_item_properties:
            fail(f"typed log item schema regressed for {route_key}")

    global_logs = merged_by_key[("GET", "/api/logs")].response_schema
    if not isinstance(global_logs, dict):
        fail("global log response schema is missing")
    global_log_item = global_logs.get("properties", {}).get("logs", {}).get("items", {})
    if global_log_item.get("properties") != {
        "timestamp": {"type": "string"},
        "log": {"type": "string"},
        "time": {"type": "string"},
    }:
        fail("global log item schema regressed")

    webservice_logs = merged_by_key[("GET", "/api/webservice/logs")].response_schema
    webservice_log_props = webservice_logs.get("properties", {}) if isinstance(webservice_logs, dict) else {}
    for field, expected in {
        "hasMore": {"type": "boolean"},
        "loadedCount": {"type": "integer"},
        "totalExact": {"type": "boolean"},
    }.items():
        if webservice_log_props.get(field) != expected:
            fail(f"WebService log pagination field regressed: {field}")

    ddns_task = merged_by_key[("POST", "/api/ddns")].request_body_schema
    if not isinstance(ddns_task, dict):
        fail("DDNS task request schema is missing")
    ddns_props = ddns_task.get("properties", {})
    callback_props = (
        ddns_props.get("DNS", {}).get("properties", {}).get("Callback", {}).get("properties", {})
    )
    if callback_props.get("Headers") != {
        "type": ["array", "null"],
        "items": {"type": "string"},
    }:
        fail("DDNS callback header schema regressed")
    if ddns_props.get("TaskType", {}).get("enum") != ["IPv4", "IPv6", "IPv4&IPv6"]:
        fail("DDNS TaskType enum evidence regressed")

    web_rule = merged_by_key[("POST", "/api/webservice/rules")].request_body_schema
    if not isinstance(web_rule, dict):
        fail("WebService rule request schema is missing")
    web_rule_update = merged_by_key[("PUT", "/api/webservice/rule/{param}")].request_body_schema
    if web_rule_update != web_rule:
        fail("WebService create/update request schemas drifted apart")
    web_props = web_rule.get("properties", {})
    if web_props.get("TLSMinVersion") != {"type": "integer", "minimum": 0, "maximum": 3}:
        fail("WebService TLSMinVersion bounds regressed")
    redirect_type = (
        web_props.get("DefaultProxy", {})
        .get("properties", {})
        .get("OtherParams", {})
        .get("properties", {})
        .get("RedirectType")
    )
    if redirect_type != {"type": "string"}:
        fail("WebService DefaultProxy.OtherParams.RedirectType schema regressed")

    autorecord_schema = merged_by_key[("PUT", "/api/ipfliter/autorecordipconf")].request_body_schema
    if not isinstance(autorecord_schema, dict) or autorecord_schema.get("properties", {}).get(
        "BasicPassword"
    ) != {"type": "string"}:
        fail("IPFilter AutoRecord request schema regressed")
    porttrap_schema = merged_by_key[("PUT", "/api/ipfliter/porttrapconf")].request_body_schema
    if not isinstance(porttrap_schema, dict) or porttrap_schema.get("properties", {}).get(
        "AllowRuleKeys"
    ) != {"type": "array", "items": {"type": "string"}}:
        fail("IPFilter PortTrap request schema regressed")

    def schema_property_names(schema: object) -> set[str]:
        if isinstance(schema, list):
            names: set[str] = set()
            for entry in schema:
                names.update(schema_property_names(entry))
            return names
        if not isinstance(schema, dict):
            return set()
        names = set(schema.get("properties", {})) if isinstance(schema.get("properties"), dict) else set()
        for value in schema.values():
            if isinstance(value, (dict, list)):
                names.update(schema_property_names(value))
        return names

    ssl_setting_response = merged_by_key[("GET", "/api/ssl/setting")].response_schema
    if not isinstance(ssl_setting_response, dict):
        fail("SSL settings response schema is missing")
    ssl_setting_props = ssl_setting_response.get("properties", {})
    if ssl_setting_props.get("syncClientList") != {
        "type": ["array", "null"],
        "items": {},
    }:
        fail("SSL syncClientList response schema regressed")
    certificate_check_time = ssl_setting_props.get("certificateCheckTime", {})
    if not isinstance(certificate_check_time, dict) or "syncClientList" in certificate_check_time.get(
        "properties", {}
    ):
        fail("SSL syncClientList must remain a top-level settings response field")

    sensitive_response_fields = {
        ("GET", "/api/ssl"): {
            "CertBase64",
            "KeyBase64",
            "IssuerCertificate",
            "acmeDNSSecret",
            "acmeHMAC",
            "preACMEHMAC",
            "acmeProxyPassword",
            "prePrivateKeyBase64",
        },
        ("GET", "/api/ssl/setting"): {"globalPrivateKey"},
        ("GET", "/api/ssl/credential-sources"): {"secretValue", "proxyPassword"},
        ("GET", "/api/ssl/{param}"): {
            "CertBase64",
            "KeyBase64",
            "IssuerCertificate",
            "acmeDNSSecret",
            "acmeHMAC",
            "preACMEHMAC",
            "acmeProxyPassword",
            "prePrivateKeyBase64",
        },
        ("GET", "/api/ipfliter/porttrapconf"): {"WebhookProxyPassword"},
        ("GET", "/api/ipfliter/autorecordipconf"): {"BasicPassword"},
        ("GET", "/api/cron/list"): {
            "Jobs",
            "IOT_DianDeng_AUTHKEY",
            "IOT_Bemfa_SecretKey",
            "IOTDianDengClientMsg",
            "IOTBemfaClientMsg",
        },
        ("GET", "/api/stun/configure"): {"WebhookProxyPassword"},
        ("GET", "/api/stun/{param}"): {
            "Options",
            "WebhookProxyPassword",
            "WebhookURL",
            "WebhookHeaders",
            "WebhookRequestBody",
            "UpnPDiyControlAPIUrl",
            "CallScriptContent",
            "TCPStreamEncryptionKey",
            "UDPPacketEncryptionKey",
        },
        ("GET", "/api/ddns/configure"): {"WebhookProxyPassword"},
        ("GET", "/api/ddns/credential-sources"): {"secretValue", "proxyPassword"},
        ("GET", "/api/ddns/task/{param}"): {"Secret", "HttpClientProxyPassword", "WebhookProxyPassword"},
        ("GET", "/api/frp/list/{param}"): {"ConfigText"},
        ("GET", "/api/rclone/remote/{param}"): {
            "Params",
            "Root",
            "HttpClientProxyAddr",
            "HttpClientProxyUser",
            "HttpClientProxyPassword",
            "ProxyPasswd",
            "MountPoint",
            "DeviceName",
            "VolumeName",
            "ExtraOptions",
            "ExtraFlags",
        },
        ("GET", "/api/rclone/sync/{param}"): {
            "SourceRemoteKey",
            "SourcePath",
            "DestRemoteKey",
            "DestPath",
            "IncludePatterns",
            "ExcludePatterns",
            "ExtraArgs",
        },
        ("GET", "/api/wol/service/configure"): {
            "Token",
            "QuickControlSafeURL",
            "QuickControlBasicAuthPasswd",
            "WebhookProxyPassword",
        },
        ("GET", "/api/thirdPartyAuthManager/list"): {"RefreshToken", "AccessToken", "TwoFAKey"},
        ("GET", "/api/thirdPartyAuthManager/list/{param}"): {"RefreshToken", "AccessToken", "TwoFAKey"},
        ("GET", "/api/third/filebrowser/configure"): {"RedisCacheUrl"},
        ("GET", "/api/status/host-processes"): {"command"},
        ("GET", "/api/modules/list"): {"baseURL"},
    }
    for route_key, forbidden in sensitive_response_fields.items():
        response_schema = merged_by_key[route_key].response_schema
        if not isinstance(response_schema, dict):
            fail(f"protected response schema missing for {route_key}")
        leaked = schema_property_names(response_schema) & forbidden
        if leaked:
            fail(f"sensitive response fields leaked into documented schema for {route_key}: {sorted(leaked)}")

    docker_create = merged_by_key[("POST", "/api/docker/containers")].request_body_schema
    if not isinstance(docker_create, dict):
        fail("Docker create-container request schema is missing")
    docker_host_props = docker_create.get("properties", {}).get("hostConfig", {}).get("properties", {})
    restart_policy = docker_host_props.get("RestartPolicy", {}).get("properties", {})
    if restart_policy.get("Name") != {"type": "string"} or restart_policy.get(
        "MaximumRetryCount"
    ) != {"type": "integer"}:
        fail("Docker RestartPolicy nested schema regressed")
    if docker_host_props.get("Mounts", {}).get("items", {}).get("properties", {}).get(
        "ReadOnly"
    ) != {"type": "boolean"}:
        fail("Docker Mounts nested schema regressed")

    frp_proxy = merged_by_key[("POST", "/api/frp/{param}/proxies")].request_body_schema
    if not isinstance(frp_proxy, dict):
        fail("FRP proxy request schema is missing")
    frp_props = frp_proxy.get("properties", {})
    if frp_props.get("healthCheckType", {}).get("enum") != ["tcp", "http"]:
        fail("FRP health-check enum evidence regressed")
    if (
        frp_props.get("natTraversal", {})
        .get("properties", {})
        .get("disableAssistedAddrs")
        != {"type": "boolean"}
    ):
        fail("FRP natTraversal nested schema regressed")

    frp_ret_only = {"type": "object", "properties": {"ret": {"type": "integer"}}}
    for route_key in {
        ("POST", "/api/frp/list"),
        ("PUT", "/api/frp/list"),
        ("DELETE", "/api/frp/list/{param}"),
    }:
        if merged_by_key[route_key].response_schema != frp_ret_only:
            fail(f"FRP disposable instance ret-only response schema regressed for {route_key}")

    frp_toggle = merged_by_key[("GET", "/api/frp/list/{param}/{param2}")]
    if frp_toggle.risk is not OperationRisk.MUTATING:
        fail("FRP enable/disable GET must remain classified as mutating")
    if frp_toggle.response_schema != frp_ret_only:
        fail("FRP enable/disable GET ret-only response schema regressed")

    expected_frp_list = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "list": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "Key": {"type": "string"},
                        "Remark": {"type": "string"},
                        "Type": {"type": "string"},
                        "ConfigMode": {"type": "string"},
                        "Enable": {"type": "boolean"},
                        "Running": {"type": "boolean"},
                        "RunErrorMsg": {"type": "string"},
                        "ServerAddr": {"type": "string"},
                        "ProxyCount": {"type": "integer"},
                        "VisitorCount": {"type": "integer"},
                    },
                },
            },
        },
    }
    if merged_by_key[("GET", "/api/frp/list")].response_schema != expected_frp_list:
        fail("FRP disposable list summary schema regressed")

    expected_frp_detail = {
        "type": "object",
        "properties": {
            "instance": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Enable": {"type": "boolean"},
                    "Remark": {"type": "string"},
                    "Type": {"type": "string"},
                    "ConfigMode": {"type": "string"},
                    "Params": {"type": ["object", "null"]},
                },
            },
            "ret": {"type": "integer"},
        },
    }
    if merged_by_key[("GET", "/api/frp/list/{param}")].response_schema != expected_frp_detail:
        fail("FRP disposable detail response schema regressed")

    expected_frp_status = {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "status": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "remark": {"type": "string"},
                    "type": {"type": "string"},
                    "running": {"type": "boolean"},
                    "enable": {"type": "boolean"},
                    "serverAddr": {"type": "string"},
                    "proxyCount": {"type": "integer"},
                    "visitorCount": {"type": "integer"},
                },
            },
        },
    }
    if merged_by_key[("GET", "/api/frp/{param}/status")].response_schema != expected_frp_status:
        fail("FRP disabled-client status response schema regressed")

    nullable_untyped_array = {"type": ["array", "null"], "items": {}}
    nullable_log_array = {
        "type": ["array", "null"],
        "items": {
            "type": "object",
            "properties": {
                "LogContent": {"type": "string"},
                "LogTime": {"type": "string"},
                "ShowTime": {"type": "boolean"},
                "Level": {"type": "string"},
            },
        },
    }
    frp_read_schemas = {
        ("GET", "/api/frp/{param}/lastlogs"): {
            "type": "object", "properties": {"lastLogs": nullable_log_array, "ret": {"type": "integer"}}
        },
        ("GET", "/api/frp/{param}/logs"): {
            "type": "object",
            "properties": {
                "logs": nullable_log_array,
                "page": {"type": "integer"},
                "pageSize": {"type": "integer"},
                "ret": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        ("GET", "/api/frp/{param}/proxies"): {
            "type": "object", "properties": {"proxies": nullable_untyped_array, "ret": {"type": "integer"}}
        },
    }
    for route_key, expected_schema in frp_read_schemas.items():
        if merged_by_key[route_key].response_schema != expected_schema:
            fail(f"FRP disposable read response schema regressed for {route_key}")

    expected_frp_visitor_item = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "type": {"type": "string"},
            "disabled": {"type": "boolean"},
            "serverName": {"type": "string"},
            "bindAddr": {"type": "string"},
            "bindPort": {"type": "integer"},
            "maxRetriesAnHour": {"type": "integer"},
            "minRetryInterval": {"type": "integer"},
            "protocol": {"type": "string"},
            "transport": {
                "type": "object",
                "properties": {
                    "useEncryption": {"type": "boolean"},
                    "useCompression": {"type": "boolean"},
                },
            },
            "natTraversal": {
                "type": "object",
                "properties": {"disableAssistedAddrs": {"type": "boolean"}},
            },
            "plugin": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "destinationIP": {"type": "string"},
                },
            },
        },
    }
    frp_visitor_get = patched_by_key[("GET", "/api/frp/{param}/visitors")]
    if frp_visitor_get.response_schema != {
        "type": "object",
        "properties": {
            "ret": {"type": "integer"},
            "visitors": {"type": ["array", "null"], "items": expected_frp_visitor_item},
        },
    }:
        fail("FRP visitor runtime readback schema regressed")
    if frp_visitor_get.confidence != "runtime-verified":
        fail("FRP visitor GET must remain runtime-verified")
    for route_key in {
        ("POST", "/api/frp/{param}/visitors"),
        ("PUT", "/api/frp/{param}/visitors"),
        ("DELETE", "/api/frp/{param}/visitors/{param2}"),
    }:
        route = merged_by_key[route_key]
        if route.response_schema != ret_only_schema:
            fail(f"FRP visitor ret-only response schema regressed for {route_key}")
        if route.confidence != "runtime-verified":
            fail(f"FRP visitor route must remain runtime-verified for {route_key}")


def check_generated_artifacts() -> None:
    snapshot_path = ROOT / "evidence" / "lucky-v3-endpoints.json"
    openapi_path = ROOT / "openapi" / "lucky-v3.openapi.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    openapi = json.loads(openapi_path.read_text(encoding="utf-8"))
    check_runtime_verification(snapshot_path, snapshot)
    runtime_path = snapshot_path.with_name("lucky-v3-runtime-verification.json")
    merged_snapshot = load_merged_snapshot(snapshot_path, runtime_verification=runtime_path)
    if snapshot["route_count"] != len(snapshot["routes"]):
        fail("snapshot route_count does not match routes")
    if snapshot["bundle_count"] != len(snapshot["bundle_sha256"]):
        fail("snapshot bundle_count does not match bundle hashes")
    route_keys = [(item["path"], item["method"]) for item in snapshot["routes"]]
    if len(route_keys) != len(set(route_keys)):
        fail("snapshot contains duplicate path/method routes")
    for item in snapshot["routes"]:
        if not item["path"].startswith("/api/"):
            fail(f"snapshot contains invalid API path: {item['path']}")
        if item["method"] not in {"GET", "POST", "PUT", "DELETE", "PATCH", "UNKNOWN"}:
            fail(f"snapshot contains invalid HTTP method: {item['method']}")
    if openapi.get("openapi") != "3.1.0":
        fail("OpenAPI document is not 3.1.0")
    if openapi["components"]["securitySchemes"]["OpenToken"]["name"] != "openToken":
        fail("OpenAPI security header is incorrect")
    for server in openapi.get("servers", []):
        if "{safeEntry}" not in server["url"]:
            fail("OpenAPI server URL must use the safeEntry placeholder")
        if server.get("variables", {}).get("safeEntry", {}).get("default") != "your-safe-entry":
            fail("OpenAPI safeEntry default must remain a non-live placeholder")
    documented = {
        (path, method.upper())
        for path, item in openapi["paths"].items()
        for method in item
        if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}
    }
    inferred = {
        (item["path"], item["method"])
        for item in merged_snapshot["routes"]
        if item["method"] != "UNKNOWN"
    }
    if documented != inferred:
        fail("OpenAPI paths are out of sync with the endpoint snapshot")
    operation_ids = [
        operation["operationId"]
        for item in openapi["paths"].values()
        for method, operation in item.items()
        if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}
    ]
    if len(operation_ids) != len(set(operation_ids)):
        fail("OpenAPI operationId values are not unique")
    with tempfile.TemporaryDirectory() as directory:
        generated_markdown = Path(directory) / "api-routes.md"
        generated_openapi = Path(directory) / "lucky-v3.openapi.json"
        write_markdown(merged_snapshot, generated_markdown)
        write_openapi(merged_snapshot, generated_openapi)
        committed_markdown = ROOT / "docs" / "generated" / "api-routes.md"
        if generated_markdown.read_bytes() != committed_markdown.read_bytes():
            fail("generated API route Markdown is stale")
        if generated_openapi.read_bytes() != openapi_path.read_bytes():
            fail("generated OpenAPI document is stale")


def main() -> None:
    check_secrets()
    check_local_links()
    check_skill_packaging()
    check_generated_artifacts()
    print("repository verification passed")


if __name__ == "__main__":
    main()
