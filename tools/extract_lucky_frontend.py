#!/usr/bin/env python3
"""Extract a best-effort Lucky API inventory from built frontend JavaScript.

The script stores derived route metadata only. It never copies the frontend
bundles into the repository and it does not need an OpenToken.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from lucky_api.catalog import classify_known_operation


URL_CALL_RE = re.compile(
    r"url\s*:\s*(?P<expr>(?:(?!,\s*method\s*:).){1,600}?),\s*"
    r"method\s*:\s*[\"'](?P<method>get|post|put|delete|patch)[\"']",
    re.IGNORECASE | re.DOTALL,
)
DIRECT_METHOD_CALL_RE = re.compile(
    r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\."
    r"(?P<method>get|post|put|delete|patch)\(\s*"
    r"(?P<expr>`(?:\\.|[^`]){1,600}`|\"(?:\\.|[^\"]){1,600}\"|'(?:\\.|[^']){1,600}')",
    re.IGNORECASE | re.DOTALL,
)
ROUTE_LITERAL_RE = re.compile(r"/api/[A-Za-z0-9_./${}:-]+")
PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")
KEY_RE = re.compile(r"(?:^|,)\s*([A-Za-z_$][\w$-]*)\s*:")


def split_top_level_plus(expression: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    depth = 0
    for index, char in enumerate(expression):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "+" and depth == 0:
            parts.append(expression[start:index].strip())
            start = index + 1
    parts.append(expression[start:].strip())
    return [part for part in parts if part]


def placeholder_name(raw: str, number: int) -> str:
    identifiers = re.findall(r"[A-Za-z_$][\w$]*", raw)
    ignored = {"encodeURIComponent", "String", "Number"}
    identifiers = [item for item in identifiers if item not in ignored]
    candidate = identifiers[-1] if identifiers else "param"
    if len(candidate) <= 2 or candidate.startswith("_"):
        candidate = "param"
    return candidate if number == 1 else f"{candidate}{number}"


def normalize_path_expression(expression: str) -> str | None:
    expression = expression.strip()
    if expression.startswith("`") and expression.endswith("`"):
        body = expression[1:-1]
        counter = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal counter
            counter += 1
            return "{" + placeholder_name(match.group(1), counter) + "}"

        path = PLACEHOLDER_RE.sub(replace, body)
    else:
        pieces: list[str] = []
        dynamic_count = 0
        for part in split_top_level_plus(expression):
            if len(part) >= 2 and part[0] in "'\"`" and part[-1] == part[0]:
                literal = part[1:-1]
                if part[0] == "`":
                    literal = PLACEHOLDER_RE.sub("{param}", literal)
                pieces.append(literal)
            else:
                dynamic_count += 1
                pieces.append("{" + placeholder_name(part, dynamic_count) + "}")
        path = "".join(pieces)
    if not path.startswith("/api/"):
        return None
    path = re.sub(r"/{2,}", "/", path)
    return path.rstrip("/") or "/api"


def normalize_direct_method_path(expression: str) -> str | None:
    """Normalize a literal/template first argument from ``client.post(...)``.

    Lucky's current frontend occasionally bypasses the shared ``{url,method}``
    wrapper and calls Axios directly with a runtime base prefix, for example
    ``client.post(`${base}api/docker/images/upload-temp`, ...)``.  Keep this
    parser deliberately conservative: the first argument must itself be a
    quoted string/template and must contain a statically visible ``api/``
    segment.  Everything before that segment is discarded as the HTTP base.
    """

    expression = expression.strip()
    if len(expression) < 2 or expression[0] not in "'\"`" or expression[-1] != expression[0]:
        return None
    body = expression[1:-1]
    marker = "/api/"
    index = body.find(marker)
    if index < 0:
        marker = "api/"
        index = body.find(marker)
        if index < 0:
            return None
        if index > 0 and body[index - 1] not in "}/":
            return None
    path_expr = body[index:]
    if not path_expr.startswith("/"):
        path_expr = "/" + path_expr
    placeholder_index = 0

    def replace_direct_placeholder(_match: re.Match[str]) -> str:
        nonlocal placeholder_index
        placeholder_index += 1
        name = "param" if placeholder_index == 1 else f"param{placeholder_index}"
        return "{" + name + "}"

    path_expr = PLACEHOLDER_RE.sub(replace_direct_placeholder, path_expr)
    quote = "`" if "${" in path_expr else '"'
    return normalize_path_expression(f"{quote}{path_expr}{quote}")


def object_keys(snippet: str, field: str) -> list[str]:
    match = re.search(rf"\b{re.escape(field)}\s*:\s*\{{([^{{}}]{{0,500}})\}}", snippet)
    if not match:
        return []
    return sorted(set(KEY_RE.findall(match.group(1))))


def route_module(path: str) -> str:
    parts = path.split("/")
    return parts[2] if len(parts) > 2 else "core"


def matching_brace(text: str, start: int) -> int | None:
    if start < 0 or text[start] != "{":
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, min(len(text), start + 2500)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def matching_paren(text: str, start: int) -> int | None:
    """Return the closing parenthesis for one JavaScript call expression.

    Direct Axios calls may sit immediately next to unrelated requests in a
    minified bundle.  Metadata such as ``multipart/form-data`` must therefore
    be inferred from the current call only, not from an arbitrary trailing
    character window.  This scanner is intentionally small but quote-aware so
    parentheses inside strings/templates do not terminate the call early.
    """

    if start < 0 or text[start] != "(":
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, min(len(text), start + 12000)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def extract(assets_dir: Path, version: str) -> dict:
    routes: dict[tuple[str, str], dict] = {}
    route_only: dict[str, set[str]] = defaultdict(set)
    bundle_hashes: dict[str, str] = {}

    files = sorted(assets_dir.glob("*.js"))
    if not files:
        raise SystemExit(f"no JavaScript bundles found in {assets_dir}")

    for file_path in files:
        raw = file_path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        bundle_hashes[file_path.name] = hashlib.sha256(raw).hexdigest()
        for match in URL_CALL_RE.finditer(text):
            path = normalize_path_expression(match.group("expr"))
            if not path:
                continue
            method = match.group("method").upper()
            object_start = text.rfind("{", max(0, match.start() - 180), match.start())
            object_end = matching_brace(text, object_start)
            if object_end is not None and object_end >= match.end():
                snippet = text[object_start : object_end + 1]
            else:
                snippet = text[match.start() : min(len(text), match.end() + 220)]
            key = (path, method)
            item = routes.setdefault(
                key,
                {
                    "path": path,
                    "method": method,
                    "module": route_module(path),
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": False,
                    "response_type": "json",
                    "evidence": [],
                    "confidence": "frontend-call",
                },
            )
            item["query_keys"] = sorted(
                set(item["query_keys"]) | set(object_keys(snippet, "params"))
            )
            body_match = re.search(r"\bdata\s*:\s*([^,})]+|\{[^{}]{0,500}\})", snippet)
            if body_match:
                item["has_body"] = True
                item["body_keys"] = sorted(
                    set(item["body_keys"]) | set(object_keys(snippet, "data"))
                )
            response_match = re.search(r"responseType\s*:\s*[\"']([^\"']+)", snippet)
            if response_match:
                item["response_type"] = response_match.group(1)
            if file_path.name not in item["evidence"]:
                item["evidence"].append(file_path.name)

        for match in DIRECT_METHOD_CALL_RE.finditer(text):
            path = normalize_direct_method_path(match.group("expr"))
            if not path:
                continue
            method = match.group("method").upper()
            key = (path, method)
            item = routes.setdefault(
                key,
                {
                    "path": path,
                    "method": method,
                    "module": route_module(path),
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": method in {"POST", "PUT", "PATCH"},
                    "response_type": "json",
                    "evidence": [],
                    "confidence": "frontend-call",
                },
            )
            if method in {"POST", "PUT", "PATCH"}:
                item["has_body"] = True
            call_start = text.find("(", match.start(), match.end())
            call_end = matching_paren(text, call_start)
            if call_end is not None and call_end >= match.end():
                snippet = text[match.start() : call_end + 1]
            else:
                snippet = text[match.start() : min(len(text), match.end() + 220)]
            if "multipart/form-data" in snippet:
                item["request_content_type"] = "multipart/form-data"
            if file_path.name not in item["evidence"]:
                item["evidence"].append(file_path.name)

        for literal in ROUTE_LITERAL_RE.findall(text):
            literal = literal.rstrip(".,;:/")
            if literal in {"/api", "/api/."} or re.match(r"^/api/\d", literal):
                continue
            if "${" in literal:
                continue
            literal = PLACEHOLDER_RE.sub("{param}", literal)
            route_only[literal].add(file_path.name)

    known_paths = {item["path"] for item in routes.values()}
    for path, evidence in sorted(route_only.items()):
        if path in known_paths:
            continue
        # Keep literal-only evidence conservative. A parent literal and a
        # method-bearing descendant can legitimately coexist in one bundle;
        # only the version-bound runtime verification layer may suppress a
        # literal after the target instance has been checked.
        routes[(path, "UNKNOWN")] = {
            "path": path,
            "method": "UNKNOWN",
            "module": route_module(path),
            "query_keys": [],
            "body_keys": [],
            "has_body": False,
            "response_type": "unknown",
            "evidence": sorted(evidence),
            "confidence": "route-literal-only",
        }

    route_list = sorted(routes.values(), key=lambda item: (item["module"], item["path"], item["method"]))
    return {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "target": {"product": "Lucky", "version": version},
        "methodology": "Static analysis of locally served, built frontend JavaScript bundles.",
        "bundle_count": len(files),
        "bundle_sha256": bundle_hashes,
        "route_count": len(route_list),
        "routes": route_list,
    }


def write_markdown(snapshot: dict, output: Path) -> None:
    groups: dict[str, list[dict]] = defaultdict(list)
    for route in snapshot["routes"]:
        groups[route["module"]].append(route)
    lines = [
        "---",
        "pageClass: api-routes-page",
        "---",
        "",
        "# API 路由参考",
        "",
        f"> 目标版本：Lucky {snapshot['target']['version']}。共收录 {snapshot['route_count']} 个“路径 + 方法”记录。",
        "> 此表由前端构建产物静态证据与可选的版本绑定运行时验证合并生成，不代表上游承诺的稳定公共 API；`UNKNOWN` 表示仍只有路径字面量证据。",
        "",
    ]
    for module in sorted(groups):
        lines.extend(
            [
                f"## `{module}`",
                "",
                "| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for route in groups[module]:
            query = ", ".join(f"`{key}`" for key in route["query_keys"]) or "—"
            if route["body_keys"]:
                body = ", ".join(f"`{key}`" for key in route["body_keys"])
            elif isinstance(route.get("request_body_schema"), dict):
                schema = route["request_body_schema"]
                if schema.get("type") == "array":
                    item_type = schema.get("items", {}).get("type", "any")
                    body = f"`array<{item_type}>`"
                elif schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
                    keys = list(schema["properties"])
                    body = ", ".join(f"`{key}`" for key in keys) or "`object`"
                else:
                    body = f"`{schema.get('type', 'schema')}`"
            else:
                body = "有" if route["has_body"] else "—"
            risk = route.get("risk") or (
                "unknown"
                if route["method"] == "UNKNOWN"
                else classify_known_operation(route["method"], route["path"]).value
            )
            lines.append(
                f"| `{route['method']}` | `{route['path']}` | `{risk}` | {query} | {body} | "
                f"`{route['response_type']}` | `{route['confidence']}` |"
            )
        lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def write_openapi(snapshot: dict, output: Path) -> None:
    paths: dict[str, dict] = {}
    for route in snapshot["routes"]:
        if route["method"] == "UNKNOWN":
            continue
        operation = {
            "summary": f"Lucky frontend call: {route['method']} {route['path']}",
            "description": "Reverse-documented from frontend and optional runtime evidence; schemas may still be incomplete.",
            "operationId": operation_id(route["method"], route["path"]),
            "tags": [route["module"]],
            "security": [{"OpenToken": []}],
            "responses": response_spec(route),
            "x-evidence-confidence": route["confidence"],
            "x-evidence-bundles": route.get("evidence", []),
            "x-lucky-risk": route.get("risk") or classify_known_operation(route["method"], route["path"]).value,
        }
        if route.get("schema_evidence"):
            operation["x-schema-evidence"] = route["schema_evidence"]
        if route.get("success_response_markers"):
            operation["x-lucky-success-response-markers"] = route["success_response_markers"]
        parameters = []
        for name in re.findall(r"\{([^}]+)\}", route["path"]):
            parameters.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
        for name in route["query_keys"]:
            parameters.append({"name": name, "in": "query", "required": False, "schema": {}})
        if parameters:
            operation["parameters"] = parameters
        if route["has_body"]:
            schema = route.get("request_body_schema")
            if not isinstance(schema, dict):
                properties = {name: {} for name in route["body_keys"]}
                schema = {"type": "object", "properties": properties}
            content_type = route.get("request_content_type") or "application/json"
            operation["requestBody"] = {
                "required": True,
                "content": {content_type: {"schema": schema}},
            }
        paths.setdefault(route["path"], {})[route["method"].lower()] = operation
    document = {
        "openapi": "3.1.0",
        "info": {
            "title": "Lucky OpenToken API (unofficial)",
            "version": snapshot["target"]["version"],
            "description": "Reverse-documented, best-effort API inventory. Not an upstream compatibility promise.",
        },
        "servers": [
            {
                "url": "http://127.0.0.1:16601/{safeEntry}",
                "variables": {"safeEntry": {"default": "your-safe-entry", "description": "Lucky 安全入口，不含前导斜杠。"}},
            }
        ],
        "security": [{"OpenToken": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"OpenToken": {"type": "apiKey", "in": "header", "name": "openToken"}},
            "schemas": {
                "LuckyEnvelope": {
                    "type": "object",
                    "properties": {
                        "ret": {
                            "type": "integer",
                            "description": "0 usually means success; runtime-verified endpoint extensions may declare exact additional success response markers.",
                        },
                        "msg": {"type": "string"},
                        "data": {},
                    },
                    "additionalProperties": True,
                }
            },
        },
    }
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def operation_id(method: str, path: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "_", path.strip("/"))
    return f"{method.lower()}_{clean}".strip("_")


def response_spec(route: dict) -> dict:
    if isinstance(route.get("response_schema"), dict):
        content = {"application/json": {"schema": route["response_schema"]}}
        description = "Response schema observed from runtime evidence; see x-schema-evidence for provenance."
    elif route["response_type"] in {"blob", "arraybuffer"}:
        content_type = route.get("response_content_type") or "application/octet-stream"
        content = {
            content_type: {
                "schema": {"type": "string", "format": "binary"}
            }
        }
        description = (
            "Binary response with runtime-verified media type."
            if route.get("response_content_type")
            else "Binary download inferred from the frontend responseType."
        )
    else:
        content = {"application/json": {"schema": {"$ref": "#/components/schemas/LuckyEnvelope"}}}
        description = "Lucky JSON response; envelope shape varies by endpoint."
    return {
        "200": {"description": description, "content": content},
        "default": {
            "description": "HTTP error or a Lucky business error (which may also use HTTP 200).",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LuckyEnvelope"}}},
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("assets_dir", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--openapi", type=Path)
    args = parser.parse_args()
    snapshot = extract(args.assets_dir, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(snapshot, args.markdown)
    if args.openapi:
        args.openapi.parent.mkdir(parents=True, exist_ok=True)
        write_openapi(snapshot, args.openapi)


if __name__ == "__main__":
    main()
