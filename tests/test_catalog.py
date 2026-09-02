from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from lucky_api import OperationRisk, RouteCatalog
from lucky_api.catalog import CatalogError


class RuntimeVerificationTests(unittest.TestCase):
    def test_runtime_schema_patch_only_replaces_empty_response_schema_leaf(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [
                {
                    "path": "/api/example",
                    "method": "GET",
                    "module": "example",
                    "response_type": "json",
                    "response_schema": {
                        "type": "object",
                        "properties": {"items": {"type": "array", "items": {}}},
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            verification = {
                "schema_version": 1,
                "target": {"product": "Lucky", "version": "3.0.0"},
                "static_snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                "suppress_literals": [],
                "routes": [],
                "schema_patches": [
                    {
                        "path": "/api/example",
                        "method": "GET",
                        "at": ["properties", "items", "items"],
                        "value": {"type": "string"},
                        "evidence": "fixture evidence",
                    }
                ],
            }
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            catalog = RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)
            route = catalog.match("GET", "/api/example")
            self.assertEqual(
                route.response_schema["properties"]["items"]["items"],  # type: ignore[index,union-attr]
                {"type": "string"},
            )

            verification["schema_patches"][0]["at"] = ["properties", "items"]
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            with self.assertRaises(CatalogError):
                RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)

    def test_runtime_verification_suppresses_literals_and_overrides_risk(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [
                {
                    "path": "/api/configure",
                    "method": "UNKNOWN",
                    "module": "configure",
                    "confidence": "route-literal-only",
                },
                {
                    "path": "/api/prefix",
                    "method": "UNKNOWN",
                    "module": "prefix",
                    "confidence": "route-literal-only",
                },
                {
                    "path": "/api/prefix/{param}",
                    "method": "GET",
                    "module": "prefix",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/method-only",
                    "method": "GET",
                    "module": "method-only",
                    "confidence": "frontend-call",
                },
            ],
        }
        verification = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "suppress_literals": ["/api/prefix"],
            "routes": [
                {
                    "path": "/api/configure",
                    "method": "GET",
                    "risk": "dangerous",
                    "response_type": "blob",
                    "confidence": "runtime-verified",
                },
                {
                    "path": "/api/configure",
                    "method": "POST",
                    "risk": "dangerous",
                    "confidence": "runtime-verified",
                },
                {
                    "path": "/api/prefix/{param}",
                    "method": "GET",
                    "risk": "read-only",
                },
            ],
            "route_method_ci_evidence": {
                "routes": ["GET /api/method-only"],
                "route_response_routes": [],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            verification["static_snapshot_sha256"] = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            catalog = RouteCatalog.from_file(
                snapshot_path,
                runtime_verification=runtime_path,
            )

        self.assertEqual(catalog.search(risk=OperationRisk.UNKNOWN), [])
        configure = catalog.match("GET", "/api/configure")
        self.assertIsNotNone(configure)
        self.assertEqual(configure.confidence, "runtime-verified")  # type: ignore[union-attr]
        self.assertEqual(configure.response_type, "blob")  # type: ignore[union-attr]
        self.assertEqual(configure.risk, OperationRisk.DANGEROUS)  # type: ignore[union-attr]
        self.assertEqual(
            catalog.classify("POST", "/api/configure"),
            OperationRisk.DANGEROUS,
        )
        prefixed = catalog.match("GET", "/api/prefix/value")
        self.assertIsNotNone(prefixed)
        self.assertEqual(prefixed.confidence, "runtime-verified")  # type: ignore[union-attr]
        method_only = catalog.match("GET", "/api/method-only")
        self.assertIsNotNone(method_only)
        self.assertEqual(method_only.confidence, "runtime-verified")  # type: ignore[union-attr]

    def test_static_catalog_keeps_verified_toggle_gets_mutating_without_runtime_sidecar(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [
                {
                    "path": "/api/cloudflared/list/{param}/{param2}",
                    "method": "GET",
                    "module": "cloudflared",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/coraza/list/{param}/{param2}",
                    "method": "GET",
                    "module": "coraza",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/frp/list/{param}/{param2}",
                    "method": "GET",
                    "module": "frp",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/ipfliter/list/{param}/{param2}/{param3}",
                    "method": "GET",
                    "module": "ipfliter",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/rclone/remotelist/option",
                    "method": "GET",
                    "module": "rclone",
                    "confidence": "frontend-call",
                },
                {
                    "path": "/api/rclone/sync/option",
                    "method": "GET",
                    "module": "rclone",
                    "confidence": "frontend-call",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            catalog = RouteCatalog.from_file(snapshot_path)

        for path in {
            "/api/cloudflared/list/tunnel-key/false",
            "/api/coraza/list/waf-key/true",
            "/api/frp/list/client-key/false",
            "/api/ipfliter/list/rule-key/subrule-key/true",
            "/api/rclone/remotelist/option",
            "/api/rclone/sync/option",
        }:
            self.assertEqual(catalog.classify("GET", path), OperationRisk.MUTATING)

    def test_runtime_verification_rejects_different_same_version_snapshot(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [],
        }
        verification = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "static_snapshot_sha256": "0" * 64,
            "suppress_literals": [],
            "routes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            with self.assertRaises(CatalogError):
                RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)

    def test_runtime_route_must_be_backed_by_static_evidence(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            verification = {
                "schema_version": 1,
                "target": {"product": "Lucky", "version": "3.0.0"},
                "static_snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                "suppress_literals": [],
                "routes": [
                    {
                        "path": "/api/not-in-static-snapshot",
                        "method": "GET",
                        "risk": "read-only",
                    }
                ],
            }
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            with self.assertRaises(CatalogError):
                RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)

    def test_suppression_must_target_static_unknown_evidence(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [
                {"path": "/api/status", "method": "GET", "module": "status"}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            verification = {
                "schema_version": 1,
                "target": {"product": "Lucky", "version": "3.0.0"},
                "static_snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                "suppress_literals": ["/api/status"],
                "routes": [],
            }
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            with self.assertRaises(CatalogError):
                RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)

    def test_malformed_static_routes_raise_catalog_error(self) -> None:
        for routes in (["nope"], [{"module": "missing-path-and-method"}]):
            with self.subTest(routes=routes), tempfile.TemporaryDirectory() as directory:
                snapshot = {
                    "schema_version": 1,
                    "target": {"product": "Lucky", "version": "3.0.0"},
                    "routes": routes,
                }
                snapshot_path = Path(directory) / "snapshot.json"
                runtime_path = Path(directory) / "runtime.json"
                snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
                verification = {
                    "schema_version": 1,
                    "target": {"product": "Lucky", "version": "3.0.0"},
                    "static_snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                    "suppress_literals": [],
                    "routes": [],
                }
                runtime_path.write_text(json.dumps(verification), encoding="utf-8")
                with self.assertRaises(CatalogError):
                    RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)

    def test_runtime_schema_metadata_merges_into_static_route(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [
                {
                    "path": "/api/order",
                    "method": "PUT",
                    "module": "order",
                    "confidence": "frontend-call",
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": True,
                    "response_type": "json",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            verification = {
                "schema_version": 1,
                "target": {"product": "Lucky", "version": "3.0.0"},
                "static_snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                "suppress_literals": [],
                "routes": [
                    {
                        "path": "/api/order",
                        "method": "PUT",
                        "risk": "mutating",
                        "request_body_schema": {"type": "array", "items": {"type": "string"}},
                        "request_content_type": "application/json",
                        "success_response_markers": [{"ret": 1, "msg": "success"}],
                        "schema_evidence": "frontend array mapping",
                    }
                ],
            }
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            catalog = RouteCatalog.from_file(snapshot_path, runtime_verification=runtime_path)
        route = catalog.match("PUT", "/api/order")
        self.assertIsNotNone(route)
        self.assertEqual(route.request_body_schema, {"type": "array", "items": {"type": "string"}})  # type: ignore[union-attr]
        self.assertEqual(route.request_content_type, "application/json")  # type: ignore[union-attr]
        self.assertEqual(route.schema_evidence, "frontend array mapping")  # type: ignore[union-attr]
        self.assertEqual(route.success_response_markers, ((1, "success"),))  # type: ignore[union-attr]
        self.assertIsInstance(hash(route), int)  # type: ignore[arg-type]
        self.assertEqual({route}, {route})  # type: ignore[arg-type]

    def test_runtime_verification_version_must_match_snapshot(self) -> None:
        snapshot = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.0"},
            "routes": [],
        }
        verification = {
            "schema_version": 1,
            "target": {"product": "Lucky", "version": "3.0.1"},
            "static_snapshot_sha256": "0" * 64,
            "suppress_literals": [],
            "routes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            runtime_path = Path(directory) / "runtime.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            runtime_path.write_text(json.dumps(verification), encoding="utf-8")
            with self.assertRaises(CatalogError):
                RouteCatalog.from_file(
                    snapshot_path,
                    runtime_verification=runtime_path,
                )


if __name__ == "__main__":
    unittest.main()
