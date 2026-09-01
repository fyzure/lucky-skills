from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.extract_lucky_frontend import extract, write_openapi


class ExtractorTests(unittest.TestCase):
    def test_fixture_methods_parameters_bodies_and_literal_route(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "frontend.js"
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "frontend.js").write_bytes(fixture.read_bytes())
            snapshot = extract(Path(directory), "test")
        routes = {(item["path"], item["method"]): item for item in snapshot["routes"]}
        containers = routes[("/api/docker/containers", "GET")]
        self.assertEqual(containers["query_keys"], ["all", "includeStats"])
        update = routes[("/api/ddns/task/{key}", "PUT")]
        self.assertTrue(update["has_body"])
        upload = routes[("/api/docker/images/upload-temp", "POST")]
        self.assertTrue(upload["has_body"])
        self.assertEqual(upload["request_content_type"], "multipart/form-data")
        direct_delete = routes[("/api/docker/images/{param}", "DELETE")]
        self.assertNotIn("request_content_type", direct_delete)
        self.assertIn(("/api/docker/compose/{param}/backups/upload", "POST"), routes)
        self.assertIn(("/api/ddns/task", "UNKNOWN"), routes)
        self.assertIn(("/api/status/ws", "UNKNOWN"), routes)
        self.assertEqual(snapshot["bundle_count"], 1)

    def test_openapi_uses_runtime_request_schema_and_content_type(self) -> None:
        snapshot = {
            "target": {"version": "test"},
            "route_count": 3,
            "routes": [
                {
                    "path": "/api/order",
                    "method": "PUT",
                    "module": "order",
                    "confidence": "runtime-verified",
                    "evidence": [],
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": True,
                    "response_type": "json",
                    "risk": "mutating",
                    "request_body_schema": {"type": "array", "items": {"type": "string"}},
                    "response_schema": {
                        "type": "object",
                        "properties": {"ret": {"type": "integer"}},
                    },
                    "schema_evidence": "frontend order mapping",
                },
                {
                    "path": "/api/import",
                    "method": "POST",
                    "module": "import",
                    "confidence": "runtime-verified",
                    "evidence": [],
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": True,
                    "response_type": "json",
                    "risk": "dangerous",
                    "request_content_type": "multipart/form-data",
                    "request_body_schema": {
                        "type": "object",
                        "properties": {"file": {"type": "string", "format": "binary"}},
                    },
                },
                {
                    "path": "/api/icon",
                    "method": "GET",
                    "module": "icon",
                    "confidence": "runtime-verified",
                    "evidence": [],
                    "query_keys": [],
                    "body_keys": [],
                    "has_body": False,
                    "response_type": "blob",
                    "response_content_type": "image/png",
                    "risk": "read-only",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "openapi.json"
            write_openapi(snapshot, output)
            document = json.loads(output.read_text(encoding="utf-8"))
        order = document["paths"]["/api/order"]["put"]
        self.assertEqual(
            order["requestBody"]["content"]["application/json"]["schema"],
            {"type": "array", "items": {"type": "string"}},
        )
        self.assertEqual(order["x-schema-evidence"], "frontend order mapping")
        self.assertEqual(
            order["responses"]["200"]["content"]["application/json"]["schema"],
            {"type": "object", "properties": {"ret": {"type": "integer"}}},
        )
        upload = document["paths"]["/api/import"]["post"]
        self.assertEqual(
            upload["requestBody"]["content"]["multipart/form-data"]["schema"]["properties"]["file"]["format"],
            "binary",
        )
        icon = document["paths"]["/api/icon"]["get"]
        self.assertEqual(
            icon["responses"]["200"]["content"]["image/png"]["schema"],
            {"type": "string", "format": "binary"},
        )


if __name__ == "__main__":
    unittest.main()
