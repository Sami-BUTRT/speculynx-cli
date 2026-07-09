import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import typer
from typer.testing import CliRunner
from unittest.mock import patch

from speculynx import main
from speculynx.scanner import load_openapi_file
from speculynx.scanner import run_audit


class OpenAPIVersionTests(unittest.TestCase):
    def load_document(self, document: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "openapi.json"
            file_path.write_text(json.dumps(document), encoding="utf-8")
            return load_openapi_file(file_path)

    def assert_document_rejected(self, document: dict) -> None:
        with redirect_stdout(StringIO()), self.assertRaises(typer.Exit) as raised:
            self.load_document(document)
        self.assertEqual(raised.exception.exit_code, 1)

    def test_accepts_openapi_3_0_0(self):
        document = self.load_document({"openapi": "3.0.0"})
        self.assertEqual(document["openapi"], "3.0.0")

    def test_accepts_openapi_3_0_3(self):
        document = self.load_document({"openapi": "3.0.3"})
        self.assertEqual(document["openapi"], "3.0.3")

    def test_accepts_openapi_3_1_0(self):
        document = self.load_document({"openapi": "3.1.0"})
        self.assertEqual(document["openapi"], "3.1.0")

    def test_rejects_swagger_2_0(self):
        self.assert_document_rejected({"swagger": "2.0"})

    def test_rejects_document_without_openapi_field(self):
        self.assert_document_rejected({"info": {"title": "Missing version"}})

    def test_rejects_openapi_2_0_0(self):
        self.assert_document_rejected({"openapi": "2.0.0"})


class FixtureScanTests(unittest.TestCase):
    def run_free_audit_for_document(self, document: dict) -> list:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "openapi.json"
            file_path.write_text(json.dumps(document), encoding="utf-8")
            return run_audit(file_path, is_pro=False)

    def get_rule(self, results: list, rule_id: str) -> dict:
        return next(r for r in results if r["id"] == rule_id)

    def test_scans_openapi_fixture_without_network_or_pro_license(self):
        fixture_path = Path(__file__).parent / "fixtures" / "api_test.yaml"

        results = run_audit(fixture_path, is_pro=False)

        self.assertEqual(
            ["KEY-EXP-01", "HTTP-001", "AUTH-001", "KEY-EXP-02"],
            [r["id"] for r in results],
        )
        self.assertFalse(results[0]["passed"])
        self.assertFalse(results[1]["passed"])
        self.assertFalse(results[2]["passed"])
        self.assertFalse(results[3]["passed"])

    def test_http_server_url_triggers_free_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "HTTP API", "version": "1.0.0"},
            "servers": [{"url": "http://api.example.test"}],
            "paths": {},
        })

        http_rule = self.get_rule(results, "HTTP-001")
        self.assertFalse(http_rule["passed"])
        self.assertEqual("HTTP non sécurisé", http_rule["name"])
        self.assertEqual("ÉLEVÉE", http_rule["severity"])

    def test_https_server_url_does_not_trigger_free_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "HTTPS API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.test"}],
            "paths": {},
        })

        http_rule = self.get_rule(results, "HTTP-001")
        self.assertTrue(http_rule["passed"])

    def test_missing_authentication_triggers_free_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Public API", "version": "1.0.0"},
            "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertFalse(auth_rule["passed"])
        self.assertEqual("Authentification manquante", auth_rule["name"])
        self.assertEqual("ÉLEVÉE", auth_rule["severity"])

    def test_global_security_does_not_trigger_missing_auth_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Protected API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
            "security": [{"BearerAuth": []}],
            "paths": {"/users": {"get": {"responses": {"200": {"description": "OK"}}}}},
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertTrue(auth_rule["passed"])

    def test_unused_security_scheme_triggers_missing_auth_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Unused Auth API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
                }
            },
            "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertFalse(auth_rule["passed"])

    def test_post_without_security_and_without_global_auth_triggers_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "POST API", "version": "1.0.0"},
            "paths": {"/items": {"post": {"responses": {"201": {"description": "Created"}}}}},
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertFalse(auth_rule["passed"])

    def test_public_health_endpoint_in_protected_api_does_not_trigger_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Health API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
            "security": [{"BearerAuth": []}],
            "paths": {
                "/health": {
                    "get": {
                        "security": [],
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/users": {"get": {"responses": {"200": {"description": "OK"}}}},
            },
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertTrue(auth_rule["passed"])

    def test_public_security_on_sensitive_operation_triggers_rule(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Sensitive Public API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
            "security": [{"BearerAuth": []}],
            "paths": {
                "/users": {
                    "get": {
                        "security": [],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        })

        auth_rule = self.get_rule(results, "AUTH-001")
        self.assertFalse(auth_rule["passed"])

    def test_legacy_security_definitions_are_not_used_as_openapi_3_auth(self):
        results = self.run_free_audit_for_document({
            "openapi": "3.0.3",
            "info": {"title": "Legacy Auth API", "version": "1.0.0"},
            "securityDefinitions": {
                "LegacyAuth": {
                    "type": "apiKey",
                    "name": "X-API-Key",
                    "in": "header",
                }
            },
            "security": [{"LegacyAuth": []}],
            "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        })

        self.assertFalse(self.get_rule(results, "AUTH-001")["passed"])
        self.assertTrue(self.get_rule(results, "KEY-EXP-02")["passed"])

    def test_legacy_definitions_refs_are_not_resolved_by_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "openapi.json"
            file_path.write_text(json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "Legacy Ref API", "version": "1.0.0"},
                "components": {
                    "securitySchemes": {
                        "BearerAuth": {
                            "type": "http",
                            "scheme": "bearer",
                            "description": "JWT expires after 15 minutes.",
                        }
                    }
                },
                "security": [{"BearerAuth": []}],
                "definitions": {
                    "LegacySecret": {
                        "type": "object",
                        "properties": {"password": {"type": "string"}},
                    }
                },
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "200": {
                                    "description": "OK",
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "#/definitions/LegacySecret"}
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
            }), encoding="utf-8")

            results = run_audit(file_path, is_pro=True)

        self.assertTrue(self.get_rule(results, "DATA-001")["passed"])

    def test_scan_output_uses_ascii_prefixes(self):
        fixture_path = Path(__file__).parent / "fixtures" / "api_test.yaml"
        runner = CliRunner()

        with patch("speculynx.main._load_saved_license_key", return_value=None):
            result = runner.invoke(
                main.app,
                ["scan", "--file", str(fixture_path)],
            )

        self.assertEqual(0, result.exit_code, result.output)
        for symbol in ("⚡", "🚨", "✅", "❌", "⚠️", "🛑", "📄", "🌐", "📊", "↳"):
            self.assertNotIn(symbol, result.output)
        self.assertIn("[FREE] Mode Free", result.output)
        self.assertIn("[SCAN] [FINDING]", result.output)
        self.assertIn("[RESULT] Résultat", result.output)


if __name__ == "__main__":
    unittest.main()
