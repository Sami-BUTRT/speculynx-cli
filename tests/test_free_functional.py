import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.scanner import load_openapi_file, run_audit


FIXTURES = Path(__file__).parent / "fixtures"
PRO_RULE_IDS = {
    "KEY-PRO-01",
    "KEY-PRO-02",
    "KEY-PRO-03",
    "BOLA-001",
    "BFLA-001",
    "DATA-001",
    "SECRET-001",
    "SSRF-001",
    "RATE-001",
    "INV-001",
}


def rule_by_id(results: list, rule_id: str) -> dict:
    return next(result for result in results if result["id"] == rule_id)


class FreeFunctionalTests(unittest.TestCase):
    def audit_fixture(self, name: str) -> list:
        return run_audit(FIXTURES / name, is_pro=False)

    def assert_readable_finding(self, rule: dict, *, name: str, severity: str) -> None:
        self.assertFalse(rule["passed"])
        self.assertEqual(name, rule["name"])
        self.assertEqual(severity, rule["severity"])
        self.assertTrue(rule["fail_message"])

    def test_query_key_rule_positive_and_negative_fixtures(self):
        risky = rule_by_id(self.audit_fixture("free_key_query.yaml"), "KEY-EXP-01")
        clean = rule_by_id(self.audit_fixture("free_no_key_query.yaml"), "KEY-EXP-01")

        self.assert_readable_finding(risky, name="Clés exposées dans l'URL", severity="ÉLEVÉE")
        self.assertTrue(clean["passed"])

    def test_insecure_http_rule_positive_and_negative_fixtures(self):
        risky = rule_by_id(self.audit_fixture("free_http_server.yaml"), "HTTP-001")
        clean = rule_by_id(self.audit_fixture("free_https_server.yaml"), "HTTP-001")

        self.assert_readable_finding(risky, name="HTTP non sécurisé", severity="ÉLEVÉE")
        self.assertTrue(clean["passed"])

    def test_missing_auth_rule_positive_and_negative_fixtures(self):
        risky = rule_by_id(self.audit_fixture("free_missing_auth.yaml"), "AUTH-001")
        clean = rule_by_id(self.audit_fixture("free_auth_present.yaml"), "AUTH-001")

        self.assert_readable_finding(risky, name="Authentification manquante", severity="ÉLEVÉE")
        self.assertTrue(clean["passed"])

    def test_key_expiration_rule_positive_and_negative_fixtures(self):
        risky = rule_by_id(self.audit_fixture("free_key_no_expiration.yaml"), "KEY-EXP-02")
        clean = rule_by_id(self.audit_fixture("free_key_expiration.yaml"), "KEY-EXP-02")

        self.assert_readable_finding(risky, name="Absence d'expiration des clés", severity="MOYENNE")
        self.assertTrue(clean["passed"])

    def test_yaml_and_json_openapi_files_are_accepted(self):
        yaml_document = load_openapi_file(FIXTURES / "free_auth_present.yaml")
        self.assertEqual("3.1.0", yaml_document["openapi"])

        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "openapi.json"
            json_path.write_text(json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "JSON API", "version": "1.0.0"},
                "paths": {},
            }), encoding="utf-8")
            json_document = load_openapi_file(json_path)

        self.assertEqual("3.0.0", json_document["openapi"])

    def test_free_cli_scan_is_local_readable_and_runs_no_pro_rules(self):
        runner = CliRunner()
        with patch("speculynx.main._load_saved_license_key", return_value=None), patch(
            "speculynx.main.verify_license_online"
        ) as verify_license:
            result = runner.invoke(
                main.app,
                ["scan", "--file", str(FIXTURES / "free_key_query.yaml")],
            )

        self.assertEqual(0, result.exit_code, result.output)
        verify_license.assert_not_called()
        self.assertIn("[FREE] Mode Free", result.output)
        self.assertIn("[RESULT] Résultat", result.output)
        for rule_id in PRO_RULE_IDS:
            self.assertNotIn(rule_id, result.output)

    def test_free_cli_pdf_export_is_blocked_without_creating_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "free-report.pdf"
            with patch("speculynx.main._load_saved_license_key", return_value=None), patch(
                "speculynx.main.verify_license_online"
            ) as verify_license:
                result = runner.invoke(
                    main.app,
                    [
                        "scan",
                        "--file",
                        str(FIXTURES / "free_key_query.yaml"),
                        "--export",
                        str(output_path),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            verify_license.assert_not_called()
            self.assertFalse(output_path.exists())
            self.assertIn("Export refusé", result.output)
            self.assertIn("Pro uniquement", result.output)


if __name__ == "__main__":
    unittest.main()
