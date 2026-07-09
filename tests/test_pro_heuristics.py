import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.scanner import run_audit


FIXTURES = Path(__file__).parent / "fixtures"
RISKY_FIXTURE = FIXTURES / "openapi_pro_risky.yaml"
CLEAN_FIXTURE = FIXTURES / "openapi_clean.yaml"
RATE_LIMITED_FIXTURE = FIXTURES / "openapi_rate_limited.yaml"
PUBLIC_HEALTH_FIXTURE = FIXTURES / "openapi_public_health.yaml"
BASE_FIXTURE = FIXTURES / "api_test.yaml"
PRO_RULE_IDS = {
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


class ProHeuristicRuleTests(unittest.TestCase):
    def test_free_scan_does_not_run_pro_heuristics(self):
        results = run_audit(RISKY_FIXTURE, is_pro=False)

        self.assertTrue(PRO_RULE_IDS.isdisjoint({result["id"] for result in results}))

    def test_pro_scan_runs_pro_heuristics(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        self.assertTrue(PRO_RULE_IDS.issubset({result["id"] for result in results}))

    def test_bola_triggers_on_object_identifier_route(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BOLA-001")
        self.assertFalse(rule["passed"])
        self.assertIn("Pattern à risque détecté", rule["fail_message"])
        self.assertIn("Ce n'est pas une preuve de BOLA", rule["fail_message"])
        self.assertIn("contrôle propriétaire", rule["fail_message"])

    def test_bola_does_not_trigger_on_public_health(self):
        results = run_audit(PUBLIC_HEALTH_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BOLA-001")
        self.assertTrue(rule["passed"])

    def test_bfla_triggers_on_admin_route_without_precise_authorization(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BFLA-001")
        self.assertFalse(rule["passed"])
        self.assertIn("fonction privilégiée", rule["fail_message"])
        self.assertIn("peut indiquer un risque BFLA", rule["fail_message"])

    def test_bfla_does_not_trigger_with_precise_scopes(self):
        results = run_audit(CLEAN_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BFLA-001")
        self.assertTrue(rule["passed"])

    def test_sensitive_data_triggers_on_sensitive_response_fields(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "DATA-001")
        self.assertFalse(rule["passed"])
        self.assertEqual("ÉLEVÉE", rule["severity"])
        self.assertIn("potentiellement sensibles", rule["fail_message"])
        self.assertIn("minimisées", rule["fail_message"])

    def test_sensitive_data_avoids_obvious_clean_schema(self):
        results = run_audit(CLEAN_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "DATA-001")
        self.assertTrue(rule["passed"])

    def test_secret_example_triggers_on_live_key_pattern(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SECRET-001")
        self.assertFalse(rule["passed"])
        self.assertIn("ressemble à un secret réel", rule["fail_message"])
        self.assertIn("placeholder neutre", rule["fail_message"])

    def test_secret_example_ignores_placeholders(self):
        results = run_audit(CLEAN_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SECRET-001")
        self.assertTrue(rule["passed"])

    def test_ssrf_triggers_on_client_supplied_url(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SSRF-001")
        self.assertFalse(rule["passed"])
        self.assertIn("URL fournie par le client", rule["fail_message"])
        self.assertIn("dépend de l'usage serveur", rule["description"])

    def test_rate_limit_triggers_on_sensitive_endpoint_without_documentation(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "RATE-001")
        self.assertFalse(rule["passed"])
        self.assertIn("ne documente pas de limitation de débit", rule["fail_message"])

    def test_rate_limit_does_not_trigger_when_429_or_headers_are_documented(self):
        results = run_audit(RATE_LIMITED_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "RATE-001")
        self.assertTrue(rule["passed"])

    def test_inventory_triggers_on_deprecated_or_empty_version(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "INV-001")
        self.assertFalse(rule["passed"])
        self.assertIn("versioning de l'API", rule["fail_message"])

    def test_pro_pdf_export_generates_non_empty_file_without_backend(self):
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.pdf"
            with patch("speculynx.main._load_saved_license_key", return_value="test-key"):
                with patch(
                    "speculynx.main.verify_license_online",
                    return_value={"valid": True, "plan": "pro", "status": "active"},
                ):
                    result = runner.invoke(
                        main.app,
                        [
                            "scan",
                            "--file",
                            str(BASE_FIXTURE),
                            "--export",
                            str(output_path),
                        ],
                    )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue(output_path.exists())
            self.assertGreater(output_path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
