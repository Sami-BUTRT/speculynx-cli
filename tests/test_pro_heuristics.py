import re
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.scanner import (
    check_pro_ai_agent_risk,
    check_pro_identity_context,
    check_pro_over_permissioned,
    run_audit,
)


FIXTURES = Path(__file__).parent / "fixtures"
RISKY_FIXTURE = FIXTURES / "openapi_pro_risky.yaml"
CLEAN_FIXTURE = FIXTURES / "openapi_clean.yaml"
BOLA_PROTECTED_FIXTURE = FIXTURES / "openapi_bola_protected.yaml"
ADMIN_SCOPED_FIXTURE = FIXTURES / "openapi_admin_scoped.yaml"
RATE_LIMITED_FIXTURE = FIXTURES / "openapi_rate_limited.yaml"
PUBLIC_HEALTH_FIXTURE = FIXTURES / "openapi_public_health.yaml"
SENSITIVE_LEGITIMATE_FIXTURE = FIXTURES / "openapi_sensitive_legitimate.yaml"
SECRET_PLACEHOLDERS_FIXTURE = FIXTURES / "openapi_secret_placeholders.yaml"
SSRF_BENIGN_FIXTURE = FIXTURES / "openapi_ssrf_benign.yaml"
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
PRUDENCE_MARKERS = (
    "peut",
    "potentiel",
    "à vérifier",
    "si",
    "non documenté",
    "semble",
    "pattern",
    "heuristique",
    "statique",
    "pourrait",
)
FORBIDDEN_CERTAINTY_PHRASES = (
    "vulnérable avec certitude",
    "faille confirmée",
    "exploitation confirmée",
    "compromis",
    "exploitable avec certitude",
    "compromission",
)
ACTION_MARKERS = (
    "vérifiez",
    "vérifier",
    "contrôle",
    "côté serveur",
    "gateway",
    "scopes",
    "rôles",
    "minimisées",
    "masquées",
    "rotation",
    "révocation",
    "isolation tenant",
    "allowlist",
    "tags",
)


def rule_by_id(results: list, rule_id: str) -> dict:
    return next(result for result in results if result["id"] == rule_id)


def decoded_pdf_streams(path: Path) -> bytes:
    decoded = []
    for stream in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", path.read_bytes(), re.DOTALL):
        try:
            decoded.append(zlib.decompress(stream))
        except zlib.error:
            decoded.append(stream)
    return b"\n".join(decoded)


class ProHeuristicRuleTests(unittest.TestCase):
    def test_identity_context_rule_positive_and_negative_cases(self):
        risky = check_pro_identity_context({
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
                }
            }
        })
        clean = check_pro_identity_context({
            "components": {
                "securitySchemes": {
                    "OAuth2": {"type": "oauth2", "flows": {}}
                }
            }
        })

        self.assertFalse(risky["passed"])
        self.assertEqual("KEY-PRO-01", risky["id"])
        self.assertEqual("ÉLEVÉE", risky["severity"])
        self.assertTrue(clean["passed"])

    def test_ai_agent_rule_positive_and_mitigated_cases(self):
        risky = check_pro_ai_agent_risk({
            "paths": {"/users/{id}": {"delete": {"responses": {"204": {}}}}}
        })
        mitigated = check_pro_ai_agent_risk({
            "paths": {
                "/users/{id}": {
                    "delete": {
                        "description": "Requires explicit confirmation and MFA verification.",
                        "responses": {"204": {}},
                    }
                }
            }
        })

        self.assertFalse(risky["passed"])
        self.assertEqual("KEY-PRO-02", risky["id"])
        self.assertEqual("CRITIQUE", risky["severity"])
        self.assertTrue(mitigated["passed"])

    def test_over_permissioned_rule_positive_and_scoped_cases(self):
        risky = check_pro_over_permissioned({
            "components": {
                "securitySchemes": {
                    "OAuth2": {
                        "type": "oauth2",
                        "flows": {"clientCredentials": {"scopes": {}}},
                    }
                }
            }
        })
        scoped = check_pro_over_permissioned({
            "components": {
                "securitySchemes": {
                    "OAuth2": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "scopes": {"catalog:read": "Read catalog"}
                            }
                        },
                    }
                }
            }
        })

        self.assertFalse(risky["passed"])
        self.assertEqual("KEY-PRO-03", risky["id"])
        self.assertEqual("ÉLEVÉE", risky["severity"])
        self.assertTrue(scoped["passed"])

    def test_free_scan_does_not_run_pro_heuristics(self):
        results = run_audit(RISKY_FIXTURE, is_pro=False)

        self.assertTrue(PRO_RULE_IDS.isdisjoint({result["id"] for result in results}))

    def test_pro_scan_runs_pro_heuristics(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        self.assertTrue(PRO_RULE_IDS.issubset({result["id"] for result in results}))

    def test_clean_api_does_not_trigger_major_pro_heuristics(self):
        results = run_audit(CLEAN_FIXTURE, is_pro=True)

        for rule_id in PRO_RULE_IDS:
            self.assertTrue(rule_by_id(results, rule_id)["passed"], rule_id)

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

    def test_bola_protected_object_route_remains_prudent_if_reported(self):
        results = run_audit(BOLA_PROTECTED_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BOLA-001")
        self.assertFalse(rule["passed"])
        self.assertIn("Ce n'est pas une preuve de BOLA", rule["fail_message"])
        self.assertIn("L'analyse statique", rule["fail_message"])
        self.assertIn("isolation tenant", rule["fail_message"])

    def test_bfla_triggers_on_admin_route_without_precise_authorization(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "BFLA-001")
        self.assertFalse(rule["passed"])
        self.assertIn("fonction privilégiée", rule["fail_message"])
        self.assertIn("peut indiquer un risque BFLA", rule["fail_message"])

    def test_bfla_does_not_trigger_with_precise_scopes(self):
        results = run_audit(ADMIN_SCOPED_FIXTURE, is_pro=True)

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

    def test_sensitive_data_legitimate_case_remains_contextual(self):
        results = run_audit(SENSITIVE_LEGITIMATE_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "DATA-001")
        self.assertFalse(rule["passed"])
        self.assertEqual("MOYENNE", rule["severity"])
        self.assertIn("selon le contexte métier", rule["fail_message"])
        self.assertIn("minimisées", rule["fail_message"])

    def test_secret_example_triggers_on_live_key_pattern(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SECRET-001")
        self.assertFalse(rule["passed"])
        self.assertIn("ressemble à un secret réel", rule["fail_message"])
        self.assertIn("placeholder neutre", rule["fail_message"])

    def test_secret_example_ignores_placeholders(self):
        results = run_audit(SECRET_PLACEHOLDERS_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SECRET-001")
        self.assertTrue(rule["passed"])

    def test_ssrf_triggers_on_client_supplied_url(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SSRF-001")
        self.assertFalse(rule["passed"])
        self.assertIn("URL fournie par le client", rule["fail_message"])
        self.assertIn("dépend de l'usage serveur", rule["description"])
        self.assertIn("ne confirme pas l'usage backend", rule["fail_message"])

    def test_ssrf_benign_url_fields_remain_prudent_if_reported(self):
        results = run_audit(SSRF_BENIGN_FIXTURE, is_pro=True)

        rule = rule_by_id(results, "SSRF-001")
        self.assertFalse(rule["passed"])
        self.assertIn("Si le serveur la contacte", rule["fail_message"])
        self.assertIn("ne confirme pas l'usage backend", rule["fail_message"])

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
        self.assertIn("À vérifier", rule["fail_message"])

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
            pdf_text = decoded_pdf_streams(output_path)
            self.assertIn(b"SPECULYNX", pdf_text)
            self.assertIn("Clés exposées".encode("latin-1"), pdf_text)

    def test_pro_pdf_export_with_pro_findings_generates_non_empty_file_without_backend(self):
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "pro-risk-report.pdf"
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
                            str(RISKY_FIXTURE),
                            "--export",
                            str(output_path),
                        ],
                    )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue(output_path.exists())
            self.assertGreater(output_path.stat().st_size, 0)

    def test_pro_findings_use_prudent_non_certain_wording(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        for rule_id in PRO_RULE_IDS:
            rule = rule_by_id(results, rule_id)
            self.assertFalse(rule["passed"], rule_id)
            text = " ".join(
                str(value)
                for value in (rule["name"], rule["description"], rule["fail_message"])
                if value
            ).lower()
            self.assertTrue(
                any(marker in text for marker in PRUDENCE_MARKERS),
                f"{rule_id} lacks prudent wording: {text}",
            )
            for forbidden in FORBIDDEN_CERTAINTY_PHRASES:
                self.assertNotIn(forbidden, text)

    def test_pro_findings_include_pedagogical_action_markers(self):
        results = run_audit(RISKY_FIXTURE, is_pro=True)

        for rule_id in PRO_RULE_IDS:
            rule = rule_by_id(results, rule_id)
            self.assertFalse(rule["passed"], rule_id)
            text = " ".join(
                str(value)
                for value in (rule["description"], rule["fail_message"])
                if value
            ).lower()
            self.assertTrue(
                any(marker in text for marker in ACTION_MARKERS),
                f"{rule_id} lacks actionable guidance: {text}",
            )


if __name__ == "__main__":
    unittest.main()
