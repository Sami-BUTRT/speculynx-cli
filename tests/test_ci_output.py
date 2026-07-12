import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from speculynx import main


FIXTURES = Path(__file__).parent / "fixtures"


class CIOutputTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.no_license = patch("speculynx.main._load_saved_license_key", return_value=None)
        self.no_license.start()

    def tearDown(self):
        self.no_license.stop()

    def invoke(self, fixture: str, *options: str):
        return self.runner.invoke(main.app, ["scan", "--file", str(FIXTURES / fixture), *options])

    def test_free_clean_text_is_explicitly_partial_and_indeterminate(self):
        result = self.invoke("openapi_clean.yaml")
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("SCAN PARTIEL — MODE FREE", result.output)
        self.assertIn("Règles", result.output)
        self.assertIn("Couverture : partielle", result.output)
        self.assertIn("Verdict global : indéterminé", result.output)
        for misleading in ("API sécurisée", "Scan réussi", "0 vulnérabilité", "OK /", "Aucun risque"):
            self.assertNotIn(misleading, result.output)

    def test_free_finding_and_pro_only_risk_semantics(self):
        finding = self.invoke("free_http_server.yaml", "--fail-on", "high")
        self.assertEqual(1, finding.exit_code, finding.output)
        self.assertIn("HTTP non sécurisé", finding.output)
        self.assertIn("Verdict global : risques détectés", finding.output)
        pro_only = self.invoke("openapi_bola_protected.yaml")
        self.assertEqual(0, pro_only.exit_code, pro_only.output)
        self.assertIn("BOLA-001", pro_only.output)
        self.assertIn("non analysé dans ce mode", pro_only.output)
        self.assertNotIn("Risque BOLA potentiel", pro_only.output)
        self.assertIn("Verdict global : indéterminé", pro_only.output)

    def test_json_is_valid_stable_and_consistent_for_openapi_30_and_31(self):
        for fixture in ("openapi_clean.yaml", "free_auth_present.yaml"):
            result = self.invoke(fixture, "--json")
            self.assertEqual(0, result.exit_code, result.output)
            payload = json.loads(result.stdout)
            self.assertEqual("1.0", payload["schema_version"])
            self.assertEqual("free", payload["scan"]["mode"])
            self.assertEqual("partial", payload["scan"]["coverage"]["status"])
            self.assertEqual(4, payload["scan"]["coverage"]["rules_executed"])
            self.assertEqual(10, payload["scan"]["coverage"]["rules_skipped"])
            self.assertEqual(len(payload["findings"]), payload["summary"]["total_findings"])
            self.assertEqual(result.stdout.strip(), json.dumps(payload, ensure_ascii=False, sort_keys=True))

    def test_fail_on_thresholds(self):
        expected = {"never": 0, "low": 1, "medium": 1, "high": 1, "critical": 0}
        for threshold, code in expected.items():
            result = self.invoke("free_http_server.yaml", "--json", "--fail-on", threshold)
            self.assertEqual(code, result.exit_code, (threshold, result.output))

    def test_invalid_documents_return_code_2_and_no_json_stdout(self):
        documents = {
            "swagger.yaml": 'swagger: "2.0"\n',
            "missing.yaml": "info:\n  title: Missing\n",
            "invalid.yaml": "openapi: [\n",
            "invalid.json": "{not json}",
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, content in documents.items():
                path = Path(directory) / name
                path.write_text(content, encoding="utf-8")
                result = self.runner.invoke(main.app, ["scan", "--file", str(path), "--json"])
                self.assertEqual(2, result.exit_code, (name, result.output))
                self.assertEqual("", result.stdout)

    def test_unexpected_internal_error_returns_code_3_without_details(self):
        with patch("speculynx.main.run_audit", side_effect=RuntimeError("secret detail")):
            result = self.invoke("openapi_clean.yaml", "--json")
        self.assertEqual(3, result.exit_code)
        self.assertEqual("", result.stdout)
        self.assertNotIn("secret detail", result.stderr)

    def test_version_option_reports_the_package_version(self):
        result = self.runner.invoke(main.app, ["--version"])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual("0.1.4\n", result.stdout)
