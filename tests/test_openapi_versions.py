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
    def test_scans_openapi_fixture_without_network_or_pro_license(self):
        fixture_path = Path(__file__).parent / "fixtures" / "api_test.yaml"

        results = run_audit(fixture_path, is_pro=False)

        self.assertEqual(["KEY-EXP-01", "KEY-EXP-02"], [r["id"] for r in results])
        self.assertFalse(results[0]["passed"])
        self.assertFalse(results[1]["passed"])

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
