import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.dast import run_dast_audit


def write_live_scan_spec(directory: str) -> Path:
    file_path = Path(directory) / "openapi.json"
    file_path.write_text(json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "Live Scan API", "version": "1.0.0"},
        "paths": {
            "/items/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}},
                },
                "post": {"responses": {"201": {"description": "Created"}}},
                "put": {"responses": {"200": {"description": "Updated"}}},
                "patch": {"responses": {"200": {"description": "Patched"}}},
                "delete": {"responses": {"204": {"description": "Deleted"}}},
            }
        },
    }), encoding="utf-8")
    return file_path


class DastSafetyTests(unittest.TestCase):
    def mocked_client(self):
        client = Mock()
        client.request.return_value = SimpleNamespace(status_code=404, text="")
        client.get.return_value = SimpleNamespace(status_code=404, text="")
        manager = Mock()
        manager.__enter__ = Mock(return_value=client)
        manager.__exit__ = Mock(return_value=None)
        return client, manager

    def methods_sent_by_request(self, client):
        return [call.args[0] for call in client.request.call_args_list]

    @patch("speculynx.dast.httpx.Client")
    def test_live_scan_defaults_to_get_only(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager

        with tempfile.TemporaryDirectory() as directory:
            run_dast_audit(write_live_scan_spec(directory), "https://api.example.test")

        self.assertEqual(["GET"], self.methods_sent_by_request(client))
        self.assertEqual(20, client.get.call_count)

    @patch("speculynx.dast.httpx.Client")
    def test_live_scan_with_yes_alone_keeps_unsafe_methods_disabled(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as directory:
            with patch("speculynx.main._load_saved_license_key", return_value="test-key"):
                with patch(
                    "speculynx.main.verify_license_online",
                    return_value={"valid": True, "plan": "pro", "status": "active"},
                ):
                    result = runner.invoke(
                        main.app,
                        [
                            "scan-live",
                            "--file",
                            str(write_live_scan_spec(directory)),
                            "--target",
                            "https://api.example.test",
                            "--yes",
                        ],
                    )

        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(["GET"], self.methods_sent_by_request(client))
        self.assertNotIn("POST", self.methods_sent_by_request(client))
        self.assertNotIn("PUT", self.methods_sent_by_request(client))
        self.assertNotIn("PATCH", self.methods_sent_by_request(client))
        self.assertNotIn("DELETE", self.methods_sent_by_request(client))

    @patch("speculynx.dast.httpx.Client")
    def test_live_scan_allows_unsafe_methods_only_with_explicit_flag(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager

        with tempfile.TemporaryDirectory() as directory:
            run_dast_audit(
                write_live_scan_spec(directory),
                "https://api.example.test",
                allow_unsafe_methods=True,
            )

        methods = self.methods_sent_by_request(client)
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)
        self.assertIn("PUT", methods)
        self.assertIn("PATCH", methods)
        self.assertIn("DELETE", methods)

    @patch("speculynx.dast.httpx.Client")
    def test_dry_run_sends_no_http_requests(self, client_factory):
        with tempfile.TemporaryDirectory() as directory:
            results = run_dast_audit(
                write_live_scan_spec(directory),
                "https://api.example.test",
                dry_run=True,
            )

        client_factory.assert_not_called()
        self.assertEqual("DAST-DRY-RUN", results[0]["id"])

    @patch("speculynx.dast.httpx.Client")
    def test_insecure_stays_explicit(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager

        with tempfile.TemporaryDirectory() as directory:
            run_dast_audit(write_live_scan_spec(directory), "https://api.example.test", insecure=True)

        client_factory.assert_called_once_with(verify=False, follow_redirects=True)


if __name__ == "__main__":
    unittest.main()
