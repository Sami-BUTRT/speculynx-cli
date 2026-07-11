import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.dast import (
    check_dast_auth_bypass,
    check_dast_rate_limit,
    check_dast_verbose_errors,
    is_private_or_local_target,
    planned_requests,
    run_dast_audit,
)
from speculynx.scanner import load_openapi_file


FIXTURES = Path(__file__).parent / "fixtures"
DAST_METHODS_FIXTURE = FIXTURES / "dast_methods.yaml"


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

    def test_auth_bypass_rule_positive_and_negative_mock_responses(self):
        document = load_openapi_file(DAST_METHODS_FIXTURE)
        client = Mock()
        client.request.return_value = SimpleNamespace(status_code=200, text="")

        finding = check_dast_auth_bypass(
            client,
            "https://api.example.test",
            document,
        )
        client.request.return_value = SimpleNamespace(status_code=401, text="")
        protected = check_dast_auth_bypass(
            client,
            "https://api.example.test",
            document,
        )

        self.assertFalse(finding["passed"])
        self.assertEqual("DAST-01", finding["id"])
        self.assertIn("200 sans token", finding["fail_message"])
        self.assertTrue(protected["passed"])

    def test_verbose_error_rule_uses_only_mocked_non_destructive_payloads(self):
        document = load_openapi_file(DAST_METHODS_FIXTURE)
        client = Mock()
        client.request.return_value = SimpleNamespace(
            status_code=500,
            text='Traceback: File "/app/main.py", line 10',
        )

        finding = check_dast_verbose_errors(
            client,
            "https://api.example.test",
            document,
            allow_unsafe_methods=True,
        )
        skipped = check_dast_verbose_errors(
            client,
            "https://api.example.test",
            document,
            allow_unsafe_methods=False,
        )

        self.assertFalse(finding["passed"])
        self.assertEqual("DAST-03", finding["id"])
        self.assertIn("stack trace", finding["fail_message"])
        self.assertTrue(skipped["passed"])
        rendered_payloads = repr([call.kwargs.get("json") for call in client.request.call_args_list])
        for destructive_fragment in ("drop table", "delete from", "truncate", "$where"):
            self.assertNotIn(destructive_fragment, rendered_payloads.lower())

    def test_rate_limit_rule_positive_and_negative_mock_responses(self):
        document = load_openapi_file(DAST_METHODS_FIXTURE)
        limited_client = Mock()
        limited_client.get.side_effect = [
            SimpleNamespace(status_code=200, text=""),
            SimpleNamespace(status_code=429, text=""),
        ]
        unlimited_client = Mock()
        unlimited_client.get.return_value = SimpleNamespace(status_code=200, text="")

        limited = check_dast_rate_limit(
            limited_client,
            "https://api.example.test",
            document,
        )
        missing = check_dast_rate_limit(
            unlimited_client,
            "https://api.example.test",
            document,
        )

        self.assertTrue(limited["passed"])
        self.assertEqual(2, limited_client.get.call_count)
        self.assertFalse(missing["passed"])
        self.assertEqual("DAST-05", missing["id"])
        self.assertEqual(20, unlimited_client.get.call_count)

    @patch("speculynx.dast.httpx.Client")
    def test_live_scan_defaults_to_get_only(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager

        with tempfile.TemporaryDirectory() as directory:
            run_dast_audit(write_live_scan_spec(directory), "https://api.example.test")

        self.assertEqual(["GET"], self.methods_sent_by_request(client))
        self.assertEqual(20, client.get.call_count)
        for call in client.request.call_args_list:
            self.assertNotIn("json", call.kwargs)

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

    @patch("speculynx.dast.httpx.Client")
    def test_tls_verification_is_enabled_by_default(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager

        with tempfile.TemporaryDirectory() as directory:
            run_dast_audit(write_live_scan_spec(directory), "https://api.example.test")

        client_factory.assert_called_once_with(verify=True, follow_redirects=True)

    def test_path_item_parameters_are_substituted_in_planned_requests(self):
        document = load_openapi_file(DAST_METHODS_FIXTURE)

        requests = planned_requests(
            document,
            "https://api.example.test",
            allow_unsafe_methods=False,
        )

        self.assertEqual([("GET", "https://api.example.test/items/1")], requests)

    @patch("speculynx.dast.httpx.Client")
    def test_scan_live_without_license_fails_before_http_client_creation(self, client_factory):
        runner = CliRunner()
        with patch("speculynx.main._load_saved_license_key", return_value=None), patch(
            "speculynx.main.verify_license_online"
        ) as verify_license:
            result = runner.invoke(
                main.app,
                [
                    "scan-live",
                    "--file",
                    str(DAST_METHODS_FIXTURE),
                    "--target",
                    "https://api.example.test",
                    "--yes",
                ],
            )

        self.assertEqual(1, result.exit_code, result.output)
        verify_license.assert_not_called()
        client_factory.assert_not_called()
        self.assertIn("réservé aux membres Pro", result.output)

    @patch("speculynx.dast.httpx.Client")
    def test_scan_live_license_network_error_fails_closed_before_http_client(self, client_factory):
        runner = CliRunner()
        with patch("speculynx.main._load_saved_license_key", return_value="test-key"), patch(
            "speculynx.main.verify_license_online",
            return_value={"valid": False, "plan": "free", "status": "network_error"},
        ):
            result = runner.invoke(
                main.app,
                [
                    "scan-live",
                    "--file",
                    str(DAST_METHODS_FIXTURE),
                    "--target",
                    "https://api.example.test",
                    "--yes",
                ],
            )

        self.assertEqual(1, result.exit_code, result.output)
        client_factory.assert_not_called()
        self.assertIn("réservé aux membres Pro", result.output)

    @patch("speculynx.dast.httpx.Client")
    def test_cli_dry_run_prints_plan_without_creating_http_client(self, client_factory):
        runner = CliRunner()
        with patch("speculynx.main._load_saved_license_key", return_value="test-key"), patch(
            "speculynx.main.verify_license_online",
            return_value={"valid": True, "plan": "pro", "status": "active"},
        ):
            result = runner.invoke(
                main.app,
                [
                    "scan-live",
                    "--file",
                    str(DAST_METHODS_FIXTURE),
                    "--target",
                    "https://api.example.test",
                    "--yes",
                    "--dry-run",
                ],
            )

        self.assertEqual(0, result.exit_code, result.output)
        client_factory.assert_not_called()
        self.assertIn("[DRY-RUN] GET https://api.example.test/items/1", result.output)
        self.assertNotIn("[DRY-RUN] POST", result.output)

    @patch("speculynx.dast.httpx.Client")
    def test_cli_pro_flag_explicitly_enables_unsafe_methods_on_mock_client(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager
        runner = CliRunner()
        with patch("speculynx.main._load_saved_license_key", return_value="test-key"), patch(
            "speculynx.main.verify_license_online",
            return_value={"valid": True, "plan": "pro", "status": "active"},
        ):
            result = runner.invoke(
                main.app,
                [
                    "scan-live",
                    "--file",
                    str(DAST_METHODS_FIXTURE),
                    "--target",
                    "https://api.example.test",
                    "--yes",
                    "--allow-unsafe-methods",
                ],
            )

        self.assertEqual(0, result.exit_code, result.output)
        methods = self.methods_sent_by_request(client)
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            self.assertIn(method, methods)

    def test_local_private_and_metadata_targets_are_detected(self):
        private_targets = (
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://172.31.255.254",
            "http://192.168.0.1",
            "http://169.254.169.254",
        )
        for target in private_targets:
            with self.subTest(target=target):
                self.assertTrue(is_private_or_local_target(target))
        self.assertFalse(is_private_or_local_target("https://api.example.test"))

    @patch("speculynx.dast.httpx.Client")
    def test_private_target_emits_warning_without_client_in_dry_run(self, client_factory):
        output = StringIO()
        with redirect_stdout(output):
            run_dast_audit(
                DAST_METHODS_FIXTURE,
                "http://169.254.169.254",
                dry_run=True,
            )

        client_factory.assert_not_called()
        self.assertIn("[WARN] Cible locale ou privée détectée", output.getvalue())

    @patch("speculynx.dast.httpx.Client")
    def test_request_count_and_timeouts_are_bounded(self, client_factory):
        client, manager = self.mocked_client()
        client_factory.return_value = manager
        document = {
            "openapi": "3.0.0",
            "info": {"title": "Bounded API", "version": "1.0.0"},
            "paths": {
                f"/items/{index}": {
                    "get": {"responses": {"200": {"description": "OK"}}}
                }
                for index in range(6)
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "openapi.json"
            file_path.write_text(json.dumps(document), encoding="utf-8")
            run_dast_audit(file_path, "https://api.example.test")

        self.assertEqual(5, client.request.call_count)
        self.assertEqual(20, client.get.call_count)
        for call in client.request.call_args_list:
            self.assertEqual(5, call.kwargs["timeout"])
        for call in client.get.call_args_list:
            self.assertEqual(3, call.kwargs["timeout"])


if __name__ == "__main__":
    unittest.main()
