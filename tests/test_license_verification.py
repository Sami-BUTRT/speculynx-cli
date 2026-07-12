import unittest
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from keyring.errors import KeyringError
import typer

from speculynx import main
from speculynx import utils


TEST_KEY = "test-license-key"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "api_test.yaml"
FREE_RESULTS = [
    {
        "id": "KEY-EXP-01",
        "name": "Clés exposées dans l'URL",
        "severity": "ÉLEVÉE",
        "passed": False,
        "fail_message": "Des clés API sont passées en paramètres de requête.",
    }
]


class LicenseVerificationTests(unittest.TestCase):
    @patch("speculynx.utils.httpx.post")
    def test_active_license_uses_post_and_authorization_header(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {
            "valid": True,
            "plan": "pro",
            "status": "active",
        }
        post.return_value = response

        result = utils.verify_license_online(TEST_KEY)

        self.assertEqual(
            {"valid": True, "plan": "pro", "status": "active"},
            result,
        )
        post.assert_called_once_with(
            f"{utils.BACKEND_URL}/v1/verify",
            headers={"Authorization": f"Bearer {TEST_KEY}"},
            timeout=5,
        )
        self.assertNotIn("json", post.call_args.kwargs)
        self.assertNotIn("data", post.call_args.kwargs)
        self.assertNotIn("content", post.call_args.kwargs)
        self.assertNotIn("files", post.call_args.kwargs)

    @patch("speculynx.utils.httpx.post")
    def test_invalid_license_stays_free(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {
            "valid": False,
            "plan": "free",
            "status": "invalid",
        }
        post.return_value = response

        result = utils.verify_license_online(TEST_KEY)

        self.assertEqual(
            {"valid": False, "plan": "free", "status": "invalid"},
            result,
        )

    @patch("speculynx.utils.httpx.post")
    def test_network_failure_makes_pro_unavailable(self, post):
        post.side_effect = httpx.ConnectError("offline")

        result = utils.verify_license_online(TEST_KEY)

        self.assertEqual(
            {"valid": False, "plan": "free", "status": "network_error"},
            result,
        )

    @patch("speculynx.main._delete_saved_license_key")
    @patch("speculynx.main.run_audit", return_value=[])
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=TEST_KEY)
    @patch("speculynx.main.typer.echo")
    def test_network_failure_does_not_block_free_scan(
        self,
        echo,
        load_license_key,
        verify_license,
        run_audit,
        remove_license,
    ):
        verify_license.return_value = {
            "valid": False,
            "plan": "free",
            "status": "network_error",
        }
        openapi_path = Path("local-openapi.yaml")

        main.scan(file=openapi_path, export=None)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_called_once_with(TEST_KEY)
        run_audit.assert_called_once_with(openapi_path, is_pro=False)
        remove_license.assert_not_called()
        self.assertTrue(echo.called)

    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.run_audit", return_value=[])
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=None)
    def test_free_scan_without_key_does_not_use_network(
        self,
        load_license_key,
        verify_license,
        run_audit,
        echo,
    ):
        openapi_path = Path("local-openapi.yaml")

        main.scan(file=openapi_path, export=None)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_not_called()
        run_audit.assert_called_once_with(openapi_path, is_pro=False)
        self.assertTrue(echo.called)


class ScanModeAuthorizationTests(unittest.TestCase):
    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.generate_pdf_report")
    @patch("speculynx.main.run_audit", return_value=FREE_RESULTS)
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=None)
    def test_free_scan_without_key_uses_no_network_no_pro_rules_or_pdf(
        self,
        load_license_key,
        verify_license,
        run_audit,
        generate_pdf,
        echo,
    ):
        export_path = Path("report.pdf")

        with self.assertRaises(typer.Exit) as raised:
            main.scan(file=FIXTURE_PATH, export=export_path)
        self.assertEqual(4, raised.exception.exit_code)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_not_called()
        run_audit.assert_called_once_with(FIXTURE_PATH, is_pro=False)
        generate_pdf.assert_not_called()
        rendered_output = " ".join(str(call) for call in echo.call_args_list)
        self.assertIn("SCAN PARTIEL", rendered_output)
        self.assertIn("Export refusé", rendered_output)

    @patch("speculynx.main._delete_saved_license_key")
    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.generate_pdf_report")
    @patch("speculynx.main.run_audit", return_value=FREE_RESULTS)
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=TEST_KEY)
    def test_invalid_license_blocks_pro_features(
        self,
        load_license_key,
        verify_license,
        run_audit,
        generate_pdf,
        echo,
        delete_license_key,
    ):
        verify_license.return_value = {
            "valid": False,
            "plan": "free",
            "status": "invalid",
        }

        with self.assertRaises(typer.Exit) as raised:
            main.scan(file=FIXTURE_PATH, export=Path("report.pdf"))
        self.assertEqual(4, raised.exception.exit_code)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_called_once_with(TEST_KEY)
        delete_license_key.assert_called_once_with()
        run_audit.assert_called_once_with(FIXTURE_PATH, is_pro=False)
        generate_pdf.assert_not_called()

    @patch("speculynx.main._delete_saved_license_key")
    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.generate_pdf_report")
    @patch("speculynx.main.run_audit", return_value=FREE_RESULTS)
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=TEST_KEY)
    def test_network_error_blocks_pro_features_without_deleting_key(
        self,
        load_license_key,
        verify_license,
        run_audit,
        generate_pdf,
        echo,
        delete_license_key,
    ):
        verify_license.return_value = {
            "valid": False,
            "plan": "free",
            "status": "network_error",
        }

        with self.assertRaises(typer.Exit) as raised:
            main.scan(file=FIXTURE_PATH, export=Path("report.pdf"))
        self.assertEqual(4, raised.exception.exit_code)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_called_once_with(TEST_KEY)
        delete_license_key.assert_not_called()
        run_audit.assert_called_once_with(FIXTURE_PATH, is_pro=False)
        generate_pdf.assert_not_called()

    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.generate_pdf_report")
    @patch("speculynx.main.run_audit", return_value=FREE_RESULTS)
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main._load_saved_license_key", return_value=TEST_KEY)
    def test_active_license_enables_pro_scan_and_export(
        self,
        load_license_key,
        verify_license,
        run_audit,
        generate_pdf,
        echo,
    ):
        export_path = Path("report.pdf")
        verify_license.return_value = {
            "valid": True,
            "plan": "pro",
            "status": "active",
        }

        main.scan(file=FIXTURE_PATH, export=export_path)

        load_license_key.assert_called_once_with(allow_free_on_error=True)
        verify_license.assert_called_once_with(TEST_KEY)
        run_audit.assert_called_once_with(FIXTURE_PATH, is_pro=True)
        generate_pdf.assert_called_once_with(
            FIXTURE_PATH.name,
            FREE_RESULTS,
            export_path,
        )

    @patch("speculynx.utils.httpx.post")
    def test_license_verification_never_sends_openapi_file_content(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {
            "valid": True,
            "plan": "pro",
            "status": "active",
        }
        post.return_value = response
        openapi_contents = FIXTURE_PATH.read_text(encoding="utf-8")

        utils.verify_license_online(TEST_KEY)

        _, kwargs = post.call_args
        rendered_call = repr(post.call_args)
        self.assertEqual(
            {"Authorization": f"Bearer {TEST_KEY}"},
            kwargs["headers"],
        )
        self.assertNotIn("json", kwargs)
        self.assertNotIn("data", kwargs)
        self.assertNotIn("content", kwargs)
        self.assertNotIn("files", kwargs)
        self.assertNotIn(openapi_contents, rendered_call)


class LicenseKeyStorageTests(unittest.TestCase):
    @patch("speculynx.utils.keyring.set_password")
    def test_save_license_key_uses_keyring(self, set_password):
        utils.save_license_key(TEST_KEY)

        set_password.assert_called_once_with(
            utils.KEYRING_SERVICE_NAME,
            utils.KEYRING_ACCOUNT_NAME,
            TEST_KEY,
        )

    @patch("speculynx.utils.LEGACY_CONFIG_FILE")
    @patch("speculynx.utils.keyring.get_password", return_value=TEST_KEY)
    def test_load_license_key_uses_keyring(self, get_password, legacy_file):
        legacy_file.exists.return_value = False

        self.assertEqual(TEST_KEY, utils.load_license_key())
        get_password.assert_called_once_with(
            utils.KEYRING_SERVICE_NAME,
            utils.KEYRING_ACCOUNT_NAME,
        )

    @patch("speculynx.utils.keyring.delete_password")
    @patch("speculynx.utils.keyring.get_password", return_value=TEST_KEY)
    def test_delete_license_key_uses_keyring(self, get_password, delete_password):
        utils.delete_license_key()

        get_password.assert_called_once_with(
            utils.KEYRING_SERVICE_NAME,
            utils.KEYRING_ACCOUNT_NAME,
        )
        delete_password.assert_called_once_with(
            utils.KEYRING_SERVICE_NAME,
            utils.KEYRING_ACCOUNT_NAME,
        )

    @patch("speculynx.utils.LEGACY_CONFIG_FILE")
    @patch("speculynx.utils.keyring.get_password", return_value=None)
    def test_absent_license_key_returns_none(self, get_password, legacy_file):
        legacy_file.exists.return_value = False

        self.assertIsNone(utils.load_license_key())

    @patch("speculynx.utils.LEGACY_CONFIG_FILE")
    @patch("speculynx.utils.keyring.get_password")
    def test_keyring_error_is_wrapped_without_secret(self, get_password, legacy_file):
        legacy_file.exists.return_value = False
        get_password.side_effect = KeyringError(f"failure containing {TEST_KEY}")

        with self.assertRaises(utils.LicenseKeyStorageError) as raised:
            utils.load_license_key()

        self.assertEqual(utils.KEYRING_ERROR_MESSAGE, str(raised.exception))
        self.assertNotIn(TEST_KEY, str(raised.exception))

    @patch("speculynx.utils.keyring.get_password", return_value=None)
    def test_legacy_file_is_warned_about_and_ignored(self, get_password):
        with tempfile.TemporaryDirectory() as directory:
            legacy_file = Path(directory) / ".speculynx.json"
            legacy_file.write_text(f'{{"api_key": "{TEST_KEY}"}}', encoding="utf-8")

            with patch.object(utils, "LEGACY_CONFIG_FILE", legacy_file):
                output = StringIO()
                with redirect_stderr(output):
                    self.assertIsNone(utils.load_license_key())

            self.assertTrue(legacy_file.exists())
            self.assertIn("détecté et ignoré", output.getvalue())
            self.assertNotIn(TEST_KEY, output.getvalue())
            get_password.assert_called_once_with(
                utils.KEYRING_SERVICE_NAME,
                utils.KEYRING_ACCOUNT_NAME,
            )

    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.load_license_key")
    def test_cli_fails_cleanly_when_keyring_is_unavailable(self, load_key, echo):
        load_key.side_effect = utils.LicenseKeyStorageError(utils.KEYRING_ERROR_MESSAGE)

        with self.assertRaises(typer.Exit) as raised:
            main._load_saved_license_key()

        self.assertEqual(1, raised.exception.exit_code)
        rendered_output = " ".join(str(call) for call in echo.call_args_list)
        self.assertIn(utils.KEYRING_ERROR_MESSAGE, rendered_output)
        self.assertNotIn(TEST_KEY, rendered_output)

    @patch("speculynx.main.typer.echo")
    @patch("speculynx.main.run_audit", return_value=[])
    @patch("speculynx.main.verify_license_online")
    @patch("speculynx.main.load_license_key")
    def test_free_scan_continues_when_keyring_is_unavailable(
        self,
        load_key,
        verify_license,
        run_audit,
        echo,
    ):
        load_key.side_effect = utils.LicenseKeyStorageError(utils.KEYRING_ERROR_MESSAGE)
        openapi_path = Path("local-openapi.yaml")

        main.scan(file=openapi_path, export=None)

        verify_license.assert_not_called()
        run_audit.assert_called_once_with(openapi_path, is_pro=False)
        rendered_output = " ".join(str(call) for call in echo.call_args_list)
        self.assertIn("mode Free", rendered_output)
        self.assertNotIn(TEST_KEY, rendered_output)


if __name__ == "__main__":
    unittest.main()
