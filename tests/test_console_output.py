import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from speculynx import main
from speculynx.utils import safe_echo


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "api_test.yaml"
DECORATIVE_CODEPOINTS = (
    0x26A0,
    0x26A1,
    0x2705,
    0x274C,
    0x1F451,
    0x1F4C4,
    0x1F4CA,
    0x1F50D,
    0x1F512,
)


class ConsoleOutputTests(unittest.TestCase):
    def capture_free_scan(self, encoding: str = "cp1252") -> str:
        with tempfile.TemporaryFile(
            mode="w+", encoding=encoding, errors="strict"
        ) as stdout, tempfile.TemporaryFile(
            mode="w+", encoding=encoding, errors="strict"
        ) as stderr:
            with patch(
                "speculynx.main._load_saved_license_key", return_value=None
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                main.scan(file=FIXTURE_PATH, export=None)

            stdout.seek(0)
            stderr.seek(0)
            return stdout.read() + stderr.read()

    def test_scan_output_is_safe_on_strict_cp1252_streams(self):
        output = self.capture_free_scan()

        self.assertIn("[FREE] Mode Free", output)
        self.assertIn("[RESULT] Résultat", output)

    def test_safe_echo_replaces_unencodable_characters(self):
        with tempfile.TemporaryFile(
            mode="w+", encoding="cp1252", errors="strict"
        ) as stdout:
            with redirect_stdout(stdout):
                safe_echo(f"before {chr(0x1F680)} after")

            stdout.seek(0)
            self.assertEqual("before ? after\n", stdout.read())

    def test_main_cli_output_has_no_decorative_unicode(self):
        runner = CliRunner()
        help_result = runner.invoke(main.app, ["--help"])
        output = help_result.output + self.capture_free_scan()

        self.assertEqual(0, help_result.exit_code, help_result.output)
        for codepoint in DECORATIVE_CODEPOINTS:
            self.assertNotIn(chr(codepoint), output)


if __name__ == "__main__":
    unittest.main()
