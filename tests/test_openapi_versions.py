import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import typer

from speculynx.scanner import load_openapi_file


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


if __name__ == "__main__":
    unittest.main()
