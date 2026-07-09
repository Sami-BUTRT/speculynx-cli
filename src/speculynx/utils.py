import httpx
import sys
from pathlib import Path
from fpdf import FPDF
import keyring
import typer
from keyring.errors import KeyringError

BACKEND_URL = "https://api.speculynx.dev"
KEYRING_SERVICE_NAME = "speculynx"
KEYRING_ACCOUNT_NAME = "license_key"
LEGACY_CONFIG_FILE = Path.home() / ".speculynx.json"

LEGACY_STORAGE_WARNING = (
    "[WARN] Ancien stockage ~/.speculynx.json détecté et ignoré. "
    "Utilisez 'speculynx login'."
)
KEYRING_ERROR_MESSAGE = "Impossible d'accéder au coffre sécurisé du système."


class LicenseKeyStorageError(RuntimeError):
    """Raised when the operating-system credential store is unavailable."""


def safe_echo(message=None, *, err: bool = False, **kwargs) -> None:
    """Write terminal output without failing on the active console encoding."""
    stream = kwargs.get("file") or (sys.stderr if err else sys.stdout)
    text = "" if message is None else str(message)
    encoding = getattr(stream, "encoding", None)
    if encoding:
        try:
            text = text.encode(encoding, errors="replace").decode(encoding)
        except LookupError:
            pass
    typer.echo(text, err=err, **kwargs)


def _warn_if_legacy_storage_exists() -> None:
    if LEGACY_CONFIG_FILE.exists():
        safe_echo(LEGACY_STORAGE_WARNING)


def save_license_key(key: str) -> None:
    try:
        keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_ACCOUNT_NAME, key)
    except KeyringError as error:
        raise LicenseKeyStorageError(KEYRING_ERROR_MESSAGE) from error


def load_license_key() -> str | None:
    _warn_if_legacy_storage_exists()
    try:
        return keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_ACCOUNT_NAME)
    except KeyringError as error:
        raise LicenseKeyStorageError(KEYRING_ERROR_MESSAGE) from error


def delete_license_key() -> None:
    try:
        if keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_ACCOUNT_NAME) is not None:
            keyring.delete_password(KEYRING_SERVICE_NAME, KEYRING_ACCOUNT_NAME)
    except KeyringError as error:
        raise LicenseKeyStorageError(KEYRING_ERROR_MESSAGE) from error

def verify_license_online(api_key: str) -> dict:
    try:
        response = httpx.post(
            f"{BACKEND_URL}/v1/verify",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5
        )
        if response.status_code != 200:
            return {"valid": False, "plan": "free", "status": "unavailable"}

        license_info = response.json()
        status = license_info.get("status")
        if (
            license_info.get("valid") is True
            and license_info.get("plan") == "pro"
            and status == "active"
        ):
            return {"valid": True, "plan": "pro", "status": "active"}
        if status in {"invalid", "inactive", "expired"}:
            return {"valid": False, "plan": "free", "status": status}
        return {"valid": False, "plan": "free", "status": "unavailable"}
    except (httpx.RequestError, ValueError):
        return {"valid": False, "plan": "free", "status": "network_error"}

class SpeculynxPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(128, 0, 128)
        self.cell(0, 10, "SPECULYNX - RAPPORT D'AUDIT", ln=True, align="C")
        self.line(10, 22, 200, 22)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, "Document genere par Speculynx Pro", align="C")

def generate_pdf_report(target_file: str, audit_results: list, output_path: Path):
    pdf = SpeculynxPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 10, f"Fichier: {target_file}", ln=True)
    for result in audit_results:
        status = "OK" if result["passed"] else "FAIL"
        pdf.cell(0, 10, f"{result['name']} : {status}", ln=True)
    pdf.output(str(output_path))
