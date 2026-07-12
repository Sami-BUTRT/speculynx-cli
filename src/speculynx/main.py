import json as jsonlib
from enum import Enum
import typer
from typing import Optional
from pathlib import Path
from speculynx import __version__
from speculynx.scanner import build_scan_result, load_openapi_file, run_audit
from speculynx.dast import run_dast_audit
from speculynx.utils import (
    LicenseKeyStorageError,
    delete_license_key,
    generate_pdf_report,
    load_license_key,
    safe_echo,
    save_license_key,
    verify_license_online,
)

app = typer.Typer(
    name="speculynx",
    help="Speculynx : L'outil CLI d'audit de sécurité pour API REST.",
    add_completion=False,
    invoke_without_command=True,
)

JSON_SCHEMA_VERSION = "1.0"


class FailOn(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    never = "never"


@app.callback()
def app_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", is_eager=True, help="Affiche la version de Speculynx."),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

def _load_saved_license_key(*, allow_free_on_error: bool = False) -> str | None:
    try:
        return load_license_key()
    except LicenseKeyStorageError as error:
        if allow_free_on_error:
            safe_echo(
                typer.style(
                    f"[WARN] {error} Scan poursuivi en mode Free.",
                    fg=typer.colors.YELLOW,
                ),
                err=True,
            )
            return None
        safe_echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
        raise typer.Exit(code=1) from error


def _delete_saved_license_key() -> None:
    try:
        delete_license_key()
    except LicenseKeyStorageError as error:
        safe_echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
        raise typer.Exit(code=1) from error

@app.command()
def login():
    """Connecte la CLI à votre compte Speculynx Pro."""
    safe_echo(typer.style("[LOGIN] Connexion à Speculynx Pro", fg=typer.colors.MAGENTA, bold=True))
    api_key = typer.prompt("Entrez votre clé de licence Speculynx Pro", hide_input=True)
    safe_echo("Vérification auprès du serveur cloud...")
    license_info = verify_license_online(api_key)
    if license_info.get("valid") is True:
        try:
            save_license_key(api_key)
        except LicenseKeyStorageError as error:
            safe_echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
            raise typer.Exit(code=1) from error
        safe_echo(typer.style("[OK] Authentification réussie !", fg=typer.colors.GREEN, bold=True))
    elif license_info.get("status") in {"network_error", "unavailable"}:
        safe_echo(typer.style("[WARN] Service de licence indisponible.", fg=typer.colors.YELLOW))
    else:
        safe_echo(typer.style("[FAIL] Clé invalide.", fg=typer.colors.RED))


@app.command()
def logout():
    """Supprime la clé Pro du coffre sécurisé du système."""
    _delete_saved_license_key()
    safe_echo("[OK] Licence locale supprimée du coffre sécurisé.")

@app.command()
def info():
    """Affiche les détails de votre licence actuelle."""
    saved_key = _load_saved_license_key()
    if not saved_key:
        safe_echo("Aucune licence trouvée. Faites 'speculynx login'.")
        return
    license_info = verify_license_online(saved_key)
    if license_info.get("valid") is True:
        safe_echo(typer.style("[PRO] État : Speculynx Pro", fg=typer.colors.CYAN, bold=True))
    elif license_info.get("status") in {"network_error", "unavailable"}:
        safe_echo(typer.style("[WARN] Vérification Pro temporairement indisponible.", fg=typer.colors.YELLOW))
    else:
        safe_echo(typer.style("[FREE] État : Speculynx Free", fg=typer.colors.YELLOW, bold=True))
        _delete_saved_license_key()

@app.command()
def scan(
    file: Path = typer.Option(..., "--file", "-f", help="Fichier OpenAPI à auditer.", exists=True),
    export: Optional[Path] = typer.Option(None, "--export", "-e", help="[Pro] Exporter le rapport PDF."),
    json_output: bool = typer.Option(False, "--json", help="Émet uniquement un document JSON versionné sur stdout."),
    fail_on: FailOn = typer.Option(FailOn.never, "--fail-on", help="Seuil CI : critical, high, medium, low ou never."),
):
    """Lance l'audit de sécurité statique sur une spec OpenAPI."""
    saved_key = _load_saved_license_key(allow_free_on_error=True)
    is_pro = False
    if saved_key:
        license_info = verify_license_online(saved_key)
        if license_info.get("valid") is True:
            is_pro = True
        elif license_info.get("status") not in {"network_error", "unavailable"}:
            _delete_saved_license_key()

    json_output = json_output if isinstance(json_output, bool) else False
    fail_on = fail_on if isinstance(fail_on, FailOn) else FailOn.never
    if not json_output:
        safe_echo(typer.style("[PRO] Mode Pro activé", fg=typer.colors.MAGENTA, bold=True) if is_pro else typer.style("SCAN PARTIEL — MODE FREE", fg=typer.colors.YELLOW, bold=True))
    try:
        audit_results = run_audit(file, is_pro=is_pro)
    except typer.Exit:
        raise
    except Exception:
        safe_echo("[ERROR] Erreur interne inattendue pendant le scan.", err=True)
        raise typer.Exit(code=3)
    if any(result.get("id") == "SCAN-ERROR" for result in audit_results):
        safe_echo("[ERROR] Une règle n'a pas pu être évaluée.", err=True)
        raise typer.Exit(code=3)
    openapi_version = load_openapi_file(file).get("openapi") if json_output else None
    scan_result = build_scan_result(file, is_pro, audit_results, openapi_version)
    if json_output:
        payload = {
            "schema_version": JSON_SCHEMA_VERSION,
            "tool": {"name": "speculynx", "version": __version__},
            "input": scan_result["input"],
            "scan": {
                "mode": scan_result["scan_mode"],
                "coverage": {
                    "status": scan_result["coverage_status"],
                    "rules_executed": len(scan_result["rules_executed"]),
                    "rules_skipped": len(scan_result["rules_skipped"]),
                    "executed_rule_ids": [rule["id"] for rule in scan_result["rules_executed"]],
                    "skipped_rule_ids": [rule["id"] for rule in scan_result["rules_skipped"]],
                },
            },
            "summary": scan_result["summary"],
            "findings": scan_result["findings"],
            "verdict": scan_result["verdict"],
        }
        typer.echo(jsonlib.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        _print_scan_results(audit_results, scan_result)

    if export:
        if is_pro:
            generate_pdf_report(file.name, audit_results, export)
            safe_echo(f"[OK] Rapport exporté : {export}")
        else:
            safe_echo(typer.style("[ERROR] Export refusé. Membres Pro uniquement.", fg=typer.colors.RED), err=True)
            raise typer.Exit(code=4)

    if _threshold_reached(scan_result["findings"], fail_on):
        raise typer.Exit(code=1)

@app.command(name="scan-live")
def scan_live(
    file: Path = typer.Option(..., "--file", "-f", help="Fichier OpenAPI à auditer.", exists=True),
    target: str = typer.Option(..., "--target", "-t", help="URL de base de l'API cible (ex: https://api.example.com)"),
    export: Optional[Path] = typer.Option(None, "--export", "-e", help="[Pro] Exporter le rapport PDF."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirme l'autorisation sans prompt interactif (ex: usage en CI)."),
    insecure: bool = typer.Option(False, "--insecure", help="Désactive la vérification TLS (déconseillé, sauf certificat auto-signé connu)."),
    allow_unsafe_methods: bool = typer.Option(False, "--allow-unsafe-methods", help="Autorise explicitement POST, PUT, PATCH et DELETE pendant scan-live."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Affiche les requêtes prévues sans envoyer de requêtes HTTP.")
):
    """[Pro] Lance un audit DAST : envoie de vraies requêtes à l'API cible."""
    saved_key = _load_saved_license_key()
    is_pro = False
    if saved_key:
        license_info = verify_license_online(saved_key)
        if license_info.get("valid") is True:
            is_pro = True
        elif license_info.get("status") not in {"network_error", "unavailable"}:
            _delete_saved_license_key()

    if not is_pro:
        safe_echo(typer.style("[ERROR] scan-live est réservé aux membres Pro.", fg=typer.colors.RED))
        safe_echo("[ACTION] Abonnez-vous sur https://speculynx.dev")
        raise typer.Exit(code=1)

    safe_echo(typer.style("[PRO] Mode Pro activé - DAST", fg=typer.colors.MAGENTA, bold=True))
    safe_echo(typer.style(f"[TARGET] Cible : {target}", fg=typer.colors.CYAN))
    safe_echo(typer.style("[WARN] Des requêtes réelles vont être envoyées à l'API cible.\n", fg=typer.colors.YELLOW))
    if not allow_unsafe_methods:
        safe_echo("[SAFE] Par défaut, scan-live n'envoie que des requêtes GET. POST, PUT, PATCH et DELETE sont désactivées.")
    if dry_run:
        safe_echo("[DRY-RUN] Mode simulation : aucune requête HTTP ne sera envoyée.")

    if not yes:
        confirmed = typer.confirm(
            f"Confirmez-vous être autorisé à tester '{target}' "
            "(propriétaire du système ou autorisation écrite obtenue) ?"
        )
        if not confirmed:
            safe_echo(typer.style("[ERROR] Scan annulé : autorisation non confirmée.", fg=typer.colors.RED))
            raise typer.Exit(code=1)

    dast_results = run_dast_audit(
        file,
        target,
        insecure=insecure,
        allow_unsafe_methods=allow_unsafe_methods,
        dry_run=dry_run,
    )
    _print_results(dast_results)

    if export:
        generate_pdf_report(file.name, dast_results, export)
        safe_echo(f"[OK] Rapport DAST exporté : {export}")

def _print_results(results: list):
    safe_echo("")
    passed_count = sum(1 for r in results if r["passed"])
    failed_count = len(results) - passed_count
    for result in results:
        badge = "[DAST]" if result.get("dynamic") else "[SCAN]"
        if result["passed"]:
            safe_echo(typer.style(f"{badge} [OK] {result['name']}", fg=typer.colors.GREEN))
        else:
            safe_echo(typer.style(f"{badge} [FINDING] [{result['severity']}] {result['name']}", fg=typer.colors.RED))
            safe_echo(f"   -> {result['fail_message']}")
    safe_echo("")
    safe_echo(typer.style(f"[RESULT] Résultat : {passed_count} OK / {failed_count} échec(s)", bold=True))


def _print_scan_results(results: list, scan_result: dict) -> None:
    safe_echo("")
    safe_echo(f"Règles exécutées : {len(scan_result['rules_executed'])}")
    safe_echo(f"Règles non exécutées : {len(scan_result['rules_skipped'])}")
    safe_echo("")
    safe_echo("Contrôles exécutés")
    for rule in scan_result["rules_executed"]:
        safe_echo(f"[CHECK] {rule['id']} — {rule['name']}")
    if scan_result["rules_skipped"]:
        safe_echo("")
        safe_echo("Contrôles non exécutés")
        for rule in scan_result["rules_skipped"]:
            safe_echo(f"[SKIP] {rule['id']} — {rule['name']} : non analysé dans ce mode")
    safe_echo("")
    for result in results:
        if not result["passed"]:
            safe_echo(typer.style(f"[FINDING] [{result['severity']}] {result['name']}", fg=typer.colors.RED))
            safe_echo(f"   -> {result['fail_message']}")
    count = scan_result["summary"]["total_findings"]
    safe_echo(f"{count} problème{'s' if count != 1 else ''} détecté{'s' if count != 1 else ''} parmi {len(scan_result['rules_executed'])} règles exécutées.")
    safe_echo(f"Couverture : {'partielle' if scan_result['coverage_status'] == 'partial' else 'complète'}")
    verdicts = {
        "indeterminate": "indéterminé",
        "findings_detected": "risques détectés",
        "no_findings_full_coverage": "aucun finding dans la couverture exécutée",
    }
    safe_echo(f"Verdict global : {verdicts[scan_result['verdict']]}")
    safe_echo("Ce résultat ne constitue pas une validation complète de la sécurité de l’API.")


def _threshold_reached(findings: list, fail_on: FailOn) -> bool:
    if fail_on == FailOn.never:
        return False
    ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = ranks[fail_on.value]
    return any(ranks.get(finding.get("severity"), 0) >= threshold for finding in findings)

if __name__ == "__main__":
    app()
