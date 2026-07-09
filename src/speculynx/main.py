import typer
from typing import Optional
from pathlib import Path
from speculynx.scanner import run_audit
from speculynx.dast import run_dast_audit
from speculynx.utils import (
    LicenseKeyStorageError,
    delete_license_key,
    generate_pdf_report,
    load_license_key,
    save_license_key,
    verify_license_online,
)

app = typer.Typer(
    name="speculynx",
    help="Speculynx : L'outil CLI d'audit de sécurité pour API REST.",
    add_completion=False
)

def _load_saved_license_key(*, allow_free_on_error: bool = False) -> str | None:
    try:
        return load_license_key()
    except LicenseKeyStorageError as error:
        if allow_free_on_error:
            typer.echo(
                typer.style(
                    f"[WARN] {error} Scan poursuivi en mode Free.",
                    fg=typer.colors.YELLOW,
                ),
                err=True,
            )
            return None
        typer.echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
        raise typer.Exit(code=1) from error


def _delete_saved_license_key() -> None:
    try:
        delete_license_key()
    except LicenseKeyStorageError as error:
        typer.echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
        raise typer.Exit(code=1) from error

@app.command()
def login():
    """Connecte la CLI à votre compte Speculynx Pro."""
    typer.echo(typer.style("[LOGIN] Connexion à Speculynx Pro", fg=typer.colors.MAGENTA, bold=True))
    api_key = typer.prompt("Entrez votre clé de licence Speculynx Pro", hide_input=True)
    typer.echo("Vérification auprès du serveur cloud...")
    license_info = verify_license_online(api_key)
    if license_info.get("valid") is True:
        try:
            save_license_key(api_key)
        except LicenseKeyStorageError as error:
            typer.echo(typer.style(f"[ERROR] {error}", fg=typer.colors.RED), err=True)
            raise typer.Exit(code=1) from error
        typer.echo(typer.style("[OK] Authentification réussie !", fg=typer.colors.GREEN, bold=True))
    elif license_info.get("status") in {"network_error", "unavailable"}:
        typer.echo(typer.style("[WARN] Service de licence indisponible.", fg=typer.colors.YELLOW))
    else:
        typer.echo(typer.style("[FAIL] Clé invalide.", fg=typer.colors.RED))


@app.command()
def logout():
    """Supprime la clé Pro du coffre sécurisé du système."""
    _delete_saved_license_key()
    typer.echo("[OK] Licence locale supprimée du coffre sécurisé.")

@app.command()
def info():
    """Affiche les détails de votre licence actuelle."""
    saved_key = _load_saved_license_key()
    if not saved_key:
        typer.echo("Aucune licence trouvée. Faites 'speculynx login'.")
        return
    license_info = verify_license_online(saved_key)
    if license_info.get("valid") is True:
        typer.echo(typer.style("[PRO] État : Speculynx Pro", fg=typer.colors.CYAN, bold=True))
    elif license_info.get("status") in {"network_error", "unavailable"}:
        typer.echo(typer.style("[WARN] Vérification Pro temporairement indisponible.", fg=typer.colors.YELLOW))
    else:
        typer.echo(typer.style("[FREE] État : Speculynx Free", fg=typer.colors.YELLOW, bold=True))
        _delete_saved_license_key()

@app.command()
def scan(
    file: Path = typer.Option(..., "--file", "-f", help="Fichier OpenAPI à auditer.", exists=True),
    export: Optional[Path] = typer.Option(None, "--export", "-e", help="[Pro] Exporter le rapport PDF.")
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

    typer.echo(typer.style("[PRO] Mode Pro activé", fg=typer.colors.MAGENTA, bold=True) if is_pro else typer.style("[FREE] Mode Free", fg=typer.colors.YELLOW))
    audit_results = run_audit(file, is_pro=is_pro)
    _print_results(audit_results)

    if export:
        if is_pro:
            generate_pdf_report(file.name, audit_results, export)
            typer.echo(f"[OK] Rapport exporté : {export}")
        else:
            typer.echo(typer.style("[ERROR] Export refusé. Membres Pro uniquement.", fg=typer.colors.RED))

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
        typer.echo(typer.style("[ERROR] scan-live est réservé aux membres Pro.", fg=typer.colors.RED))
        typer.echo("[ACTION] Abonnez-vous sur https://speculynx.dev")
        raise typer.Exit(code=1)

    typer.echo(typer.style("[PRO] Mode Pro activé - DAST", fg=typer.colors.MAGENTA, bold=True))
    typer.echo(typer.style(f"[TARGET] Cible : {target}", fg=typer.colors.CYAN))
    typer.echo(typer.style("[WARN] Des requêtes réelles vont être envoyées à l'API cible.\n", fg=typer.colors.YELLOW))
    if not allow_unsafe_methods:
        typer.echo("[SAFE] Par défaut, scan-live n'envoie que des requêtes GET. POST, PUT, PATCH et DELETE sont désactivées.")
    if dry_run:
        typer.echo("[DRY-RUN] Mode simulation : aucune requête HTTP ne sera envoyée.")

    if not yes:
        confirmed = typer.confirm(
            f"Confirmez-vous être autorisé à tester '{target}' "
            "(propriétaire du système ou autorisation écrite obtenue) ?"
        )
        if not confirmed:
            typer.echo(typer.style("[ERROR] Scan annulé : autorisation non confirmée.", fg=typer.colors.RED))
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
        typer.echo(f"[OK] Rapport DAST exporté : {export}")

def _print_results(results: list):
    typer.echo("")
    passed_count = sum(1 for r in results if r["passed"])
    failed_count = len(results) - passed_count
    for result in results:
        badge = "[DAST]" if result.get("dynamic") else "[SCAN]"
        if result["passed"]:
            typer.echo(typer.style(f"{badge} [OK] {result['name']}", fg=typer.colors.GREEN))
        else:
            typer.echo(typer.style(f"{badge} [FINDING] [{result['severity']}] {result['name']}", fg=typer.colors.RED))
            typer.echo(f"   -> {result['fail_message']}")
    typer.echo("")
    typer.echo(typer.style(f"[RESULT] Résultat : {passed_count} OK / {failed_count} échec(s)", bold=True))

if __name__ == "__main__":
    app()
