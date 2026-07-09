import httpx
import json
import time
from pathlib import Path
from typing import Optional
import typer

# ==============================================================================
# FORGE DE REQUÊTES
# ==============================================================================

def forge_url(base_url: str, path: str, params: dict) -> str:
    """Remplace les path params {id} par des valeurs de test."""
    url = base_url.rstrip("/") + path
    for param_name in params:
        url = url.replace(f"{{{param_name}}}", "1")
    return url

def get_path_params(methods: dict) -> dict:
    """Extrait les paramètres de path depuis la spec."""
    params = {}
    for method, config in methods.items():
        if isinstance(config, dict):
            for p in config.get("parameters", []):
                if p.get("in") == "path":
                    params[p.get("name")] = "1"
    return params

# ==============================================================================
# CHECKS DAST
# ==============================================================================

def check_dast_auth_bypass(client: httpx.Client, base_url: str, openapi_data: dict) -> dict:
    """DAST-01 : Vérifie si des endpoints répondent 200 sans authentification."""
    findings = []
    paths = openapi_data.get("paths", {})

    for path, methods in list(paths.items())[:5]:  # limite à 5 paths pour le MVP
        path_params = get_path_params(methods)
        url = forge_url(base_url, path, path_params)
        for method in ["get", "post", "put", "delete"]:
            if method not in methods:
                continue
            try:
                resp = client.request(method.upper(), url, timeout=5)
                if resp.status_code == 200:
                    findings.append(f"{method.upper()} {url} → 200 sans token")
            except Exception:
                pass

    passed = len(findings) == 0
    return {
        "id": "DAST-01",
        "name": "Auth Bypass",
        "severity": "CRITIQUE",
        "passed": passed,
        "dynamic": True,
        "description": "Envoie des requêtes sans token et vérifie si l'API répond 200.",
        "fail_message": f"Endpoints accessibles sans auth : {findings}" if findings else None
    }


def check_dast_verbose_errors(client: httpx.Client, base_url: str, openapi_data: dict) -> dict:
    """DAST-03 : Envoie des données malformées (non destructrices) et cherche des stack traces.

    IMPORTANT : les payloads ci-dessous sont volontairement non-destructeurs.
    Aucune syntaxe SQL/NoSQL exécutable n'est envoyée, pour éviter qu'une faille
    d'injection réelle côté client ne cause une perte de données pendant l'audit
    (ex: un ancien payload '; DROP TABLE users; --' pouvait être exécuté pour de
    vrai sur une cible vulnérable et non protégée).
    """
    findings = []
    paths = openapi_data.get("paths", {})
    error_keywords = ["traceback", "exception", "error at line", "syntaxerror",
                      "nameerror", "typeerror", "file \"/", "line "]

    # Payloads conçus pour casser le parsing/la validation type, jamais l'exécution SQL.
    malformed_payloads = [
        {"id": "x" * 5000, "value": None},          # overflow de longueur
        {"id": -99999999999999999999, "value": []}, # type/range invalide
        {"id": {"unexpected": "nested_object"}},     # structure inattendue
    ]

    for path, methods in list(paths.items())[:5]:
        path_params = get_path_params(methods)
        url = forge_url(base_url, path, path_params)
        if "post" in methods or "put" in methods:
            method = "post" if "post" in methods else "put"
            for payload in malformed_payloads:
                try:
                    resp = client.request(
                        method.upper(), url,
                        json=payload,
                        timeout=5
                    )
                    body = resp.text.lower()
                    if any(kw in body for kw in error_keywords):
                        findings.append(f"{method.upper()} {url} → stack trace détectée")
                        break  # un seul finding par endpoint suffit
                except Exception:
                    pass

    passed = len(findings) == 0
    return {
        "id": "DAST-03",
        "name": "Verbose Errors / Info Leak",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "dynamic": True,
        "description": "Envoie des payloads malformés et détecte les stack traces dans les réponses.",
        "fail_message": f"Info leak détecté : {findings}" if findings else None
    }


def check_dast_rate_limit(client: httpx.Client, base_url: str, openapi_data: dict) -> dict:
    """DAST-05 : Envoie 20 requêtes rapides et vérifie si un 429 est retourné."""
    paths = openapi_data.get("paths", {})
    if not paths:
        return {"id": "DAST-05", "passed": True, "dynamic": True,
                "name": "Rate Limiting", "severity": "MOYENNE",
                "description": "Aucun path trouvé.", "fail_message": None}

    first_path = list(paths.keys())[0]
    path_params = get_path_params(paths[first_path])
    url = forge_url(base_url, first_path, path_params)

    got_429 = False
    for _ in range(20):
        try:
            resp = client.get(url, timeout=3)
            if resp.status_code == 429:
                got_429 = True
                break
        except Exception:
            break

    return {
        "id": "DAST-05",
        "name": "Rate Limiting absent",
        "severity": "MOYENNE",
        "passed": got_429,
        "dynamic": True,
        "description": "Envoie 20 requêtes rapides et vérifie si l'API applique un rate limit (HTTP 429).",
        "fail_message": f"Aucun rate limit détecté sur {url} après 20 requêtes." if not got_429 else None
    }

# ==============================================================================
# CHEF D'ORCHESTRE DAST
# ==============================================================================

def run_dast_audit(file_path: Path, base_url: str, insecure: bool = False) -> list:
    """
    Lance l'audit DAST complet.
    base_url : ex. https://api.example.com
    insecure : si True, désactive la vérification TLS (à éviter sauf certificat
               auto-signé connu et accepté explicitement par l'utilisateur).
    """
    from speculynx.scanner import load_openapi_file
    openapi_data = load_openapi_file(file_path)

    typer.echo(typer.style(f"\n🌐 Cible DAST : {base_url}", fg=typer.colors.CYAN))
    typer.echo(typer.style("⚠️  Mode DAST : requêtes réelles envoyées à l'API cible\n", fg=typer.colors.YELLOW))
    if insecure:
        typer.echo(typer.style("⚠️  Vérification TLS désactivée (--insecure) — risque MITM assumé.\n", fg=typer.colors.RED))

    # Client HTTP sans authentification (test d'auth bypass)
    with httpx.Client(verify=not insecure, follow_redirects=True) as client:
        results = [
            check_dast_auth_bypass(client, base_url, openapi_data),
            check_dast_verbose_errors(client, base_url, openapi_data),
            check_dast_rate_limit(client, base_url, openapi_data),
        ]

    return results
