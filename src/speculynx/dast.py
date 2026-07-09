import httpx
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
import typer


SAFE_METHODS = {"get"}
UNSAFE_METHODS = {"post", "put", "patch", "delete"}

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

def is_private_or_local_target(base_url: str) -> bool:
    host = urlparse(base_url).hostname
    if not host:
        return False
    host = host.lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_unspecified


def planned_requests(openapi_data: dict, base_url: str, *, allow_unsafe_methods: bool) -> list[tuple[str, str]]:
    requests = []
    paths = openapi_data.get("paths", {})
    allowed_methods = SAFE_METHODS | (UNSAFE_METHODS if allow_unsafe_methods else set())
    for path, methods in list(paths.items())[:5]:
        if not isinstance(methods, dict):
            continue
        path_params = get_path_params(methods)
        url = forge_url(base_url, path, path_params)
        for method in ["get", "post", "put", "patch", "delete"]:
            if method in methods and method in allowed_methods:
                requests.append((method.upper(), url))
    return requests


def check_dast_auth_bypass(
    client: httpx.Client,
    base_url: str,
    openapi_data: dict,
    *,
    allow_unsafe_methods: bool = False,
) -> dict:
    """DAST-01 : Vérifie si des endpoints répondent 200 sans authentification."""
    findings = []
    paths = openapi_data.get("paths", {})
    allowed_methods = SAFE_METHODS | (UNSAFE_METHODS if allow_unsafe_methods else set())

    for path, methods in list(paths.items())[:5]:  # limite à 5 paths pour le MVP
        if not isinstance(methods, dict):
            continue
        path_params = get_path_params(methods)
        url = forge_url(base_url, path, path_params)
        for method in ["get", "post", "put", "patch", "delete"]:
            if method not in methods or method not in allowed_methods:
                continue
            try:
                resp = client.request(method.upper(), url, timeout=5)
                if resp.status_code == 200:
                    findings.append(f"{method.upper()} {url} -> 200 sans token")
            except Exception:
                pass

    passed = len(findings) == 0
    return {
        "id": "DAST-01",
        "name": "Auth Bypass",
        "severity": "CRITIQUE",
        "passed": passed,
        "dynamic": True,
        "description": "Envoie des requêtes sans token et vérifie si l'API répond 200. Par défaut, seules les méthodes GET sont envoyées.",
        "fail_message": f"Endpoints accessibles sans auth : {findings}" if findings else None
    }


def check_dast_verbose_errors(
    client: httpx.Client,
    base_url: str,
    openapi_data: dict,
    *,
    allow_unsafe_methods: bool = False,
) -> dict:
    """DAST-03 : Envoie des données malformées (non destructrices) et cherche des stack traces.

    IMPORTANT : les payloads ci-dessous sont volontairement non-destructeurs.
    Aucune syntaxe SQL/NoSQL exécutable n'est envoyée, pour éviter qu'une faille
    d'injection réelle côté client ne cause une perte de données pendant l'audit
    (ex: un ancien payload '; DROP TABLE users; --' pouvait être exécuté pour de
    vrai sur une cible vulnérable et non protégée).
    """
    if not allow_unsafe_methods:
        return {
            "id": "DAST-03",
            "name": "Verbose Errors / Info Leak",
            "severity": "ÉLEVÉE",
            "passed": True,
            "dynamic": True,
            "description": "Check ignoré par défaut car il nécessite POST/PUT. Utilisez --allow-unsafe-methods pour l'autoriser explicitement.",
            "fail_message": None
        }

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
                        findings.append(f"{method.upper()} {url} -> stack trace détectée")
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

def run_dast_audit(
    file_path: Path,
    base_url: str,
    insecure: bool = False,
    allow_unsafe_methods: bool = False,
    dry_run: bool = False,
) -> list:
    """
    Lance l'audit DAST complet.
    base_url : ex. https://api.example.com
    insecure : si True, désactive la vérification TLS (à éviter sauf certificat
               auto-signé connu et accepté explicitement par l'utilisateur).
    """
    from speculynx.scanner import load_openapi_file
    openapi_data = load_openapi_file(file_path)

    typer.echo(typer.style(f"\n[TARGET] Cible DAST : {base_url}", fg=typer.colors.CYAN))
    typer.echo(typer.style("[WARN] Mode DAST : requêtes réelles envoyées à l'API cible\n", fg=typer.colors.YELLOW))
    if not allow_unsafe_methods:
        typer.echo(typer.style("[SAFE] Méthodes non sûres désactivées par défaut : POST, PUT, PATCH, DELETE.", fg=typer.colors.YELLOW))
    if dry_run:
        typer.echo(typer.style("[DRY-RUN] Aucune requête HTTP ne sera envoyée.", fg=typer.colors.CYAN))
    if insecure:
        typer.echo(typer.style("[WARN] Vérification TLS désactivée (--insecure) - risque MITM assumé.\n", fg=typer.colors.RED))
    if is_private_or_local_target(base_url):
        typer.echo(typer.style("[WARN] Cible locale ou privée détectée. Vérifiez explicitement votre autorisation et l'environnement.", fg=typer.colors.YELLOW))

    if dry_run:
        requests = planned_requests(openapi_data, base_url, allow_unsafe_methods=allow_unsafe_methods)
        for method, url in requests:
            typer.echo(f"[DRY-RUN] {method} {url}")
        return [{
            "id": "DAST-DRY-RUN",
            "name": "Plan de scan live",
            "severity": "INFO",
            "passed": True,
            "dynamic": True,
            "description": "Dry-run exécuté sans envoyer de requêtes HTTP.",
            "fail_message": None
        }]

    # Client HTTP sans authentification (test d'auth bypass)
    with httpx.Client(verify=not insecure, follow_redirects=True) as client:
        results = [
            check_dast_auth_bypass(client, base_url, openapi_data, allow_unsafe_methods=allow_unsafe_methods),
            check_dast_verbose_errors(client, base_url, openapi_data, allow_unsafe_methods=allow_unsafe_methods),
            check_dast_rate_limit(client, base_url, openapi_data),
        ]

    return results
