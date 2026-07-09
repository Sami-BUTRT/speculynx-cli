import json
import re
import yaml
from pathlib import Path
import typer


SUPPORTED_OPENAPI_VERSION = re.compile(r"^3\.(?:0|1)\.\d+$")


def validate_openapi_version(openapi_data: dict) -> dict:
    """Refuse tout document qui n'est pas explicitement OpenAPI 3.0.x/3.1.x."""
    if not isinstance(openapi_data, dict):
        raise ValueError("Le document OpenAPI doit être un objet JSON ou YAML.")

    version = openapi_data.get("openapi")
    if not isinstance(version, str) or not SUPPORTED_OPENAPI_VERSION.fullmatch(version):
        raise ValueError(
            "Version non supportée : Speculynx accepte uniquement "
            "OpenAPI 3.0.x et 3.1.x."
        )

    return openapi_data


def load_openapi_file(file_path: Path) -> dict:
    suffix = file_path.suffix.lower()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if suffix in ['.yaml', '.yml']:
                openapi_data = yaml.safe_load(f)
            elif suffix == '.json':
                openapi_data = json.load(f)
            else:
                raise ValueError("Format non supporté (uniquement .json, .yaml, .yml).")
        return validate_openapi_version(openapi_data)
    except Exception as e:
        typer.echo(typer.style(f"❌ Erreur de chargement : {e}", fg=typer.colors.RED))
        raise typer.Exit(code=1)


def resolve_ref(ref: str, root: dict) -> dict:
    """Résout une référence locale du type '#/components/schemas/Foo'
    ou '#/definitions/Foo' (Swagger 2.0). Ne gère pas les $ref externes
    (autre fichier/URL) : retourne {} dans ce cas plutôt que de planter.
    """
    if not isinstance(ref, str) or not ref.startswith('#/'):
        return {}
    node = root
    for part in ref.lstrip('#/').split('/'):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node if isinstance(node, dict) else {}


def deref(obj, root: dict, _seen: frozenset = frozenset()):
    """Résout récursivement les $ref dans un dict/list. Renvoie une copie
    avec les références remplacées par leur contenu réel.

    _seen suit les $ref déjà traversées sur le chemin courant (pas globalement)
    pour détecter les références circulaires (ex: schéma User -> friends[] -> User)
    sans bloquer les cas légitimes où le même $ref apparaît à plusieurs endroits
    indépendants de la spec. Quand un cycle est détecté, on s'arrête et on
    renvoie un marqueur plutôt que de planter avec un RecursionError.
    """
    if isinstance(obj, dict):
        if '$ref' in obj and isinstance(obj['$ref'], str):
            ref = obj['$ref']
            if ref in _seen:
                # Cycle détecté : on ne déréférence pas plus loin, on garde
                # la référence telle quelle pour signaler son existence sans crasher.
                return {'$ref': ref, '_circular': True}
            resolved = resolve_ref(ref, root)
            return deref(resolved, root, _seen | {ref})
        return {k: deref(v, root, _seen) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deref(item, root, _seen) for item in obj]
    return obj


def get_security_schemes(openapi_data: dict) -> dict:
    """Retourne les security schemes, que la spec soit en OpenAPI 3.0
    (components.securitySchemes) ou en Swagger 2.0 (securityDefinitions).
    Les deux structures sont fusionnées si présentes (cas rare mais possible
    sur des specs migrées partiellement)."""
    schemes = {}
    components = openapi_data.get('components', {}) or {}
    schemes.update(components.get('securitySchemes', {}) or {})
    schemes.update(openapi_data.get('securityDefinitions', {}) or {})  # Swagger 2.0
    return deref(schemes, openapi_data)


def normalize_oauth2_flows(scheme: dict) -> dict:
    """Normalise les flows OAuth2 entre OpenAPI 3.0 ('flows': {implicit, ...})
    et Swagger 2.0 (champs à plat : 'flow', 'scopes' directement sur le scheme)."""
    if 'flows' in scheme:
        return scheme.get('flows', {}) or {}
    # Swagger 2.0 : un seul flow par scheme, scopes au même niveau
    flow_name = scheme.get('flow')
    if flow_name:
        return {flow_name: {"scopes": scheme.get('scopes', {})}}
    return {}

# ==============================================================================
# PACK DE RÈGLES GRATUITES (FREEMIUM)
# ==============================================================================

def check_free_key_exposure(openapi_data: dict) -> dict:
    passed = True
    vulnerable_keywords = ["key", "token", "secret", "password", "pwd", "auth", "credential"]
    resolved = deref(openapi_data, openapi_data)
    paths = resolved.get('paths', {}) or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, config in methods.items():
            if not isinstance(config, dict):
                continue
            params = config.get('parameters', []) or []
            for p in params:
                if not isinstance(p, dict):
                    continue
                if p.get('in') == 'query':
                    param_name = (p.get('name') or '').lower()
                    if any(k in param_name for k in vulnerable_keywords):
                        passed = False
                        break
    return {
        "id": "KEY-EXP-01",
        "name": "Clés exposées dans l'URL",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Vérifie si les clés API transitent de manière non sécurisée dans la Query string.",
        "fail_message": "Des clés API sont passées en paramètres de requête (Query string)."
    }

def check_free_no_expiration(openapi_data: dict) -> dict:
    """Vérifie que les schémas d'auth basés sur une clé/token statique documentent
    un mécanisme d'expiration. Cible désormais les security schemes eux-mêmes
    (description, ou présence de oauth2 avec refresh) plutôt qu'un substring
    sur toute la spec, qui matchait à tort 'example', 'expand', 'experience'.
    """
    passed = True
    expiration_keywords = ["exp", "ttl", "expire", "expiration", "duration", "refresh"]
    schemes = get_security_schemes(openapi_data)

    key_based_schemes = {
        name: s for name, s in schemes.items()
        if isinstance(s, dict) and s.get('type') in ('apiKey', 'http')
    }

    for name, scheme in key_based_schemes.items():
        description = (scheme.get('description') or '').lower()
        if not any(exp in description for exp in expiration_keywords):
            passed = False
            break

    return {
        "id": "KEY-EXP-02",
        "name": "Absence d'expiration des clés",
        "severity": "MOYENNE",
        "passed": passed,
        "description": "Vérifie si les schémas d'authentification par clé/token documentent un cycle de vie ou une expiration.",
        "fail_message": "Aucune mention d'expiration/cycle de vie trouvée dans la description des schémas d'authentification."
    }

# ==============================================================================
# PACK DE RÈGLES AVANCÉES (VERSION PRO - ZERO TRUST & AI AGENTS)
# ==============================================================================

def check_pro_identity_context(openapi_data: dict) -> dict:
    passed = True
    security_schemes = get_security_schemes(openapi_data)
    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        if scheme.get('type') == 'apiKey':
            passed = False
            break
    return {
        "id": "KEY-PRO-01",
        "name": "Manque d'identité dynamique",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Vérifie l'utilisation de protocoles d'identité modernes (OAuth2/JWT) avec contexte.",
        "fail_message": "L'API utilise des clés statiques sans contexte d'identité dynamique (IP, géo, rôle)."
    }

def check_pro_ai_agent_risk(openapi_data: dict) -> dict:
    passed = True
    resolved = deref(openapi_data, openapi_data)
    paths = resolved.get('paths', {}) or {}
    destructive_keywords = ['delete', 'drop', 'purge', 'clear', 'truncate', 'destroy', 'remove']
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        if 'delete' in methods or any(k in path.lower() for k in destructive_keywords):
            content_str = json.dumps(methods).lower()
            if not any(mfa in content_str for mfa in ['mfa', 'confirm', 'just-in-time', 'verification', 'validate']):
                passed = False
                break
    return {
        "id": "KEY-PRO-02",
        "name": "Risque d'action par Agent IA",
        "severity": "CRITIQUE",
        "passed": passed,
        "description": "Vérifie si les routes destructrices possèdent une double validation contre les bugs d'IA.",
        "fail_message": "Routes destructrices exposées à des agents IA sans validation d'intention en temps réel."
    }

def check_pro_over_permissioned(openapi_data: dict) -> dict:
    passed = True
    security_schemes = get_security_schemes(openapi_data)
    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        if scheme.get('type') == 'oauth2':
            flows = normalize_oauth2_flows(scheme)
            for flow_name, flow_data in flows.items():
                if not isinstance(flow_data, dict):
                    continue
                if not flow_data.get('scopes'):
                    passed = False
                    break
    return {
        "id": "KEY-PRO-03",
        "name": "Permissions sur-permissionnées",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Vérifie si le contrôle d'accès applique le principe du moindre privilège via des scopes.",
        "fail_message": "L'accès à l'API ne définit pas de restrictions par granularité fine (scopes)."
    }

# ==============================================================================
# CHEF D'ORCHESTRE
# ==============================================================================

def run_audit(file_path: Path, is_pro: bool = False) -> list:
    openapi_data = load_openapi_file(file_path)
    rules_to_run = [check_free_key_exposure, check_free_no_expiration]
    if is_pro:
        rules_to_run.extend([check_pro_identity_context, check_pro_ai_agent_risk, check_pro_over_permissioned])

    results = []
    for rule in rules_to_run:
        try:
            results.append(rule(openapi_data))
        except Exception as e:
            results.append({
                "id": "SCAN-ERROR",
                "name": f"Échec de la règle {rule.__name__}",
                "severity": "INFO",
                "passed": True,  # ne bloque pas l'audit, mais on ne masque pas le problème
                "description": "Une règle n'a pas pu être évaluée sur cette spec.",
                "fail_message": f"Erreur interne : {e}"
            })
    return results
