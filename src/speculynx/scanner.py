import json
import re
import yaml
from pathlib import Path
import typer


SUPPORTED_OPENAPI_VERSION = re.compile(r"^3\.(?:0|1)\.\d+$")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
SENSITIVE_METHODS = {"post", "put", "patch", "delete"}
SENSITIVE_PATH_KEYWORDS = (
    "/admin",
    "/user",
    "/users",
    "/account",
    "/orders",
    "/payments",
    "/settings",
    "/profile",
)
PUBLIC_GET_PATHS = {"/health", "/status", "/docs", "/openapi.json", "/ping"}
OBJECT_PATH_KEYWORDS = (
    "/users/",
    "/accounts/",
    "/orders/",
    "/invoices/",
    "/payments/",
    "/documents/",
    "/files/",
    "/projects/",
    "/organizations/",
    "/tenants/",
    "/customers/",
    "/profiles/",
)
OBJECT_PARAM_NAMES = {
    "id",
    "userid",
    "accountid",
    "orderid",
    "invoiceid",
    "paymentid",
    "fileid",
    "documentid",
    "projectid",
    "orgid",
    "tenantid",
    "customerid",
    "profileid",
}
PRIVILEGED_PATH_KEYWORDS = (
    "/admin",
    "/admins",
    "/internal",
    "/management",
    "/manage",
    "/superuser",
    "/staff",
    "/moderation",
    "/billing",
    "/roles",
    "/permissions",
    "/settings",
    "/config",
)
PRIVILEGED_OPERATION_KEYWORDS = (
    "admin",
    "deleteuser",
    "updaterole",
    "assignrole",
    "grantpermission",
    "revokepermission",
    "manage",
    "internal",
    "staff",
)
BROAD_SCOPES = {"*", "admin", "write", "all", "full_access"}
HIGH_SENSITIVE_FIELDS = {
    "password",
    "pass",
    "secret",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "privatekey",
    "ssn",
    "socialsecuritynumber",
    "nationalid",
    "iban",
    "creditcard",
    "cardnumber",
    "cvv",
    "session",
    "cookie",
    "authorization",
}
MEDIUM_SENSITIVE_FIELDS = {"birthdate", "dateofbirth", "email", "phone", "address", "ip"}
SSRF_FIELD_NAMES = {
    "url",
    "uri",
    "callback",
    "callbackurl",
    "webhook",
    "webhookurl",
    "redirect",
    "redirecturl",
    "returnurl",
    "nexturl",
    "target",
    "targeturl",
    "endpoint",
    "imageurl",
    "avatarurl",
    "feedurl",
    "importurl",
    "sourceurl",
}
SSRF_PATH_KEYWORDS = (
    "fetch",
    "import",
    "webhook",
    "callback",
    "redirect",
    "preview",
    "proxy",
    "download",
    "upload",
)
RATE_LIMIT_PATH_KEYWORDS = (
    "/login",
    "/auth",
    "/password-reset",
    "/reset-password",
    "/forgot-password",
    "/otp",
    "/mfa",
    "/verify",
    "/search",
    "/export",
    "/import",
    "/upload",
    "/download",
    "/report",
    "/generate",
    "/ai",
    "/chat",
    "/payment",
    "/checkout",
)
PLACEHOLDER_VALUES = {
    "string",
    "example",
    "changeme",
    "your-api-key",
    "redacted",
    "<token>",
    "placeholder",
}
SECRET_VALUE_PATTERNS = [
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{10,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}\b", re.IGNORECASE),
]


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
        typer.echo(typer.style(f"[ERROR] Erreur de chargement : {e}", fg=typer.colors.RED))
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


def has_usable_security(security, security_schemes: dict) -> bool:
    if not isinstance(security, list) or not security:
        return False
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        if any(scheme_name in security_schemes for scheme_name in requirement):
            return True
    return False


def is_public_get_path(method: str, path: str) -> bool:
    return method.lower() == "get" and path.rstrip("/") in PUBLIC_GET_PATHS


def is_sensitive_operation(method: str, path: str) -> bool:
    method = method.lower()
    path = path.lower()
    return (
        method in SENSITIVE_METHODS
        or any(keyword in path for keyword in SENSITIVE_PATH_KEYWORDS)
    )


def normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def iter_operations(openapi_data: dict):
    paths = openapi_data.get('paths', {}) or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, config in methods.items():
            method = method.lower()
            if method in HTTP_METHODS and isinstance(config, dict):
                yield path, method, config


def operation_security(config: dict, openapi_data: dict):
    if 'security' in config:
        return config.get('security')
    return openapi_data.get('security')


def has_precise_authorization(security, security_schemes: dict) -> bool:
    if not isinstance(security, list) or not security:
        return False
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name, scopes in requirement.items():
            scheme = security_schemes.get(scheme_name)
            if not isinstance(scheme, dict):
                continue
            if scheme.get('type') in {'oauth2', 'openIdConnect'}:
                if any(str(scope).lower() not in BROAD_SCOPES for scope in scopes or []):
                    return True
    return False


def walk_values(node, path: tuple = ()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield path + (str(key),), value
            yield from walk_values(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield path + (str(index),), value
            yield from walk_values(value, path + (str(index),))

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

def check_free_insecure_http_server(openapi_data: dict) -> dict:
    passed = True
    servers = openapi_data.get('servers', []) or []
    for server in servers:
        if not isinstance(server, dict):
            continue
        url = server.get('url')
        if isinstance(url, str) and url.lower().startswith('http://'):
            passed = False
            break
    return {
        "id": "HTTP-001",
        "name": "HTTP non sécurisé",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Vérifie si l'API est documentée avec une URL serveur en HTTP non chiffré.",
        "fail_message": "L'API est documentée comme accessible en clair via HTTP, ce qui expose requêtes, tokens et données à l'interception."
    }

def check_free_missing_authentication(openapi_data: dict) -> dict:
    passed = True
    security_schemes = get_security_schemes(openapi_data)
    global_security = openapi_data.get('security')
    global_auth = has_usable_security(global_security, security_schemes)
    operation_auth_found = False
    unprotected_sensitive_operations = []
    paths = openapi_data.get('paths', {}) or {}

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, config in methods.items():
            method = method.lower()
            if method not in HTTP_METHODS or not isinstance(config, dict):
                continue
            if 'security' in config:
                operation_auth = has_usable_security(config.get('security'), security_schemes)
            else:
                operation_auth = global_auth

            if operation_auth:
                operation_auth_found = True
                continue
            if is_sensitive_operation(method, path) and not is_public_get_path(method, path):
                unprotected_sensitive_operations.append(f"{method.upper()} {path}")

    if not global_auth and not operation_auth_found:
        passed = False
    if unprotected_sensitive_operations:
        passed = False

    return {
        "id": "AUTH-001",
        "name": "Authentification manquante",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Vérifie si la spec documente un mécanisme d'authentification utilisé globalement ou par opération.",
        "fail_message": "Certaines routes semblent accessibles sans mécanisme d'authentification documenté."
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

def check_pro_bola_patterns(openapi_data: dict) -> dict:
    findings = []
    security_schemes = get_security_schemes(openapi_data)
    for path, method, config in iter_operations(openapi_data):
        if is_public_get_path(method, path) or method not in {"get", "put", "patch", "delete"}:
            continue
        params = config.get('parameters', []) or []
        path_param_names = {
            normalize_identifier(p.get('name') or '')
            for p in params
            if isinstance(p, dict) and p.get('in') == 'path'
        }
        path_lower = path.lower()
        has_object_path = any(keyword in f"{path_lower}/" for keyword in OBJECT_PATH_KEYWORDS)
        has_object_param = bool(path_param_names & OBJECT_PARAM_NAMES)
        if "{" in path and (has_object_path or has_object_param):
            security = operation_security(config, openapi_data)
            auth_note = "auth documentée" if has_usable_security(security, security_schemes) else "auth non documentée"
            findings.append(f"{method.upper()} {path} ({auth_note})")

    passed = not findings
    return {
        "id": "BOLA-001",
        "name": "Risque BOLA potentiel",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Repère les routes objet avec identifiant utilisateur, compte ou tenant.",
        "fail_message": (
            "Pattern à risque détecté : route objet avec identifiant direct "
            f"({', '.join(findings[:3])}). Ce n'est pas une preuve de BOLA. "
            "L'analyse statique ne permet pas de confirmer une vulnérabilité runtime. "
            "À vérifier côté backend : contrôle propriétaire de la ressource, "
            "isolation tenant, user_id/account_id et règles d'autorisation."
        ) if findings else None
    }

def check_pro_bfla_privileged_routes(openapi_data: dict) -> dict:
    findings = []
    security_schemes = get_security_schemes(openapi_data)
    for path, method, config in iter_operations(openapi_data):
        path_lower = path.lower()
        operation_id = normalize_identifier(str(config.get('operationId') or ''))
        privileged_path = (
            any(keyword in path_lower for keyword in PRIVILEGED_PATH_KEYWORDS)
            or re.search(r"/users/\{[^}]+\}/(?:role|permissions)", path_lower)
        )
        privileged_operation = any(keyword in operation_id for keyword in PRIVILEGED_OPERATION_KEYWORDS)
        if not privileged_path and not privileged_operation:
            continue

        security = operation_security(config, openapi_data)
        if not has_usable_security(security, security_schemes):
            findings.append(f"{method.upper()} {path} sans security exploitable")
        elif not has_precise_authorization(security, security_schemes):
            findings.append(f"{method.upper()} {path} sans scopes précis documentés")

    passed = not findings
    return {
        "id": "BFLA-001",
        "name": "Route privilégiée à vérifier",
        "severity": "ÉLEVÉE",
        "passed": passed,
        "description": "Repère les routes administratives ou privilégiées sans autorisation fine documentée.",
        "fail_message": (
            "Cette route semble liée à une fonction privilégiée "
            f"({', '.join(findings[:3])}). Cela peut indiquer un risque BFLA "
            "si les rôles/scopes ne sont pas vérifiés côté serveur. L'analyse "
            "statique ne confirme pas une faille runtime. À vérifier : scopes "
            "ou rôles précis, règles d'autorisation et séparation des privilèges."
        ) if findings else None
    }

def check_pro_sensitive_data(openapi_data: dict) -> dict:
    high_matches = []
    medium_matches = []
    roots = [
        ('components.schemas', ((openapi_data.get('components') or {}).get('schemas') or {})),
        ('paths', openapi_data.get('paths', {}) or {}),
    ]
    for root_name, root in roots:
        for path, value in walk_values(root):
            field_name = normalize_identifier(path[-1])
            location = ".".join((root_name,) + path)
            if field_name in HIGH_SENSITIVE_FIELDS:
                high_matches.append(location)
            elif field_name in MEDIUM_SENSITIVE_FIELDS:
                medium_matches.append(location)

    findings = high_matches or medium_matches
    severity = "ÉLEVÉE" if high_matches else "MOYENNE"
    return {
        "id": "DATA-001",
        "name": "Données sensibles exposées dans les schémas",
        "severity": severity,
        "passed": not findings,
        "description": "Repère les champs potentiellement sensibles dans schemas, réponses ou corps de requête.",
        "fail_message": (
            "Cette spec documente des champs potentiellement sensibles "
            f"({', '.join(findings[:5])}). Ce signal doit être confirmé "
            "manuellement selon le contexte métier. Vérifiez que ces données "
            "sont nécessaires, minimisées, masquées ou protégées par un contrôle "
            "d'accès côté serveur."
        ) if findings else None
    }

def looks_like_secret_value(key: str, value: str) -> bool:
    cleaned = value.strip()
    lowered = cleaned.lower()
    if lowered in PLACEHOLDER_VALUES or lowered.startswith("<") or len(cleaned) < 8:
        return False
    if any(pattern.search(cleaned) for pattern in SECRET_VALUE_PATTERNS):
        return True
    key_name = normalize_identifier(key)
    secret_key = any(marker in key_name for marker in ("apikey", "token", "secret", "password"))
    return secret_key and len(cleaned) >= 16 and " " not in cleaned

def check_pro_secret_examples(openapi_data: dict) -> dict:
    findings = []
    value_keys = {"example", "default", "enum", "description"}
    for path, value in walk_values(openapi_data):
        if not path:
            continue
        key = path[-1]
        parent_key = path[-2] if len(path) > 1 else key
        if isinstance(value, str) and (key in value_keys or normalize_identifier(parent_key) in HIGH_SENSITIVE_FIELDS):
            if looks_like_secret_value(parent_key, value):
                findings.append(".".join(path))
        elif isinstance(value, list) and key == "enum":
            for item in value:
                if isinstance(item, str) and looks_like_secret_value(parent_key, item):
                    findings.append(".".join(path))
                    break

    return {
        "id": "SECRET-001",
        "name": "Secret potentiel dans exemple ou schéma",
        "severity": "ÉLEVÉE",
        "passed": not findings,
        "description": "Repère les valeurs ressemblant à des secrets réels dans les examples, defaults, enums ou descriptions.",
        "fail_message": (
            "Une valeur ressemble à un secret réel dans la documentation OpenAPI "
            f"({', '.join(findings[:5])}). Ce n'est pas une confirmation de "
            "validité du secret. À vérifier : révocation/rotation si la valeur "
            "est réelle, puis remplacement par un placeholder neutre."
        ) if findings else None
    }

def check_pro_ssrf_inputs(openapi_data: dict) -> dict:
    findings = []
    for path, method, config in iter_operations(openapi_data):
        path_lower = path.lower()
        risky_endpoint = method in {"post", "put", "patch"} or any(keyword in path_lower for keyword in SSRF_PATH_KEYWORDS)
        if not risky_endpoint:
            continue
        resolved_config = deref(config, openapi_data)
        for value_path, value in walk_values(resolved_config):
            field_name = normalize_identifier(value_path[-1])
            if field_name == "name" and isinstance(value, str):
                field_name = normalize_identifier(value)
            if field_name in SSRF_FIELD_NAMES:
                findings.append(f"{method.upper()} {path} champ {value}")
                break

    return {
        "id": "SSRF-001",
        "name": "Entrée URL contrôlée par l'utilisateur",
        "severity": "ÉLEVÉE",
        "passed": not findings,
        "description": "Repère les opérations qui acceptent une URL ou cible fournie par le client ; le risque dépend de l'usage serveur.",
        "fail_message": (
            "Cette opération accepte une URL fournie par le client "
            f"({', '.join(findings[:3])}). Si le serveur la contacte sans "
            "validation stricte, cela peut créer un risque SSRF. L'analyse statique "
            "ne confirme pas l'usage backend de cette URL. À vérifier : "
            "allowlist, blocage des réseaux internes, validation de schéma et résolution DNS."
        ) if findings else None
    }

def has_rate_limit_documentation(config: dict) -> bool:
    text = json.dumps(config).lower()
    if any(keyword in text for keyword in ("rate limit", "ratelimit", "quota", "throttling", "limite de débit", "x-rate-limit", "x-ratelimit")):
        return True
    responses = config.get('responses', {}) or {}
    if '429' in responses:
        return True
    for response in responses.values():
        if not isinstance(response, dict):
            continue
        headers = response.get('headers', {}) or {}
        header_names = {name.lower() for name in headers}
        if header_names & {"x-ratelimit-limit", "x-ratelimit-remaining", "retry-after"}:
            return True
    return False

def check_pro_rate_limit_documentation(openapi_data: dict) -> dict:
    findings = []
    for path, method, config in iter_operations(openapi_data):
        path_lower = path.lower()
        if any(keyword in path_lower for keyword in RATE_LIMIT_PATH_KEYWORDS):
            if not has_rate_limit_documentation(config):
                findings.append(f"{method.upper()} {path}")

    return {
        "id": "RATE-001",
        "name": "Rate limiting non documenté",
        "severity": "MOYENNE",
        "passed": not findings,
        "description": "Repère les opérations sensibles ou coûteuses sans indice de limitation de débit documenté.",
        "fail_message": (
            "La spécification ne documente pas de limitation de débit pour cette "
            f"opération sensible ({', '.join(findings[:3])}). Vérifiez qu'un "
            "contrôle existe côté gateway, backend ou infrastructure ; ce signal "
            "ne prouve pas son absence runtime."
        ) if findings else None
    }

def check_pro_inventory_versioning(openapi_data: dict) -> dict:
    findings = []
    version = str((openapi_data.get('info') or {}).get('version') or '').strip()
    if not version or version == "0.0.0":
        findings.append("info.version absent ou non significatif")

    path_versions = set()
    operation_count = 0
    untagged_count = 0
    for path, method, config in iter_operations(openapi_data):
        operation_count += 1
        match = re.match(r"^/v(\d+)(?:/|$)", path.lower())
        if match:
            path_versions.add(match.group(1))
        if config.get('deprecated') is True:
            findings.append(f"{method.upper()} {path} deprecated=true")
        if not config.get('tags'):
            untagged_count += 1

    if len(path_versions) > 1:
        findings.append(f"versions de chemins multiples: {', '.join(sorted(path_versions))}")
    if operation_count >= 3 and untagged_count == operation_count:
        findings.append("opérations sans tags d'inventaire")

    servers = openapi_data.get('servers', []) or []
    server_hosts = {
        str(server.get('url') or '').split('/')[2]
        for server in servers
        if isinstance(server, dict) and '://' in str(server.get('url') or '')
    }
    if len(server_hosts) > 1:
        findings.append("serveurs multiples à clarifier")

    return {
        "id": "INV-001",
        "name": "Inventaire ou versioning API à clarifier",
        "severity": "MOYENNE",
        "passed": not findings,
        "description": "Repère les indices de versioning, dépréciation ou inventaire API à clarifier.",
        "fail_message": (
            "Des indices suggèrent que l'inventaire ou le versioning de l'API "
            f"pourrait être clarifié ({', '.join(findings[:4])}). Cela peut "
            "compliquer la maintenance, la dépréciation et la surveillance de sécurité. "
            "À vérifier avec les propriétaires API : catalogue, tags, versioning et plan de retrait."
        ) if findings else None
    }

# ==============================================================================
# CHEF D'ORCHESTRE
# ==============================================================================

def run_audit(file_path: Path, is_pro: bool = False) -> list:
    openapi_data = load_openapi_file(file_path)
    rules_to_run = [
        check_free_key_exposure,
        check_free_insecure_http_server,
        check_free_missing_authentication,
        check_free_no_expiration,
    ]
    if is_pro:
        rules_to_run.extend([
            check_pro_identity_context,
            check_pro_ai_agent_risk,
            check_pro_over_permissioned,
            check_pro_bola_patterns,
            check_pro_bfla_privileged_routes,
            check_pro_sensitive_data,
            check_pro_secret_examples,
            check_pro_ssrf_inputs,
            check_pro_rate_limit_documentation,
            check_pro_inventory_versioning,
        ])

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
