# Speculynx CLI

Speculynx is a local-first Python/Typer CLI for auditing OpenAPI 3.0.x and
3.1.x files for API security risks. Swagger 2.0, GraphQL, gRPC, and SOAP are
outside the MVP scope.

OpenAPI files are analyzed locally. Speculynx does not send customer OpenAPI
documents to the backend. Free scans work without a license and without network
access.

## Install

From a local checkout:

```powershell
python -m pip install -e .
```

After a package build, install the wheel locally:

```powershell
python -m pip install dist\speculynx-0.1.1-py3-none-any.whl
```

## Commands

```powershell
speculynx --help
speculynx scan --file path\to\openapi.yaml
speculynx login
speculynx info
speculynx logout
```

`login` verifies a Pro license key with:

```text
POST /v1/verify
Authorization: Bearer <license_key>
```

The key is stored with the operating-system credential store through `keyring`.
Legacy `~/.speculynx.json` files are ignored.

## Free Scan

```powershell
speculynx scan --file path\to\openapi.yaml
```

Free rules include:

- `KEY-EXP-01`: keys or tokens exposed in query parameters.
- `HTTP-001`: insecure `http://` server URLs.
- `AUTH-001`: missing documented authentication.
- `KEY-EXP-02`: missing documented key/token expiration.

## Pro Scan

With a valid Pro license, `scan` also runs heuristic checks for patterns such as
BOLA, BFLA, sensitive data exposure, likely secrets in examples, SSRF inputs,
missing rate-limit documentation, and unclear API inventory/versioning.

Pro findings are static analysis signals, not proof of runtime vulnerabilities.
They should be manually verified against backend authorization, gateway, and
infrastructure controls.

## PDF Export

PDF export is Pro-only:

```powershell
speculynx scan --file path\to\openapi.yaml --export report.pdf
```

In Free mode the export is refused.

## Live Scan / DAST

`scan-live` is Pro-only and can send real HTTP requests to a target API. It is
safe-by-default:

- only `GET` requests are sent by default;
- `POST`, `PUT`, `PATCH`, and `DELETE` require `--allow-unsafe-methods`;
- `--yes` does not unlock unsafe methods by itself;
- `--dry-run` prints planned requests without sending HTTP traffic;
- `--insecure` must be explicitly provided to disable TLS verification.

Examples:

```powershell
speculynx scan-live --file openapi.yaml --target https://api.example.com --dry-run
speculynx scan-live --file openapi.yaml --target https://api.example.com --yes
speculynx scan-live --file openapi.yaml --target https://api.example.com --yes --allow-unsafe-methods
```

Only run `scan-live` against systems you own or are explicitly authorized to
test.

## Development

```powershell
python -m unittest discover -s tests -v
python -m build
```
