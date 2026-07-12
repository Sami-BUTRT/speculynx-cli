# Speculynx CLI

Speculynx is a local-first Python/Typer CLI for auditing OpenAPI 3.0.x and
3.1.x files for API security risks. Swagger 2.0, GraphQL, gRPC, and SOAP are
outside the MVP scope.

OpenAPI files are analyzed locally. Speculynx does not send customer OpenAPI
documents to the backend. Free scans work without a license and without network
access.

## Install

### Recommended on Debian and Ubuntu

`pipx` installs Speculynx in an isolated Python environment without changing
the system Python packages:

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install speculynx
speculynx --help
```

You may need to reopen your terminal after running `pipx ensurepath`.
For an immediate one-session setup, you can also run:

```bash
export PATH="$PATH:$HOME/.local/bin"
```

The `export` command is not required for every user or shell. Once `pipx` is
already installed, the generic installation command is:

```bash
pipx install speculynx
```

### Windows PowerShell

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
pipx install speculynx
speculynx --help
```

### macOS

When `pipx` is already available on macOS, use:

```bash
pipx install speculynx
speculynx --help
```

This page does not prescribe a macOS package manager setup.

### Update or uninstall

```bash
pipx upgrade speculynx
pipx uninstall speculynx
```

### Local source checkout

For contributors working from a local checkout, a virtual environment remains
the supported development workflow:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the installation:

```powershell
speculynx --help
speculynx scan --file openapi.yaml
```

Free static scans work immediately without a license or backend connection.
For Pro features, run `speculynx login`: the command prompts interactively for
the license key with hidden input, verifies it with the licensing backend, and
stores a valid key in the operating-system credential store.

After a package build, install the wheel locally:

```powershell
python -m pip install dist\speculynx-0.1.3-py3-none-any.whl
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

## Installation troubleshooting

- `speculynx` not found: activate the virtual environment or ensure its
  `Scripts` directory is in `PATH`; for a pipx install, reopen the terminal
  after `pipx ensurepath`.
- `pipx` not found on Debian/Ubuntu: install it with `sudo apt install -y pipx`,
  then run `pipx ensurepath`.
- Unsupported Python: install Python 3.10 through 3.13.
- File not found: verify the path passed to `--file`.
- Swagger 2.0 rejected: convert the document to OpenAPI 3.0 or 3.1.
- Pro feature refused: check the stored license with `speculynx info`, then use
  `speculynx login` again if needed.

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
