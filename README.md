# Speculynx CLI

This directory contains the standalone local-first Speculynx CLI package. The
MVP accepts OpenAPI 3.0.x and 3.1.x specifications only.

Pro licence keys are stored in the operating-system credential store through
`keyring`. Use `speculynx login` to save a verified key and `speculynx logout`
to remove it. Legacy `~/.speculynx.json` files are ignored and must be removed
manually after confirming that the key has been saved with `login`.
