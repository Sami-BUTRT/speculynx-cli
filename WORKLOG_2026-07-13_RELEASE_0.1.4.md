# Worklog — release 0.1.4 — 2026-07-13

Beta feedback 1–9 is covered: pipx installation guidance, version `0.1.4`,
healthy JWT handling, partial Free coverage and indeterminate verdict in text
and JSON, `--fail-on high`, and OpenAPI 3.0/3.1 versus Swagger 2.0 behavior.
The full suite passed: 99 tests.

Fresh artifacts `speculynx-0.1.4-py3-none-any.whl` and
`speculynx-0.1.4.tar.gz` were built and both passed `twine check`. A clean venv
installed the wheel and passed the CLI smoke tests. Release commit:
`a68fe5db09f9901d7371f15ffe9aae2691a58f05`; annotated tag: `v0.1.4`.

GitHub Actions run [29278377655](https://github.com/Sami-BUTRT/speculynx-cli/actions/runs/29278377655)
passed build, tests, artifact checks, and version/tag validation. Publication
then failed in job `86913229410` with `invalid-publisher`: PyPI found no Trusted
Publisher matching repository `Sami-BUTRT/speculynx-cli`, workflow
`publish.yml`, and environment `pypi`. There is therefore no successful
workflow hash and no PyPI release proof yet; the public index still reports
latest version `0.1.2` and the `0.1.4` JSON endpoint returns HTTP 404.

A second clean venv confirmed that public installation fails with `No matching
distribution found for speculynx==0.1.4`. The pipx check and web alignment
remain intentionally blocked until the PyPI Trusted Publisher is configured.
