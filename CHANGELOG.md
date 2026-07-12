# Changelog

## 0.1.4 - 2026-07-13

### Added

- Added stable JSON schema `1.0` output with `--json`.
- Added configurable CI thresholds with `--fail-on` and documented exit codes.

### Changed

- Free scans now report partial coverage, executed and skipped rules, and an
  indeterminate verdict when no Free finding is detected.
- Invalid inputs now return exit code 2; internal rule failures return 3; an
  explicitly unavailable Pro export returns 4.

No new detection rule was added, and Free scanning remains local and offline.

## 0.1.3 - 2026-07-11

### Changed

- Added a functional test campaign covering Free, Pro, and DAST behavior.
- Fixed `KEY-EXP-01` detection for common query parameters defined at the Path
  Item level.
- Fixed DAST URL preparation so common path parameters are replaced.

There are no license contract changes and no product scope changes.

## 0.1.2 - 2026-07-10

### Changed

- Advanced the package version to 0.1.2 so the release has a unique version
  after 0.1.1 was already present on PyPI.
- Updated the local wheel installation example for the 0.1.2 artifact.

There are no runtime, CLI, security, or compatibility changes compared with
0.1.1.
