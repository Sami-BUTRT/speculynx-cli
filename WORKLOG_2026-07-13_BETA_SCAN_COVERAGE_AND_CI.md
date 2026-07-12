# Worklog — beta scan coverage and CI — 2026-07-13

The beta report exposed a semantic gap: Free correctly ran four rules, but its
summary counted only those rules and could look like a complete security
validation. The web demo also exposed selected Pro-like heuristics on arbitrary
input. The CLI now derives executed/skipped rules from an explicit registry,
uses one structured result for terminal and JSON output, and reports partial
coverage without a global safety claim.

Added JSON schema `1.0`, `--fail-on`, deterministic exit codes, CI examples,
and tests for clean Free scans, Free findings, Pro-only risks, OpenAPI 3.0/3.1,
invalid inputs, threshold ordering, stdout purity and counter consistency.
Version prepared: 0.1.4. No package was published and no OpenAPI document is
sent to the licensing service.
