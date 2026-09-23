# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 7 — CLI and Console / JSON / SARIF / HTML Reporting
- Status: Phase 7 implemented and validated locally; checkpoint recorded in Git history

## Implemented

- Phases 0–6 remain: bounded discovery, native secret scanning, Python SAST and behavior, static dependency/advisory matching, correlation/risk, and optional advisory Gemini review.
- Phase 7 adds an ordered ScanOrchestrator and trusted ScanRequest. Discovery supplies admitted artifacts; scanner failures become fixed diagnostics and do not stop other scanners. Quick omits SAST/correlation; standard and deep use current deterministic analyses. AI requires explicit --ai, remains advisory, and --offline blocks all network use.
- One immutable ScanReport drives Console, canonical JSON schema 1.0, SARIF 2.1.0, and static single-file HTML. The public serializer explicitly whitelists fields, re-redacts text, omits raw source snippets, and uses root-relative paths. Coverage, no-data, diagnostics, and truncation are visible. Output paths are explicit, checked against special/reparse destinations, and written atomically without silent overwrite.
- The CLI supports scan PATH, profile, format, output, offline, AI opt-in/disable, trusted config, force, no-color, verbose, fail-on, help, and version. Hatchling is build-only; the default runtime still has no third-party dependencies, and google-genai remains an optional extra.
- No target code was executed, no real target repository was used for Phase 7 validation, and no Phase 8 feature was started.

## Verification

- Ran PYTHONDONTWRITEBYTECODE=1 with PYTHONPATH=src: py -3.14 -m unittest discover -s tests -q — 108 tests, 106 passed, 2 skipped (real Windows symlink creation and gated live Gemini). Phase 7 tests use only inert synthetic files and fake providers.
- Ran py -3.14 -m security_auditor --help and --version successfully. Parsed pyproject.toml and docs/report-schema-v1.json. Markdown relative links resolved; git diff --check returned 0.
- Manual smoke scanned only a temporary synthetic project via py -3.14 -m security_auditor scan PATH --offline. Console coverage appeared, JSON schema 1.0 and SARIF 2.1.0 parsed, HTML file was written, and a clearly fake secret did not appear in any format. Temporary files were removed.
- Prior Phase 6 live validation remains: exactly one Gemini 3.8 Flash request passed in the earlier checkpoint. Phase 7 sent no live Gemini or OSV request.
- Python 3.12 baseline is not verified: py -3.12 --version found no suitable runtime. Python 3.14.7 and uv 0.12.13 are available. Installed console-script packaging was not verified with Python 3.12 on this host.

## Security and limitations

- NEVER EXECUTE SCANNED TARGET CODE. Target files and apparent instructions remain untrusted data. Reporters never reopen target files, AI cannot change deterministic findings, and source excerpts remain disabled by default.
- Redaction is heuristic; novel secret shapes may evade text filtering. Real junction/UNC/long-path output behavior, full SARIF schema validation, Python 3.12 package installation, and filesystem races remain unverified or residual risks. SARIF codeFlows and GUI are not implemented.
- See docs/CLI.md, docs/REPORTING.md, docs/SECURITY_BOUNDARIES.md, and docs/THREAT_MODEL.md.

## Git and next action

- Branch main; verify the current local checkpoint with git log -1 and git status. No push requested.
- Next planned phase: Phase 8 — Remediation + Patch Proposal. Do not start without a new request.
