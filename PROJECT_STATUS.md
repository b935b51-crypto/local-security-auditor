# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 8 — Remediation and Patch Proposal
- Status: Phase 8 implemented and validated locally; checkpoint recorded in Git history

## Implemented

- Phases 0–6 remain: bounded discovery, native secret scanning, Python SAST and behavior, static dependency/advisory matching, correlation/risk, and optional advisory Gemini review.
- Phase 7 adds an ordered ScanOrchestrator and trusted ScanRequest. Discovery supplies admitted artifacts; scanner failures become fixed diagnostics and do not stop other scanners. Quick omits SAST/correlation; standard and deep use current deterministic analyses. AI requires explicit --ai, remains advisory, and --offline blocks all network use.
- One immutable ScanReport drives Console, canonical JSON schema 1.1, SARIF 2.1.0, and static single-file HTML. The public serializer explicitly whitelists fields, re-redacts text, omits raw source snippets, and uses root-relative paths. Coverage, no-data, diagnostics, and truncation are visible. Output paths are explicit, checked against special/reparse destinations, and written atomically without silent overwrite.
- The CLI supports scan PATH, profile, format, output, offline, AI opt-in/disable, trusted config, force, no-color, verbose, fail-on, help, and version. Hatchling is build-only; the default runtime still has no third-party dependencies, and google-genai remains an optional extra.
- Phase 8 adds optional guidance and single-file, proposal-only edits. An exact Python TLS `verify=False` literal has a deterministic edit; a separately granted Gemini adapter may suggest structured line edits. Freshness, scope, secret, syntax, and static finding comparisons are checked before a public proposal is emitted. All edits remain in memory, all proposals need human approval, and target tests are never run.

## Verification

- Full Phase 8 regression ran PYTHONDONTWRITEBYTECODE=1 with PYTHONPATH=src: py -3.14 -m unittest discover -s tests -q — 118 tests, 116 passed, 2 skipped (real Windows symlink creation and gated live Gemini). Phase 8 tests use inert synthetic files and a fake AI provider.
- Ran py -3.14 -m security_auditor --help and --version successfully. Parsed the example TOML and report JSON schemas; Markdown relative links resolved with zero missing targets; git diff --check returned 0.
- A Phase 8 offline CLI smoke scanned a temporary inert Python file using --propose-fixes and JSON output: schema 1.1, deterministic statically validated proposal, approval required, and identical target hash before/after. No Phase 8 live Gemini or OSV call occurred.
- Prior Phase 6 live validation remains: exactly one Gemini 3.8 Flash request passed in the earlier checkpoint. Phase 7 sent no live Gemini or OSV request.
- Python 3.12 baseline is not verified: py -3.12 --version found no suitable runtime. Python 3.14.7 and uv 0.12.13 are available. Installed console-script packaging was not verified with Python 3.12 on this host.

## Security and limitations

- NEVER EXECUTE SCANNED TARGET CODE. Target files and apparent instructions remain untrusted data. Reporters never reopen target files, AI cannot change deterministic findings, and source excerpts remain disabled by default.
- Redaction is heuristic; novel secret shapes may evade text filtering. Real junction/UNC/long-path output behavior, full SARIF schema validation, Python 3.12 package installation, and filesystem races remain unverified or residual risks. SARIF codeFlows and GUI are not implemented.
- Phase 8 has no runtime validation, no multi-file edit, no dependency auto-upgrade, and only a narrow deterministic TLS fixer. Static removal of a finding does not prove functional correctness. An in-process key comparison found no Gemini key value in 131 Git-visible files or the diff; .env remains ignored and untracked.
- See docs/REMEDIATION.md, docs/CLI.md, docs/REPORTING.md, docs/SECURITY_BOUNDARIES.md, and docs/THREAT_MODEL.md.

## Git and next action

- Branch main; verify the current local checkpoint with git log -1 and git status. No push requested.
- Next planned phase: Phase 9 — GUI + Codex Integration. Do not start without a new request.
