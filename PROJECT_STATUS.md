# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 3 — Python SAST + Dangerous Behavior Scanner
- Status: implementation complete; verified on Python 3.14.7 with limits below

## Completed

- APPS v1 guidance, Phase 0 architecture, Phase 1 bounded discovery, and Phase 2 redacted Secret Scanner remain in place.
- `SASTScanner` and `BehaviorScanner` are independent synchronous plugins using the existing `Scanner` contract and preferred `scan_discovery` entry. They reopen only Phase 1 admitted regular artifacts through bounded, identity-checked content reads.
- Python SAST uses a static `ast.parse` frontend, import alias resolution, source/sink taxonomy, narrow guards, flow-sensitive intraprocedural taint, reassignment, conservative branch/loop merge, and source-free trace descriptors. Implemented rules cover command and SQL injection, path access, unsafe deserialization, dynamic code, TLS verification disabled, unsafe YAML loading, and predictable temp names.
- Behavior Scanner emits neutral operation findings from Python AST and bounded PowerShell, batch/CMD, shell, JS/TS, and selected CI text rules. It covers process/shell/Windows tools, network, deletion, registry/persistence, scheduled tasks/services, credential-sensitive access, environment, DLL, termination, security controls, hidden process, and narrow same-file download-to-execute patterns.
- Both plugins have separate file/total byte, AST, finding/match, and elapsed limits; fixed source-free diagnostics and explicit `complete|partial|aborted|failed` coverage. Findings retain separate severity and confidence with redacted evidence.
- [SAST](docs/SAST.md), [Behavior Scanner](docs/BEHAVIOR_SCANNER.md), core architecture/security/schema/scanner/roadmap docs, example config, README/AGENTS, and the architecture project skill are updated. No runtime dependency, CLI command, network adapter, external SAST tool, AI, reporter, or Phase 4 scanner was added.

## In progress

- No Phase 3 implementation remains in progress. Phase 4 has not started.

## Decisions and security boundaries

- Python baseline remains `>=3.12,<3.13` with uv and stdlib only. Python 3.12 is absent locally; no system interpreter or other project environment was changed.
- Target code is hostile data, never executed or imported. No target test, installer, script, executable, network request, or target file mutation is performed. Reparse traversal remains denied.
- SAST injection findings require a visible source-to-sink path. Behavior findings describe potentially sensitive operations, not exploitability, maliciousness, or intent. `shell=True` without taint is a behavior signal only.
- Evidence includes fixed redaction text and safe structural labels, not command lines, URLs, or source snippets. Filename redaction handles known provider token shapes and credential-assignment names; novel secrets in paths remain a residual privacy risk for future normalization/reporting gates.
- `ast.parse` is byte bounded before parse, but the node/depth and elapsed checks are not a hard preemptive parser sandbox. Text rules lack full language parsing. Results may have false positives and false negatives; see phase-specific docs.

## Verification

- Ran on Python 3.14.7: `$env:PYTHONDONTWRITEBYTECODE='1'; $env:PYTHONPATH='src'; py -3.14 -m unittest discover -s tests -v` — 53 tests, 52 passed, 1 skipped (real Windows symlink creation unavailable). Includes Phase 3 positive/negative taint, behavior, malformed/budget, rule/parse isolation, redaction, no-execution, config, documentation links, and project skill checks.
- Ran `git diff --check` before checkpoint; no whitespace errors. No lint or formatter is configured.
- Python 3.12 baseline remains **not verified**: `py -3.12 --version` reports no suitable runtime. Real junction/UNC/long-path behavior, race-free containment, and a hard parser time/memory isolation boundary remain unverified.

## Git and next action

- Branch `main`; local Phase 3 checkpoint is in Git history. No remote push. Inspect `git status` and `git log` for current state and exact commit ID.
- On a new user request, begin Phase 4 — Dependency / CVE Scanner. Preserve existing discovery, secret redaction, SAST/behavior separation, and offline default.
