# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 5 — Finding Correlation + Explainable Risk Engine
- Status: implementation complete; verified locally on Python 3.14.7 with limits below

## Completed

- Phases 0–4 remain in place: foundation, bounded discovery, secret detection, Python SAST/behavior, and static dependency/advisory matching.
- `CorrelationEngine` consumes existing normalized `ScannerResult` values. It creates a bounded immutable `RiskGraph`, `FindingGroup` roles, `AttackPathCandidate` annotations, explainable `RiskAssessment`, structured diagnostics, and completeness summary. It does not read target files or mutate source findings.
- Implemented indexed file/location/function/dependency/vulnerability/source/sink entities; same-sink SAST/behavior support; overlapping behavior; conservative secret/network context; exact structured import/dependency references; same-function behavior sequence and contextual persistence/credential candidates; Phase 3 download-execute pattern annotation.
- Primary SAST risk absorbs supporting shell/process evidence without summing their severities. Priority starts from primary severity, allows at most one level of bonus for LOW/MEDIUM only with high-confidence direct support and structured external-input evidence, and remains separate from CVSS, exploitability, and compromise probability. Incomplete coverage caps assessment confidence.
- Configurable trusted `[correlation]` limits have hard ceilings for findings, nodes, edges, paths, elapsed time, and local line proximity. Dense local buckets abort safely rather than performing unrestricted quadratic joins.
- [Correlation](docs/CORRELATION.md), [Risk Engine](docs/RISK_ENGINE.md), architecture/security/finding/roadmap docs, example config, AGENTS, and the architecture project skill reflect Phase 5. No new runtime dependencies, network, AI, report UI, scan CLI, target execution, or Phase 6 work.

## Security and interpretation

- Target repositories remain untrusted data; **NEVER EXECUTE SCANNED TARGET CODE**. The correlation layer accepts only normalized, already redacted data and emits fixed explanations rather than arbitrary source text.
- Secret and network proximity is contextual, not exfiltration. Dependency presence/import reference does not prove affected API reachability. A candidate is not a confirmed attack path. No malicious-intent or exploitability verdict is produced.
- Existing Phase 3 results do not carry a general function identity or import inventory. Same-function and dependency-reference rules are implemented for explicit structured metadata, but are not populated by current Phase 3 scanners. This remains a coverage limitation, not a guessed relationship.

## Verification

- Ran `$env:PYTHONDONTWRITEBYTECODE='1'; $env:PYTHONPATH='src'; py -3.14 -m unittest discover -s tests -q`: 84 tests, 83 passed, 1 skipped (real Windows symlink creation unavailable). Includes 12 new Phase 5 tests and earlier phases.
- Python 3.12 baseline **not verified**: `py -3.12 --version` reports no suitable runtime. Python 3.14.7, uv 0.12.13, and Git 2.53.0 are available. No system Python or dependency environment was changed.
- Live OSV, real junction/UNC/long-path behavior, race-free filesystem containment, hard parser CPU/memory isolation, and production reporter integration remain unverified or out of scope.

## Git and next action

- Branch `main`; Phase 5 local checkpoint is in Git history after the final commit. Inspect `git log -1` for its exact ID. No remote push requested.
- Phase 6 — Optional AI Security Reviewer is next only on a new user request. Do not begin it as part of Phase 5.
