# Project Status

- Last updated: 2026-09-24 (Asia/Taipei)
- Current milestone: v1 release hardening after completed Phases 0–9; Phase 10 has not started
- Status: Mosaic offline AST diagnosis and zh-TW HTML hardening implemented and validated locally; verify the checkpoint in Git history

## Implemented

- Phases 0–8 remain: bounded discovery, secrets, Python SAST/behavior, dependency/advisory matching, correlation/risk, optional advisory Gemini, canonical reporting, and proposal-only remediation. Target code is never executed or auto-modified.
- Phase 9 adds a standard-library Tk desktop GUI via `security-auditor gui`. A controller runs the existing `ScanOrchestrator` in one worker thread, transfers fixed progress/completion through a queue, and presents only the sanitized public `ScanReport` view. It supports synthetic/local scans, bounded JSON report opening, dashboard, findings/filter/detail, risks, secrets, dependencies, AI advisory, remediation proposals, gate, diagnostics, and safe JSON/SARIF/HTML export. Cancellation is cooperative and marks the report `ABORTED`.
- A shared `SecurityGatePolicy` 1.0 and evaluator back `security-auditor gate REPORT.json` and the GUI. Canonical JSON 1.1 is bounded and structurally validated. PASS requires complete coverage and no blockers; PARTIAL/ABORTED/FAILED and truncation block by default. Primary deterministic findings drive blocking; AI and patch proposals are advisory. Gate JSON stdout is machine-only, with exit 0 PASS, 10 WARN, 20 BLOCK, 3 invalid report.
- A project-scoped `.agents/skills/security-auditor/SKILL.md` defines the defensive Codex scan → JSON → gate → review/rescan workflow. No global Skill was modified. There is no patch apply action or Phase 10 implementation.
- v1 hardening separates Python AST node and depth diagnostics with target-relative paths, counts scanner applicability apart from skipped files, and raises the per-file AST node default from 10,000 to 20,000 within the unchanged 50,000 hard ceiling. HTML reporter tool-owned UI uses centralized Traditional Chinese (`zh-TW`) display text; JSON 1.1, SARIF, and console contracts retain their machine fields and language.

## Verification

- Full offline suite: `UV_OFFLINE=1`, `PYTHONDONTWRITEBYTECODE=1`, live Gemini gate unset, `uv run python -m unittest discover -s tests -q` — 142 tests, 140 passed, 0 failed, 2 skipped (Windows symlink privilege and gated live Gemini). `uv run python --version` returned Python 3.12.11. **Python 3.12.11 baseline verified.**
- Mosaic passive measurement: five admitted root files, including two Python sources (65,098 bytes / 10,593 AST nodes / depth 14 and 69,461 bytes / 11,532 AST nodes / depth 14). The old 10,000-node default rejected both; three non-applicable files were mistakenly counted as skipped. Offline JSON/HTML re-scan after correction: discovery COMPLETE, SAST 2 applicable/2 scanned/0 skipped/3 not applicable COMPLETE, behavior the same, overall COMPLETE, zero findings in analyzed coverage. SHA-256 hashes of all five root files matched before and after the two scans. Zero findings is not proof of safety.
- Phase 9 tests cover gate PASS/WARN/BLOCK, HIGH SAST/secret, medium SAST, dependency no-data, AI false-positive non-authority, supporting deduplication, malformed/oversize report rejection, gate CLI JSON/exit codes, controller scan/cancel, fake Gemini-only grant with no OSV call, Tk views and no-apply actions, public clipboard diff, partial coverage banner, and read-only report opening.
- Manual Tk smoke opened and rendered all 13 views over an inert synthetic scan: `COMPLETE`, gate `WARN`, two proposals. CLI help/gate help and import without Tk succeeded. Markdown and Skill links/frontmatter checked: 27 documents, zero missing links/metadata. `git diff --check` passed before checkpoint.
- `.env` remains ignored and untracked. The existing trusted loader enabled an in-process equality check: actual Gemini key value absent from 142 Git-visible files. No Phase 9 live Gemini or OSV request occurred.
- Environment: Windows NT 10.0.26200, project-local CPython 3.12.11 via uv 0.12.13, Git 2.53.0. The default package and full offline suite are verified under the declared Python 3.12 baseline. Manual Tk display and live Gemini validation were not repeated under Python 3.12 in this hardening.

## Security and limitations

- GUI and gate never execute scanned target code, run target tests, install target dependencies, apply proposals, or change the target. GUI AI/OSV grants are separate and off by default; reading an existing report never contacts providers. Report data and text remain hostile; Tk renders plain redacted text and the gate emits only fixed reasons and hashed finding IDs.
- Gate JSON has no authenticity signature; trusted workflows must protect report provenance. The report reader's 16 MiB cap and Python parser still consume bounded host resources. Tk cancellation cannot forcibly interrupt one in-flight parser, scanner, or provider call. Clipboard persistence is controlled by Windows after copying; redaction remains heuristic.
- Native assistive technology, high-DPI/dark mode, Windows junction/UNC/long-path edge cases, Python 3.12 Tk packaging, and standalone executable distribution are not verified. No graph visualization, persistent scan history, manual gate override, or controlled patch application is implemented.

## Git and next action

- Branch `main`; local v1 hardening checkpoint created, no push. The pre-existing untracked `uv.lock` and original Mosaic reports, plus the new hardening reports, remain outside Git. Verify with `git log -1` and `git status`.
- Core roadmap phases 0–9 are implementation milestones. Optional future Phase 10 — Controlled Patch Application — has not started.
