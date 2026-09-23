# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 6 — Optional AI Security Reviewer
- Status: Gemini 3.8 Flash live integration validated once with a synthetic Finding; local regression tests pass with the limits below

## Completed

- Phases 0–5 remain in place: foundation, bounded discovery, native secret and Python SAST/behavior scanning, static dependency/advisory matching, and deterministic correlation/risk annotations.
- `AIReviewer` selects bounded deterministic subjects from normalized Findings and optional correlation results. It builds minimal context and returns separate immutable AI annotations. Deterministic Findings and risk assessments remain authoritative and unchanged.
- AI requires trusted `AISettings(enabled=True)`, `allow_online_ai=True`, and an online session. Default/offline paths make no provider calls. Source excerpts are disabled by default and admitted only through bounded discovery reads with freshness checks. Secret findings never reopen source.
- The replaceable `AIProvider` interface has an optional `GeminiProvider` using the official `google-genai` SDK extra, default `gemini-3.8-flash`, structured output, no built-in tools, and `store=false`. Context and output have second-stage redaction and fixed-code diagnostics. SDK 2.25.0 was installed into ignored project-local `.venv` for live validation; the default/system environment was not changed.
- API keys come from the process `GEMINI_API_KEY` or a trusted tool `.env` outside the target; target `.env` cannot authenticate. The committed `.env.example` has no key. No credential was committed or logged by this work.
- [AI Reviewer](docs/AI_REVIEWER.md), [Threat Model](docs/THREAT_MODEL.md), architecture/security/finding/roadmap docs, example config, README, AGENTS, and the architecture project skill reflect Phase 6. No scan CLI, reporter, patch application, or Phase 7 implementation was added.

## Security and interpretation

- **NEVER EXECUTE SCANNED TARGET CODE.** Target files and apparent instructions remain untrusted data. Gemini Search, URL Context, Code Execution, Computer Use, and function tools are unavailable to the adapter.
- AI verdicts are advisory judgments on bounded static evidence, not proof of exploitability or permission to suppress findings. The provider response is schema checked, bounded, redacted, and kept separate from deterministic results.
- Source redaction is heuristic. Novel secret formats or identifying metadata may still be present if trusted callers enable source excerpts. Provider retention and broader model behavior remain outside this one-request validation.

## Verification

- Ran `$env:PYTHONDONTWRITEBYTECODE='1'; $env:PYTHONPATH='src'; py -3.14 -m unittest discover -s tests -q`: **97 tests, 95 passed, 2 skipped**. The skips are a real Windows symlink creation test and the separately gated live Gemini test. The new AI tests use fake providers/client and synthetic data only.
- Ran `.venv\Scripts\python.exe -m unittest tests.live.test_gemini -v` with the live gate enabled for that command only: **1 test passed, 1 Gemini request, 0 retries**. Provider `gemini`, model `gemini-3.8-flash`, thinking `medium`; schema-valid verdict `INSUFFICIENT_CONTEXT`, confidence `HIGH`. Provider usage: 324 input, 241 output, 724 total tokens. The test asserted the actual key was absent from captured output and serialized result. No prompt or response body was recorded.
- Python 3.12 baseline **not verified**: `py -3.12 --version` reports no suitable runtime. Python 3.14.7, uv 0.12.13, and Git 2.53.0 are available on Microsoft Windows 10.0.26200. No system Python or dependency environment was changed.
- `.env` remained Git-ignored and untracked before and after the test. A key comparison found no key in `git diff`, and the synthetic live-test temporary directory was removed. Provider retention, real junction/UNC/long-path behavior, and earlier parser isolation gaps remain unverified or documented elsewhere.

## Git and next action

- Branch `main`; Phase 6 local checkpoint should be verified with `git status` and `git log -1`. No remote push was requested.
- Phase 7 — Console / JSON / SARIF / HTML Reporting is the next planned phase. Do not start it without a new request.
