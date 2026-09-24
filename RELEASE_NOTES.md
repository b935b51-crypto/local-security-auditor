# Local Security Auditor 1.0.2

**1.0.2 is prepared locally for release validation. No 1.0.2 tag, push, or publication is part of this preparation.**

## Detection precision patch

- Known secure runtime generators such as appropriately imported Python `secrets` APIs are no longer classified as hardcoded credentials when bounded AST evidence proves the call structure. This is a narrow allowlist; literal credentials and unknown helpers remain eligible for detection.
- Clearly synthetic generic credentials in test contexts receive narrower treatment. Tests remain scanned, and provider-specific secret patterns remain active in tests. Fixture classification is heuristic.
- CLI-controlled file paths remain visible as findings. Local operator-controlled flows in developer scripts may receive Low severity while HTTP-controlled or mixed-source flows retain Medium. CLI input can still be untrusted in automation; lower severity does not prove non-exploitability.

No Gate policy, JSON 1.1 schema, SARIF 2.1.0 contract, OSV budgets, or network opt-in behavior changed. Target code is still treated as untrusted data and is not executed or modified during scans. Remediation runtime tests remain `NOT_RUN`; Phase 10 automatic patch application is not implemented. Real symlink and UNC behavior remain incompletely validated on this host.

Install the locally built 1.0.2 wheel in a clean Python `>=3.12,<3.13` environment. The optional `[gemini]` extra remains separate. This document does not imply package-registry publication.

## 1.0.2 validation

Python 3.12.11 offline regression passed 211 tests with 6 expected skips and no failures. Clean wheel and sdist installs reported 1.0.2; the wheel passed all 12 synthetic precision golden tests from outside the source tree. The optional Gemini extra installed offline and an offline AI-requested scan made no external request. Source and installed-wheel deterministic results matched on an inert fixture. The 1.0.2 wheel scanned the Trading Platform with `--profile standard --osv --no-ai`: 341 dependency cache hits, zero `NO_DATA`, zero OSV/Gemini requests, COMPLETE deterministic coverage, and Gate WARN. At that snapshot, the 15 Findings comprised 1 Low and 14 Info; the target Git short status was empty before and after. This observation does not prove project safety. A second offline build produced identical wheel and sdist member lists and SHA-256 values.

## 1.0.1 release history

Version 1.0.1 added the explicit OSV opt-in. The following account records its original local preparation; 1.0.1 was subsequently released.

At the time of the original preparation, no 1.0.1 tag, push, or release had been performed.

## What changed

`security-auditor scan PATH --osv --no-ai` now explicitly permits bounded live OSV dependency queries without enabling Gemini. Omitting `--osv` keeps the offline default. `--offline` forces offline mode and cannot be combined with `--osv`. An explicitly selected trusted configuration with `[scan] offline=false` can also permit OSV; CLI flags take precedence. A fresh cache hit can make actual network requests zero even when `--osv` is selected. `scan.offline` records whether network was permitted; OSV request counters record actual network use.

When an offline scan has no usable cached vulnerability data, its diagnostic now explains that OSV is disabled and suggests `--osv` or trusted configuration. `NO_DATA` remains distinct from `NO_MATCH`, and incomplete coverage still blocks the Gate. The CLI, cache, and provider continue to send only validated ecosystem/name/exact-version coordinates to the fixed HTTPS OSV endpoint; AI requires its own explicit choice. The cache key/schema/path algorithms, OSV budgets, JSON 1.1, SARIF 2.1.0, and Gate 1.0 are unchanged.

The earlier installed 1.0.0 report showing 0/341 cache hits remains an observed historical discrepancy. Current source and installed 1.0.0 parsers each resolve the same 341 keys to fresh entries through the production cache API, so no speculative cache change is included in this patch. The original process's effective cache environment was not recorded in the report.

## Installation

Requires Python `>=3.12,<3.13`. Install the built 1.0.1 wheel into a clean environment, for example `uv pip install --python <venv-python> dist/local_security_auditor-1.0.1-py3-none-any.whl`. Add `[gemini]` to the wheel requirement only if the optional Gemini adapter is needed. The package has not been published to PyPI. See [CLI](docs/CLI.md) for usage and exit codes.

## 1.0.0 release history

The 1.0.0 final build was subsequently tagged, pushed, and published as a GitHub Release. The validation details below describe that build at finalization time.

## Highlights

Local Security Auditor is an offline-first static auditor for untrusted local repositories. It combines bounded file discovery, Secret scanning (including bounded large-text analysis), Python SAST, dangerous behavior signals, supported dependency inventory and vulnerability matching, correlation and risk prioritization. Optional OSV queries and Gemini advisory review are separately enabled. Results are available through the CLI, Windows Tk GUI, Security Gate, and Console, JSON 1.1, SARIF 2.1.0, and Traditional Chinese HTML reports.

## Security model

The selected target is untrusted data. The auditor does not execute target code, import target modules, run target tests, install target dependencies, or automatically modify target files. Symlink, junction, and reparse traversal is denied by default. File, parser, finding, output, and provider request budgets limit work. `COMPLETE` means finished analysis within the declared scan scope; `PARTIAL`, `ABORTED`, and `FAILED` are explicit, and incomplete coverage blocks the default Gate. Zero findings never proves a project safe.

## Scanners and external services

Secrets are redacted before public Findings; Python SAST requires a defensible source-to-sink path; behavior signals do not by themselves establish intent or exploitability. Dependency analysis parses admitted manifests and lockfiles without running a package manager. Optional OSV queries send only validated exact package coordinates to the fixed HTTPS endpoint, with scan-global request limits and a normalized tool-local cache. A known vulnerable dependency version does not establish that its affected function is reachable or the application exploitable. Optional Gemini reviews are advisory, receive bounded redacted context after explicit opt-in, and cannot change deterministic Findings, severity, or the Gate decision.

## Reporting, GUI, Gate, and remediation

JSON 1.1 is the canonical machine contract. SARIF 2.1.0 contains deterministic results; static zh-TW HTML has escaping, CSP, no JavaScript, and no remote assets. The Windows Tk GUI reads the same sanitized report view as the CLI. Gate 1.0 returns PASS, WARN, or BLOCK based on coverage and primary deterministic Findings. Remediation is **proposal-only**: every patch requires human approval; no patch is applied automatically and runtime tests remain `NOT_RUN`.

## Real-world validation

Mosaic's final recorded offline scan had COMPLETE coverage and zero Findings in the analyzed scope; its saved report gated PASS. The final installed **1.0.0** wheel scanned the Trading Platform offline with COMPLETE Discovery, Secrets, SAST, Behavior, Dependencies, Correlation, and Overall coverage, and Gate WARN (3 medium and 14 info Findings). Its 2,169,199-byte log was analyzed in bounded large-text mode, and dependency replay had 341 cache hits with zero OSV requests. Target Git status was unchanged before and after. These are observed snapshots, not guarantees about either project. Historical live Gemini and bounded live OSV validation, Windows junction/long-path checks, and 1.0.0 clean-install evidence are documented in [Release Candidate](docs/RELEASE_CANDIDATE.md), [RC real-world validation](docs/RC_REAL_WORLD_VALIDATION.md), and [project status](PROJECT_STATUS.md).

## Installation

Requires Python `>=3.12,<3.13`. From the locally built artifact in a new environment:

```powershell
python -m pip install .\dist\local_security_auditor-1.0.0-py3-none-any.whl
security-auditor --version
security-auditor scan PATH --offline --format json --output report.json
security-auditor gate report.json --format json
```

Alternatively use `uv pip install --python <venv-python> <wheel-path>`. Install `<wheel-path>[gemini]` only when the optional Gemini adapter is needed. The GUI requires a Python installation with Tk support. The package has **not** been published to PyPI; install from the local wheel or sdist. See [CLI](docs/CLI.md) for output and exit-code details.

## Known limitations

- Deep SAST is Python-focused; dependency formats and ecosystems are limited to documented support.
- Secret redaction is heuristic. Discovery admits files up to 4 MiB by default; larger applicable files can leave coverage incomplete.
- Real symlink and UNC cases were not validated on this Windows host. High-DPI and assistive-technology GUI behavior were not fully verified.
- No standalone EXE or installer is built. Remediation runtime tests are `NOT_RUN`; controlled patch application is not part of 1.0.0.

## Upgrade notes

The package version changes from `0.9.0` RC to `1.0.0`. JSON remains schema `1.1`, SARIF remains `2.1.0`, and Gate policy remains `1.0`; no scanner rule, Secret limit, Discovery ceiling, or OSV budget was changed for this version transition. Existing reports should be interpreted with their embedded tool and schema versions, and Gate accepts only canonical JSON 1.1. Reinstall from the 1.0.0 artifact in a clean Python 3.12 environment to verify your workflow before replacing a prior installation.
