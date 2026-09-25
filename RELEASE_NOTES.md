# Local Security Auditor 1.0.4

**1.0.4 is prepared locally and ready for an annotated tag after the release-preparation commit. No 1.0.4 tag, push, or publication is part of this preparation.**

## Finding identity, correlation, and provenance patch

Exact semantic duplicates now appear once in public Finding counts and remediation proposals. Nested `exec(compile(...))` is one dynamic-code operation; an independent `compile(...)` call remains visible. Findings with different evidence or different sinks remain distinct. At one sink, specific command execution is primary and generic process execution is supporting; both machine Findings remain available. The Gate still uses primary deterministic issues and retains policy 1.0.

Test-file paths receive an additive context tag without suppressing a Finding. A `stored_source_lookup` tag requires bounded Python AST evidence of a local stored-source lookup. Neither tag establishes safe input or a sandbox; dynamic strategy code execution remains a security-sensitive behavior. Remote input retains its own source context.

Dependency summaries now identify the OSV provider, assessed and unassessed exact dependency records, fresh and stale accepted cache lookup keys, cache age range and TTL when known, and actual network requests. A fresh, complete lookup can be assessed even if it has no advisory match; a stale or unavailable lookup remains incomplete. “No known vulnerability matches in assessed dependency coverage” is limited to the assessed data and is not a claim that the application has no vulnerabilities. Cache freshness and OSV knowledge constrain that statement.

AI review remains optional and advisory. A requested review with zero eligible subjects reports `no_eligible_items`, rather than `complete`; disabled, partial, and failed states remain distinct. Patch AI availability is independent of finding review. AI cannot change deterministic Findings or the Gate.

JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, the offline-first default, explicit OSV and Gemini choices, and provider budgets are unchanged. No new detector rule or Phase 10 patch application is included. Deep JavaScript/TypeScript SAST remains outside scope. Real symlink and UNC host validation is incomplete; remediation runtime tests remain `NOT_RUN`.

Install the locally built 1.0.4 wheel in a clean Python `>=3.12,<3.13` environment. The optional `[gemini]` extra is separate. This document does not imply package-registry publication.

## 1.0.4 validation

Python 3.12.11 full offline regression passed **247 tests: 241 passed, 0 failed, 6 skipped**. Two offline builds produced identical filenames, member lists, sizes, and SHA-256 values. The wheel is `local_security_auditor-1.0.4-py3-none-any.whl` (187,855 bytes; SHA-256 `252e28216f054e57a3c31c0b017a4114a3163948f6a9950f45f97e8ede4c99d5`); the sdist is `local_security_auditor-1.0.4.tar.gz` (138,121 bytes; SHA-256 `95f5f2956fa5060dea49e52041deeae779cb62c105e425d0c3636a38bd1c2cd2`). Both report version 1.0.4 and Python `>=3.12,<3.13`. Archive inspection found no audit reports, cache, target copies, credentials, or private absolute path markers; the ordinary `.gitignore` in the sdist is not Git internal data.

Fresh repo-external Python 3.12.11 core-wheel, wheel `[gemini]` (`google-genai` 2.25.0), and sdist installs passed. The installed CLI reported 1.0.4 and retained separate `--offline`, `--osv`, `--ai`, and `--no-ai` choices. Twenty installed-wheel golden tests passed for finding identity, correlation, dependency provenance, AI status, reports, and network isolation. Four additional installed-wheel Gate tests passed. A separate installed-wheel fake-provider check confirmed AI `partial` after one successful and one failed synthetic review; disabled, complete, failed, and budget-aborted states also passed installed tests. A synthetic source-versus-wheel comparison matched stable JSON fields; the installed wheel produced JSON 1.1, SARIF 2.1.0, static zh-TW HTML with CSP, and Gate PASS. The optional Gemini extra's offline AI-requested scan made no external request.

The installed wheel scanned the Trading Platform at profile `deep` with `--offline --no-ai`: 21 machine Findings (0 Critical, 0 High, 4 Medium, 1 Low, 16 Info), 20 primary groups, all deterministic coverage COMPLETE, zero diagnostics, 343 exact records assessed, 341 fresh cache hits, zero OSV/Gemini requests, and Gate WARN. The nested dynamic-code operation retained one fingerprint; same-sink CMD/PROCESS Findings had primary/supporting roles. Target Git HEAD and short status were unchanged. `.pytest-tmp` existed in the target, but this snapshot did not produce incomplete coverage. This is a target snapshot, not a safety guarantee.

After the user explicitly authorized this one bounded OSV check, a fresh clean-installed 1.0.4 wheel scanned the Trading Platform at profile `deep` with `--osv --no-ai`. `scan.offline` was `false`. Its dependency inventory had 344 records, one first-party root, 343 exact registry records, **343 assessed and zero unassessed**, 341 fresh cache hits, zero stale hits, zero `NO_DATA`, zero advisory matches, and **zero actual OSV batch/detail/total requests** because the cache was complete. Gemini use was zero. Discovery, Secrets, SAST, Behavior, Dependencies, Correlation, and Overall coverage were COMPLETE with no diagnostics; Gate 1.0 remained WARN for nonblocking primary Findings. Counts remained 21 machine Findings and 20 groups (0 Critical, 0 High, 4 Medium, 1 Low, 16 Info).

The target Git HEAD was unchanged. Its short status changed from 11 entries immediately before the scan to 14 immediately after, then 16 on a later check, reflecting concurrent dashboard work. Exact before/after target equivalence therefore cannot be claimed. The Auditor wrote its report only to the external temporary directory and did not intentionally modify, execute, import, or install target code. The target's concurrent work is a snapshot limitation, not evidence of a scanner regression; the scan's reported coverage remained COMPLETE. The temporary validation environment and report were removed after aggregate results were recorded.

## 1.0.3 release history

The following 1.0.3 account is retained as historical validation evidence.

# Local Security Auditor 1.0.3

**1.0.3 is prepared locally for release validation. No 1.0.3 tag, push, or publication is part of this preparation.**

## Secret Scanner precision patch

Generic hardcoded-secret detection in JavaScript and TypeScript now requires credential-like **source literal** evidence instead of treating arbitrary right-hand-side expression text as secret material. Direct `process.env` references and narrowly proven `NodeJS.ProcessEnv` parameter wrappers, including simple `trim()` or optional `?.trim()` transforms, are no longer described as hardcoded credentials. This requires static declaration evidence; an object called `config` is not trusted by name alone, and declaration evidence is not proof of the runtime caller.

Hardcoded literal fallbacks remain detectable, including `process.env.API_KEY ?? "literal"`, mixed templates, and quoted material inside bounded template interpolation. Runtime calls and member access, such as a token-producing expression, are not classified as high-entropy hardcoded literals when no literal secret material exists; this does not establish that a runtime token is cryptographically secure. Unknown helpers are not assumed to be trusted secure sources.

Clearly synthetic generic test fixtures receive narrower treatment. Test files remain scanned, and provider-specific secret patterns remain active there at their normal severity. The test-fixture classification is heuristic and does not grant blanket trust to tests.

This patch adds no full JS/TS AST or dataflow security analysis. The lexical source-literal reader is bounded and may miss complex expressions; low-diversity literals can still fall below the existing generic detection threshold even in production files. `COMPLETE` means the enabled, supported analyzers finished within their declared scope, not that every vulnerability class was analyzed. Existing real-symlink and UNC validation limitations remain. Remediation runtime tests remain `NOT_RUN`, and Phase 10 controlled patch application is not implemented. JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, OSV opt-in/budgets, and Gemini's independent opt-in are unchanged.

Install the locally built 1.0.3 wheel in a clean Python `>=3.12,<3.13` environment. The optional `[gemini]` extra remains separate. This document does not imply package-registry publication.

## 1.0.3 validation

Python 3.12.11 full offline regression passed **235 tests: 229 passed, 0 failed, 6 skipped**. The first post-bump run exposed stale 1.0.2 distribution metadata in this repository's `.venv`; refreshing only that project-local installation to 1.0.3 made the complete rerun pass. Default tests made no live provider requests.

Two final offline builds produced the same wheel/sdist filenames, archive member lists, sizes, and SHA-256 values. The final wheel is `local_security_auditor-1.0.3-py3-none-any.whl` (185189 bytes, SHA-256 `d5d95b5965ed1c3735588a1088bb116e00c76ed55f86e75c97cbc511fbdbc064`); the sdist is `local_security_auditor-1.0.3.tar.gz` (135579 bytes, SHA-256 `ba0f1286afda296f029b5ea20a1547c58e4d69ccc1c9fc6c702a5a2d1fafad20`). Archive member and private-path inspection found no `.env`, audit report, tool cache, StockDashboard source copy, or embedded private absolute path. Both archives remain ignored in `dist/`.

Fresh repo-external Python 3.12.11 core-wheel, wheel `[gemini]`, and sdist installations passed. Installed CLI/import/metadata reported 1.0.3; the optional SDK was `google-genai` 2.25.0. The installed wheel passed all 16 synthetic JS/TS golden cases, including environment references, hardcoded fallbacks, opaque literals, provider-specific test tokens, and static template material. CLI help retained offline/OSV/Gemini and proposal options. Default, explicit offline, and offline AI-requested synthetic scans made zero external requests.

The **installed 1.0.3 wheel**, not only source, scanned StockDashboard with `--profile standard --osv --no-ai`: all 16 formerly false-positive generic Secret locations were absent, and all 14 Behavior finding fingerprints matched an immediate source scan of the same target. Counts were 0 Critical, 0 High, 0 Medium, 8 Low, and 6 Info. Secrets, Dependencies, and Overall coverage were COMPLETE with zero diagnostics; 195 exact dependencies hit the cache, `NO_DATA` was zero, and actual OSV/Gemini requests were zero. Gate 1.0 remained WARN for nonblocking findings. Offline installed-wheel HTML was static zh-TW with CSP and no old generic Secret findings; SARIF remained 2.1.0 with 14 results. StockDashboard Git status and HEAD were identical before and after. This observed scan does not establish that the target has no vulnerabilities.

## 1.0.2 release history

The following 1.0.2 account is retained as historical validation evidence.

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
