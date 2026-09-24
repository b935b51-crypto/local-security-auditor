# RC real-world validation: Trading Platform coverage diagnosis

Date: 2026-09-24 (Asia/Taipei). This is a passive, offline diagnosis of the operator-provided Trading Platform repository under Local Security Auditor 0.9.0 RC at `316feb3`. The target was treated as untrusted input. No target code, tests, installer, Gemini, or OSV request ran. No scanner config, rule, limit, or target file was changed.

The formal command was `uv run --offline --no-sync security-auditor scan <target> --offline --no-ai --format json --output audit-trading-platform-coverage-diagnosis.json`. The untracked JSON report is in the auditor workspace and is **not** a release artifact. The target's Git status was empty before and after the scan.

## Coverage and Gate

| Component | Status | Relevant count or reason |
| --- | --- | --- |
| Discovery | COMPLETE | 308 admitted artifacts |
| Secrets | PARTIAL | 247 scanned; 60 unsupported/not applicable; one supported file over the per-file limit |
| Python SAST | COMPLETE | 129 / 129 applicable scanned |
| Behavior | COMPLETE | 132 / 132 applicable scanned |
| Dependencies | PARTIAL | Four source artifacts parsed; one local editable record unresolved for registry lookup; 341 exact lookup keys had no offline cache |
| Correlation | PARTIAL | Propagates upstream incomplete coverage |
| Overall | PARTIAL | 10 Findings: 0 critical, 0 high, 2 medium, 0 low, 8 info |

The public report has three aggregate diagnostic codes, with `path: null`: `SECRET_FILE_TOO_LARGE`, `DEPENDENCY_PROVIDER_NO_DATA`, and `DEPENDENCY_UNRESOLVED_VERSION`. In-memory scanner/discovery inspection identified the specific records below without printing source or secret values. Gate policy 1.0 returned `BLOCK`, with `COVERAGE_PARTIAL`, `DEPENDENCY_NO_DATA`, `NON_BLOCKING_PRIMARY_FINDINGS`, and `SCAN_DIAGNOSTICS`. Its `blocking_findings` list was empty. Intentional discovery exclusions did not cause the block.

## Secret coverage

The sole size-limit artifact is `log/program.log.20260924`, 2,169,199 bytes. Discovery classified it as text, UTF-8, `unknown` artifact kind, with no detected programming language. A bounded 4 KiB prefix check found no NUL byte; it did not establish a conventional log format. Its `log/` location and name suggest generated runtime log data, but its provenance and role are **not verified**. It is not identified as first-party source, config, a manifest, or a test fixture. Because a text log may contain secrets, it remains applicable under current Secret Scanner policy. The file was not read in full for this diagnosis. One applicable file was skipped at the safety limit; `PARTIAL` is accurate. The scanner's `artifacts_skipped=61` also includes 60 unsupported/nontext artifacts that do not independently make coverage partial. Aggregate diagnostic paths are absent in the public report, a diagnosability limitation.

| Secret budget | Default and actual runtime value | Hard ceiling |
| --- | ---: | ---: |
| Per file | 1,048,576 bytes | 4,194,304 bytes |
| Total bytes | 67,108,864 bytes | 268,435,456 bytes |
| Per line | 16,384 bytes | 65,536 bytes |
| Matches per rule per file | 100 | 1,000 |
| Findings per file | 100 | 1,000 |
| Total findings | 1,000 | 10,000 |
| Elapsed time | 300 seconds | 3,600 seconds |

The observed file is about 2.07 MiB, above the 1 MiB default. Raising that default would increase full-read/decoded-text memory and line/regex work for every newly admitted large text file, and the file can grow. There is no evidence that an unconditional limit increase is the right fix. **Limit decision: UNKNOWN pending confirmation of the file's provenance and intended scope; maintain honest PARTIAL.** Future work may consider bounded streaming or a trusted, explicit scope policy, but neither was implemented here. Do not automatically exclude `log/` or mark this file not applicable solely from its filename.

## Dependency coverage

The four admitted source artifacts were `apps/dashboard/package-lock.json` (153,464 bytes), `apps/dashboard/package.json` (1,290 bytes), `pyproject.toml` (1,071 bytes), and `uv.lock` (60,424 bytes). Inventory inspection used the formal parser and an injected provider that would reject any attempted query. It yielded 344 records: 343 exact versions and one `local_path` record; 341 distinct exact registry lookup keys. Directness was 28 direct, 19 transitive, and 297 unknown. There were no parser failures or unsupported dependency source artifacts.

The sole unresolved record is PyPI `personal-automated-equity-trading-platform` from `uv.lock`, marked `local_path`, with no queryable registry version. A bounded static read confirmed the matching `pyproject.toml` project name and `uv.lock` source `editable="."`. This identifies the repository's own editable root package, not an unresolved third-party registry pin. The lock contains a version field, but an editable local source is intentionally not looked up as a public registry release. The 343 third-party exact records are already resolved; manifest constraints have not caused an additional unresolved item. There is no credential-bearing URL in the unresolved record.

In this offline run, all 341 unique exact lookup keys returned `OFFLINE_NO_CACHE`; cache hits, `MATCH`, `NO_MATCH`, `QUERY_FAILED`, and `UNSUPPORTED` were zero. The report's `DEPENDENCY_PROVIDER_NO_DATA` and `no_data=341` are aggregate coverage language for unavailable advisory data, not 341 positive `NO_MATCH` results. Dependencies are `PARTIAL` for **both** the absent offline advisory cache and the deliberately unresolved local editable record. The latter will remain non-queryable even if OSV is enabled. No live provider request was sent.

Current default OSV budgets allow 500 unique exact keys, batches of 50, up to 100 advisory details per batch, 1 MiB per response, 16 MiB provider response bytes per batch, 10 seconds per request, and a best-effort 120-second deadline across batches. For 341 uncached keys, a full online run would attempt up to seven batch requests and, in the theoretical maximum, 700 detail requests before time/byte limits intervene. There is no scan-wide advisory detail request count cap; the 100-advisory limit applies per batch. **Do not make a first live validation by querying the full project.** A later authorized pilot should use a small trusted exact-version subset, observe cache and request counts, then decide whether a full run is appropriate; incomplete provider work must remain `PARTIAL`.

## Finding snapshot

Only location, rule, severity, and confidence are recorded here; no evidence or source is reproduced.

| Role | Relative path | Rule | Severity | Confidence |
| --- | --- | --- | --- | --- |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| Test | `tests/integration/test_portfolio_phase4.py` | `SECRET.GENERIC.ASSIGNMENT` | MEDIUM | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/export_openapi.py` | `SAST.PYTHON.PATH_TRAVERSAL` | MEDIUM | MEDIUM |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |
| First-party script | `scripts/start_e2e.ps1` | `BEHAVIOR.ENVIRONMENT_READ` | INFO | LOW |

## Decision

**HARDENING #5 NEEDED**, but not a new scanner feature or a limit increase. A common first-party editable root is presently counted as unresolved third-party dependency coverage, and aggregate size diagnostics do not identify the skipped file in the public report. Both are product-level scope/observability issues. A safe future change would prove root-package identity from admitted manifest and lockfile data before classifying it outside registry dependency coverage, while preserving partial coverage for other local/path/VCS dependencies. It should also expose a bounded target-relative path for the oversized file diagnostic. This diagnosis made **no code change**; preserving `PARTIAL` and Gate `BLOCK` is correct until coverage is actually resolved. Full-project live OSV is not recommended as the first online run.

## Hardening #5 follow-up (2026-09-24)

The earlier diagnosis above remains the **before** record. Source hardening now recognizes the single scan-root `uv.lock` `editable="."` entry as `FIRST_PARTY_ROOT` only when the admitted scan-root `pyproject.toml` supplies the matching normalized `[project].name`. Name equality alone, an outside-root editable path, another local dependency, a missing manifest, and conflicting same-name lock entries do not qualify. The root record remains in inventory with both source paths, but is not sent to OSV or counted unresolved third-party. This changes applicability, not the 341 offline lookup results.

Formal passive re-scans used `uv run --offline --no-sync security-auditor scan <target> --offline --no-ai` and wrote untracked `audit-trading-platform-hardening5.json` and `.html` outside the target. The target Git short status was empty before and after. The new JSON 1.1 summary reports 344 packages, 343 exact registry records, one first-party root, zero unresolved third-party records, 341 no-data/offline-no-cache lookup keys, zero cache hits, and zero provider queries. Discovery, Python SAST, and Behavior are COMPLETE; Secrets, Dependencies, Correlation, and Overall remain PARTIAL. Ten Findings remain (0 critical, 0 high, 2 medium, 0 low, 8 info); this is an observed snapshot, not a stability guarantee for an active project.

The sole public Secret size diagnostic now has code `SECRET_FILE_TOO_LARGE` and path `log/program.log.20260924`; the observed 2,169,199-byte UTF-8 text file still exceeds the unchanged 1 MiB default. HTML uses `lang="zh-TW"`, displays the relative path and the new dependency counts, and contains no absolute target path in the checked rendering. Gate remains `BLOCK` for actual PARTIAL coverage and offline advisory-data absence, with no blocking Finding. `DEPENDENCY_UNRESOLVED_VERSION` is no longer present. No target code, target tests, package installation, Gemini, or live OSV ran; no target file was intentionally modified.

The full project-local Python 3.12.11 offline suite ran with live gates unset: 165 tests, 161 passed, 0 failed, 4 skipped. Synthetic regressions cover root identity and counterexamples, offline cache absence, Secret filename redaction, JSON/HTML paths, and optional JSON 1.1 Gate fields.

The remaining RC distribution wheel/sdist predate hardening #4 and #5. Rebuild and clean-smoke the 0.9.0 RC artifacts before external validation. Before any full-project live OSV request for 341 keys, assess a scan-wide advisory detail request budget; the current per-batch limit alone can permit too many detail requests.
