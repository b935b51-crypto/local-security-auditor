# RC real-world validation: Trading Platform coverage diagnosis

## Bounded full Trading Platform live OSV validation (2026-09-24)

At source checkpoint `4d5f9ab`, a fresh passive inventory of the Trading Platform found four admitted dependency sources: `pyproject.toml`, `uv.lock`, `apps/dashboard/package.json`, and `apps/dashboard/package-lock.json`. The 344 records comprised one evidenced first-party editable root and 343 exact registry dependency records, collapsing to 341 unique OSV keys. There were no unresolved third-party, local-path, VCS, URL, or constraint-only records. No target code, tests, install hooks, or modules ran, and the target Git short status was empty before and after.

With batch size 50, the uncached preflight required `ceil(341 / 50) = 7` batches. This passed the scan-global caps of 10 batch, 50 detail, and 60 total network requests; the effective detail ceiling was `min(50, 60 - 7) = 50`. One explicitly online, AI-disabled **formal orchestrator scan** used the fixed OSV HTTPS endpoint and the normal tool-local cache. The same immutable report produced both untracked JSON 1.1 and zh-TW HTML files outside the target, so the second format sent no second live query. Actual provider usage was **7 batch, 0 detail, 7 total requests**, with 0 cache hits and 0 deduplicated advisory details. OSV returned no advisory references for these exact coordinates: 0 seen, 0 accepted, 0 truncated, 0 overflowed packages, and 0 dependency vulnerability Findings. No provider, timeout, rate-limit, response-shape, or budget diagnostic occurred. All 341 query results were complete `NO_MATCH` and eligible for normalized cache write; this means no known matching advisory was returned, not that the application is safe.

The live Dependencies component was `COMPLETE` with 0 unresolved and 0 no-data lookups. The immediate offline replay used the same formal pipeline and tool-local cache, with a transport that counts and rejects any attempted network call. It recorded **0 network attempts**, 341 cache hits, `COMPLETE` dependency coverage, and 0 dependency Findings. Dependency summary states, coverage components, and all Finding fingerprints matched the live report; network counters and cache-hit counts differed as expected. The live scan took 5.203 seconds (2.687 seconds in OSV provider calls); the offline replay took 2.172 seconds.

The 2,169,199-byte `log/program.log.20260924` still exceeded the unchanged 1 MiB Secret per-file limit. Thus Secrets, Correlation, and Overall remained `PARTIAL`; Discovery, SAST, Behavior, and Dependencies were `COMPLETE`. Each report had 17 total Findings (0 critical, 0 high, 3 medium, 0 low, 14 info), none from known vulnerable dependencies. Gate 1.0 returned `BLOCK` for both reports with `COVERAGE_PARTIAL`, `NON_BLOCKING_PRIMARY_FINDINGS`, and `SCAN_DIAGNOSTICS`; its sole diagnostic code was `SECRET_FILE_TOO_LARGE`. The reports were untracked and excluded from this checkpoint. No production scanner code, safety limit, default exclusion, target file, or release artifact was changed. The 0.9.0 wheel/sdist still predate the current source and need rebuilding and clean smoke validation before external RC use.

---

## Hardening #7 advisory overflow (2026-09-24)

The production OSV adapter now distinguishes a malformed batch from a valid response containing more advisory references than the local processing caps. It validates all IDs within the 1 MiB response bound, stably deduplicates within each result, accepts at most 100 unique IDs per result and 100 unique IDs across one batch, and marks omitted references incomplete. The safety caps were **not raised**. A truncated package lookup is never cached as complete or returned as `NO_MATCH`; confirmed Findings survive later detail-budget exhaustion or timeout.

The final default Python 3.12.11 offline suite passed 181 tests: 175 passed, 0 failed, 6 skipped. Fake responses covered 100/101/106 IDs, duplicate IDs, malformed tails, per-batch cap, detail/total budgets, timeout preservation, cache nonwrite, JSON/console/zh-TW HTML, and Gate BLOCK. Live tests remain opt-in and skipped by default.

One authorized synthetic ten-coordinate flow used the official OSV HTTPS endpoint with caps of 1 batch, 3 details, and 4 total requests. The batch returned HTTP 200, `application/json`, 17,199 bytes, and 10 results; the largest result held 106 advisory references. Across the batch, 253 unique-per-result references were seen, 100 accepted under the existing per-batch cap, and 153 not processed. These are **references, not confirmed vulnerabilities**. Actual calls were **1 batch + 3 details = 4 total**. Three affected Findings were retained. Diagnostics were `DEPENDENCY_OSV_ADVISORY_LIMIT_REACHED` and `DEPENDENCY_OSV_DETAIL_BUDGET_REACHED`; there was **no** `VULN_PROVIDER_BAD_RESPONSE`. Dependency coverage was PARTIAL. One normalized complete package lookup was cached; incomplete lookups were not cached as complete. Offline replay made zero network requests and had one cache hit. Temporary synthetic target and tool-local cache were removed. No Trading Platform online query, Gemini request, raw payload log, source/path upload, wheel rebuild, or Phase 10 work occurred. The Gate's BLOCK behavior for the same truncated semantics was verified in the offline report regression, rather than by a second live scan.

This establishes readiness for a separately authorized **bounded** full-project OSV validation, conditional on rechecking current package inventory and budgets. The current 0.9.0 wheel/sdist are stale relative to source changes.

---

## OSV live response mismatch diagnosis (2026-09-24)

The hardening #6 ten-key pilot's `VULN_PROVIDER_BAD_RESPONSE` is now localized by a new explicitly gated, staged synthetic test. It used only public PyPI names and exact versions; the official HTTPS provider received no source, path, or credentials. The test records only HTTP status, sanitized media type, byte count, JSON type, allowlisted key names, bounded result/advisory counts, and fixed validator reason codes. It never records response bodies or advisory descriptions.

| Stage | Keys | HTTP | Batch | Detail | Findings | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 1 | 200 | 1 | 2 | 2 | Complete |
| 2 | 2 | 200 | 1 | 3 | 3 | `DEPENDENCY_OSV_DETAIL_BUDGET_REACHED`; partial findings retained |
| 3 | 5 | 200 | 1 | 3 | 3 | `DEPENDENCY_OSV_DETAIL_BUDGET_REACHED`; partial findings retained |
| 4 | 10 | 200 | 1 | 0 | 0 | `VULN_PROVIDER_BAD_RESPONSE`; batch `VULNS_LIMIT_EXCEEDED` |

Cumulative actual HTTP attempts: **4 batch + 8 detail = 12 total**. The first three flows proved that a valid response exceeding the three-detail network budget is classified as budget exhaustion, not a bad response. The fourth batch was valid JSON with 10 result objects; one result contained **106 advisory IDs**, over the configured `max_advisories=100` per-result guard. The provider rejected that count before fetching details and classified it as malformed. The original pilot had the same ten-coordinate set, so this is strong evidence for its cause; the previous run's exact HTTP counts remain unknown. There was no retry after the first failure in this diagnostic flow.

Root cause classification: **VALIDATOR_TOO_STRICT** for a legitimate provider response relative to a safety count limit. The 100-advisory cap should remain in force, but its exceedance should be reported as a distinct bounded coverage limit rather than `BAD_RESPONSE`. This diagnosis added stage/reason observability and offline shape/budget tests; it did **not** change the production provider's limiting behavior. A narrowly scoped Hardening #7 is needed to define partial coverage and result preservation for oversized advisory lists. A full Trading Platform online query remains unauthorized and unattempted. The prior 0.9.0 wheel/sdist remain stale.

The Python 3.12.11 default offline suite after this diagnosis ran 176 tests: 170 passed, 0 failed, 6 skipped. All live gates were unset; the gated live diagnosis is skipped by default.

---

## Hardening #6 provider-budget pilot (2026-09-24)

Source hardening now caps one OSV operation at 10 batch, 50 advisory detail, and 60 total network requests by default. For the Trading Platform's last observed 341 unique exact keys and batch size 50, seven batch requests would be needed without package cache; advisory details are capped at 50 and all network calls at 60. The project was **not** queried online in this hardening. Its earlier offline coverage and Gate result remain the latest observed target state.

Offline synthetic regressions passed for batch/detail/total limits, cross-batch advisory-ID reuse, normalized package cache replay, retained partial Findings, unqueried `NO_DATA` semantics, public counters, zh-TW budget warning, and Gate `BLOCK`. The default Python 3.12.11 suite ran 170 tests, 165 passed, 0 failed, 5 skipped (the additional skip is the new gated live pilot).

A single gated online pilot used ten public PyPI name/version coordinates from an inert temporary requirements file. It was limited to one official HTTPS batch request and three advisory detail requests, with a four-request total ceiling. The formal provider returned `VULN_PROVIDER_BAD_RESPONSE`; no Finding was produced. The test assertion occurred before its safe method-count output, so the **actual** live POST/GET counts are not available from that run; the enforced maximum was four. The temporary target/cache were removed. There was no second live flow, Gemini call, or target source/local path upload. This pilot is **not a successful live validation**. A future bounded, metadata-only diagnostic of the response mismatch is needed before a 341-key live scan. The earlier one-key PyYAML live result remains separately verified.

---

## Earlier offline diagnosis and hardening #5 (historical baseline)

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

The remaining RC distribution wheel/sdist predate hardening #4 and #5. Rebuild and clean-smoke the 0.9.0 RC artifacts before external validation. At the time of hardening #5, a scan-wide advisory detail budget was still missing; hardening #6 added that limit, with its new live pilot outcome recorded above.
