# Finding correlation (Phase 5)

`CorrelationEngine.correlate(ScannerResult[])` consumes already normalized, redacted findings. It does not reopen artifacts, rerun scanners, execute target content, access the network, or mutate original `Finding` objects. It returns a separate immutable `CorrelationResult` for reporting; the engine does not implement CLI or rendering behavior.

The package separates input orchestration (`engine.py`), validated graph identities and budgets (`graph.py`), deterministic relationships (`rules.py`), explainable priority (`scoring.py`), and immutable contracts (`models.py`). The dependency direction is from orchestration toward those pure modules and core contracts; none imports a scanner implementation or reporter.

## Identities and graph

Finding nodes use the original fingerprint; file, dependency, vulnerability, source, and sink nodes use versioned hashes of validated structural identifiers. Function identity is accepted only from a bounded `function_id` structured evidence field. It is currently absent from Phase 3 findings, so same-function relationships require a future normalized producer. Paths must be safe root-relative POSIX paths and are never copied into graph explanations. Rejected inputs yield a fixed diagnostic code with safe attribution and partial coverage. Hash collisions or inconsistent duplicate fingerprints yield diagnostics; original inputs are never deleted.

Edges carry stable type, source and target, confidence, fixed evidence labels, rationale, and rule ID. V1 implements `SAME_FILE`, `SAME_DEPENDENCY`, `SAME_VULNERABILITY`, `SAME_SOURCE`, `SAME_SINK`, `SOURCE_TO_SINK`, `SUPPORTS`, `OVERLAPS`, `RELATED_BEHAVIOR`, `POSSIBLE_SEQUENCE`, `POSSIBLE_DEPENDENCY_USE`, and `POSSIBLE_ATTACK_PATH`. The enum reserves additional relationships for reviewed future rules. A same-file entity edge is an indexing fact, not a vulnerability correlation.

## Deterministic rules

| Rule | Evidence | Interpretation |
| --- | --- | --- |
| `CORRELATION.SAST_BEHAVIOR.SAME_SINK` | Compatible SAST/behavior rules on the same file and line | Behavior supports the SAST primary finding; behavior severity is not added |
| `CORRELATION.BEHAVIOR.OVERLAP` | Shell/process/command behavior on one file and line | Overlapping descriptions of one local operation |
| `CORRELATION.BEHAVIOR.SAME_SINK_SPECIFIC` | `PROCESS_EXEC` and a more specific shell/CMD/PowerShell signal at the same file, line, and column | Specific command signal is PRIMARY; generic process signal is SUPPORTING. A different call on the same line remains separate. |
| `CORRELATION.SECRET.NETWORK_CONTEXT` | Same file within configured line distance or explicit same function | Context only; LOW for proximity, MEDIUM for structured same function; no exfiltration claim |
| `CORRELATION.DEPENDENCY.PROJECT_REFERENCE` | PyPI distribution name exactly equals an explicit normalized Python import name | Dependency appears referenced; no vulnerable API reachability claim |
| `CORRELATION.BEHAVIOR.LOCAL_SEQUENCE` | Explicit same function, ordered network then process operation within distance | LOW confidence contextual sequence, not a download-execute flow |
| `CORRELATION.BEHAVIOR.PERSISTENCE_CLUSTER` / `CREDENTIAL_CLUSTER` | Explicit same function and nearby network, process, and relevant behavior | LOW confidence candidate, with no malware, theft, persistence-success, or intent verdict |

The Phase 3 `BEHAVIOR.DOWNLOAD_EXECUTE` finding is the only v1 evidence for a local same-file download and subsequent launch candidate. Phase 5 annotates it; it does not emit a second security finding. Two unrelated files containing a network call and process call never form that candidate. Proximity alone never proves dataflow. Built-in rules use fixed IDs and pure result data; a future plug-in rule contract must preserve these boundaries.

`CorrelationRule` is a future adapter protocol with stable ID, title, required categories, confidence policy, priority, explanation, and `evaluate(findings, graph) -> CorrelationRuleOutput`. V1 built-in rules are deliberately engine-owned so untrusted target content cannot register rule code or mutate shared graph state. Any future adapter output must pass the same bounded validation gate before insertion.

The import-reference rule requires an `import_reference` normalized finding with `import_name` structured metadata. Existing Phase 3 scanners do not emit this inventory. Thus current scans report dependency relevance as `PRESENT` until a reviewed static import-reference producer exists. No fuzzy distribution/import mapping is attempted; names containing a distribution hyphen are not equated to imports. This gap is explicit rather than a guessed reachability conclusion.

## Grouping and confidence

`FindingGroup` records PRIMARY/SUPPORTING roles and support-edge IDs. Same-sink SAST is primary; compatible behavior is supporting. All original findings remain accessible and unchanged. A behavior signal supporting a SAST finding is not separately summed into that group's priority. Secret and dependency relevance edges remain contextual and do not change the original severity or confidence.

The current production scanner IDs are `sast.python` and `behavior.static`; correlation accepts those IDs and the earlier synthetic aliases used by contract tests. Grouping does not delete the underlying machine findings or add their severities. The JSON 1.1 `summary.counts.severity` and `total_findings` still count all distinct final Findings; `finding_groups` is the separate primary-issue view. The Gate continues to evaluate primary roles under policy 1.0. Group membership expresses a static same-sink relation, not runtime exploitability.

Edge confidence is no higher than the weakest participating finding. Correlation assessment confidence starts from the primary finding and its direct support, then is capped at MEDIUM when any supplied scanner or correlation coverage is incomplete. A LOW proximity edge does not become a HIGH-confidence exploit claim. `AttackPathCandidate` includes assumptions and limitations and is never labeled confirmed.

## Completeness and limits

`CorrelationSummary` includes per-scanner coverage, COMPLETE/PARTIAL/ABORTED/FAILED, counts, and fixed-code diagnostics. Scanner summary completeness is checked in addition to top-level status. Invalid input, duplicate/collision, timeout, node/edge/finding/path budget, and dense local bucket cases produce diagnostics. Graph construction uses indexes by file, line, function, and import name; dense local candidate sets are capped rather than unrestricted quadratic joins. Limits have hard ceilings in `core/config.py`. Timeout checks bound the Python loop but do not forcibly preempt a single operation.

The correlation result is data for reporting, which rechecks redaction, escapes output, and never dumps arbitrary source or structured payloads. The engine itself copies only fixed labels and validated structural IDs, not free-text Finding titles, snippets, descriptions, or evidence values.

## Invalid-input attribution and producer path contract

The ingestion validator runs **before** graph relationships, grouping, and scoring. It validates Finding/Location/Evidence types, 64-hex fingerprint, bounded safe relative path, line/column, severity/confidence enums, rule/scanner/category tokens, bounded structured evidence pairs, and optional dependency/advisory coordinates. Finding `id` is not the graph key; fingerprint is. Free-text source/sink and snippets are not used as structural graph identities. Only whitelisted structured source/sink metadata contributes edges. Roles and primary/supporting references are constructed after admission, not read from an input Finding.

`CORRELATION_INVALID_FINDING` remains a pipeline diagnostic, not a target vulnerability. Each of the first 100 rejected inputs has a separately attributable diagnostic: existing public `path` contains a sanitized target-relative path when representable; existing `message` contains a validated fingerprint (or input ordinal when invalid), bounded rule ID, line when valid, and fixed reason. Reasons include `INVALID_FINGERPRINT`, `INVALID_LOCATION`, `UNREDACTED_OR_UNSAFE_PATH`, `INVALID_STRUCTURED_EVIDENCE`, `INVALID_DEPENDENCY_COORDINATE`, `INVALID_VULNERABILITY_REFERENCE`, `INVALID_SEVERITY_OR_CONFIDENCE`, and invalid identity/token types. Overflow retains an exact count with `DETAILS_OMITTED`; it never silently discards the failure. No source content, evidence, raw Finding, exception, or absolute path is copied. The report's existing diagnostic cap still applies.

The observed three Secret inputs failed the shared redacted-path contract: the Secret emitter only masked detected values in filenames, while correlation also required the shared credential-shaped filename redaction. The emitter now applies `safe_finding_path` **before fingerprint and Finding creation**, for both full-buffer and bounded large-text modes. The validator is not relaxed, and original Findings are not coerced in correlation. Matching rules, limits, counts, and severity are unchanged. Fingerprints for previously noncanonical Secret paths change because the canonical redacted path is an identity input; ordinary canonical-path fingerprints remain stable, and existing collision diagnostics remain active.

Correlation still inherits incomplete upstream scanner coverage. Removing all invalid-input diagnostics does **not** make correlation COMPLETE if supplied dependency coverage remains PARTIAL. This is the existing propagation contract; it was not redesigned.

### 2026-10-02 validation evidence (candidate 1.0.7)

Read-only offline diagnosis at scanner HEAD `7f948cf` identified **MALFORMED_FINDING_EMITTED_UPSTREAM**: all three inputs were otherwise valid but `safe_finding_path(location.path) != location.path`. They failed `_location` during ingestion. Group construction had not run, so no dangling reference or primary/supporting invariant was involved. This does not establish a new target vulnerability or adjudicate whether the detected test values are real credentials.

All three share the public path `tests/unit/test_account_credential_[REDACTED]`, scanner `secrets`, category `secret`, evidence kind `redacted_secret`, and no source/sink trace. Before repair they had no correlation role or group; after repair each has a valid primary group. No evidence values or original path suffix are included here.

| Original fingerprint prefix | Rule | Line:column | Severity/confidence | New fingerprint prefix |
| --- | --- | --- | --- | --- |
| `15f17a39e242ba6b` | `SECRET.GENERIC.ASSIGNMENT` | 57:10 | MEDIUM/MEDIUM | `3529565038bc42ab` |
| `559366da115f7930` | `SECRET.GENERIC.ASSIGNMENT` | 441:14 | MEDIUM/MEDIUM | `9bdaff4152ce8ade` |
| `366e9ac6db3370944` | `SECRET.GENERIC.ENTROPY` | 444:29 | LOW/LOW | `2f8c760c86c32c83` |

Final Trading Platform source deep/offline/no-AI validation: invalid-input diagnostics **3 -> 0**; all 68 Findings retained (0 Critical, 0 High, 12 Medium, 26 Low, 30 Info). Discovery/Secrets/SAST/Behavior COMPLETE. Dependencies PARTIAL from 341 stale cache hits (0 fresh, 0 no-data; 343 exact dependency records unassessed for freshness). Correlation remains PARTIAL solely through existing upstream propagation, with no local diagnostic. Overall PARTIAL; actual Gate CLI BLOCK, exit 20. OSV/Gemini requests 0; sockets were denied during validation. Group membership, assessment/attack-path references, JSON 1.1, SARIF 2.1.0, and HTML/console layered wording passed.

Initial diagnosis target HEAD was `9cb212b01b5ca729a0c8483e265f53cd023fd8d2`; external work advanced it to `0c5ad0f05d17a7e0ccc9268acaac393491ad96a7` before final validation. Each scan's own before/after HEAD and empty short status matched. The Auditor did not execute/import/install/modify target content or refresh provider data. Temporary reports were removed. The three patterns are also covered by inert synthetic golden tests; current full offline Python 3.12.11 regression is **274 tests, 268 passed, 0 failed, 6 skipped**.
