# Finding correlation (Phase 5)

`CorrelationEngine.correlate(ScannerResult[])` consumes already normalized, redacted findings. It does not reopen artifacts, rerun scanners, execute target content, access the network, or mutate original `Finding` objects. It returns a separate immutable `CorrelationResult` for a future reporter. No CLI or reporter is implemented here.

The package separates input orchestration (`engine.py`), validated graph identities and budgets (`graph.py`), deterministic relationships (`rules.py`), explainable priority (`scoring.py`), and immutable contracts (`models.py`). The dependency direction is from orchestration toward those pure modules and core contracts; none imports a scanner implementation or reporter.

## Identities and graph

Finding nodes use the original fingerprint; file, dependency, vulnerability, source, and sink nodes use versioned hashes of validated structural identifiers. Function identity is accepted only from a bounded `function_id` structured evidence field. It is currently absent from Phase 3 findings, so same-function relationships require a future normalized producer. Paths must be safe root-relative POSIX paths and are never copied into correlation explanations. Unrecognized or unsafe findings yield a fixed diagnostic and partial coverage. Hash collisions or inconsistent duplicate fingerprints yield diagnostics; original inputs are never deleted.

Edges carry stable type, source and target, confidence, fixed evidence labels, rationale, and rule ID. V1 implements `SAME_FILE`, `SAME_DEPENDENCY`, `SAME_VULNERABILITY`, `SAME_SOURCE`, `SAME_SINK`, `SOURCE_TO_SINK`, `SUPPORTS`, `OVERLAPS`, `RELATED_BEHAVIOR`, `POSSIBLE_SEQUENCE`, `POSSIBLE_DEPENDENCY_USE`, and `POSSIBLE_ATTACK_PATH`. The enum reserves additional relationships for reviewed future rules. A same-file entity edge is an indexing fact, not a vulnerability correlation.

## Deterministic rules

| Rule | Evidence | Interpretation |
| --- | --- | --- |
| `CORRELATION.SAST_BEHAVIOR.SAME_SINK` | Compatible SAST/behavior rules on the same file and line | Behavior supports the SAST primary finding; behavior severity is not added |
| `CORRELATION.BEHAVIOR.OVERLAP` | Shell/process/command behavior on one file and line | Overlapping descriptions of one local operation |
| `CORRELATION.SECRET.NETWORK_CONTEXT` | Same file within configured line distance or explicit same function | Context only; LOW for proximity, MEDIUM for structured same function; no exfiltration claim |
| `CORRELATION.DEPENDENCY.PROJECT_REFERENCE` | PyPI distribution name exactly equals an explicit normalized Python import name | Dependency appears referenced; no vulnerable API reachability claim |
| `CORRELATION.BEHAVIOR.LOCAL_SEQUENCE` | Explicit same function, ordered network then process operation within distance | LOW confidence contextual sequence, not a download-execute flow |
| `CORRELATION.BEHAVIOR.PERSISTENCE_CLUSTER` / `CREDENTIAL_CLUSTER` | Explicit same function and nearby network, process, and relevant behavior | LOW confidence candidate, with no malware, theft, persistence-success, or intent verdict |

The Phase 3 `BEHAVIOR.DOWNLOAD_EXECUTE` finding is the only v1 evidence for a local same-file download and subsequent launch candidate. Phase 5 annotates it; it does not emit a second security finding. Two unrelated files containing a network call and process call never form that candidate. Proximity alone never proves dataflow. Built-in rules use fixed IDs and pure result data; a future plug-in rule contract must preserve these boundaries.

`CorrelationRule` is a future adapter protocol with stable ID, title, required categories, confidence policy, priority, explanation, and `evaluate(findings, graph) -> CorrelationRuleOutput`. V1 built-in rules are deliberately engine-owned so untrusted target content cannot register rule code or mutate shared graph state. Any future adapter output must pass the same bounded validation gate before insertion.

The import-reference rule requires an `import_reference` normalized finding with `import_name` structured metadata. Existing Phase 3 scanners do not emit this inventory. Thus current scans report dependency relevance as `PRESENT` until a reviewed static import-reference producer exists. No fuzzy distribution/import mapping is attempted; names containing a distribution hyphen are not equated to imports. This gap is explicit rather than a guessed reachability conclusion.

## Grouping and confidence

`FindingGroup` records PRIMARY/SUPPORTING roles and support-edge IDs. Same-sink SAST is primary; compatible behavior is supporting. All original findings remain accessible and unchanged. A behavior signal supporting a SAST finding is not separately summed into that group's priority. Secret and dependency relevance edges remain contextual and do not change the original severity or confidence.

Edge confidence is no higher than the weakest participating finding. Correlation assessment confidence starts from the primary finding and its direct support, then is capped at MEDIUM when any supplied scanner or correlation coverage is incomplete. A LOW proximity edge does not become a HIGH-confidence exploit claim. `AttackPathCandidate` includes assumptions and limitations and is never labeled confirmed.

## Completeness and limits

`CorrelationSummary` includes per-scanner coverage, COMPLETE/PARTIAL/ABORTED/FAILED, counts, and fixed-code diagnostics. Scanner summary completeness is checked in addition to top-level status. Invalid input, duplicate/collision, timeout, node/edge/finding/path budget, and dense local bucket cases produce diagnostics. Graph construction uses indexes by file, line, function, and import name; dense local candidate sets are capped rather than unrestricted quadratic joins. Limits have hard ceilings in `core/config.py`. Timeout checks bound the Python loop but do not forcibly preempt a single operation.

The correlation result is data for Phase 7 reporting. Future serialization must recheck redaction, escape output, and never dump arbitrary source or structured payloads. The engine itself copies only fixed labels and validated structural IDs, not free-text Finding titles, snippets, descriptions, or evidence values.
