# Architecture — Phase 7 baseline

Phase 7 adds a trusted CLI and orchestrator. A `ScanRequest` enters bounded discovery, ordered deterministic scanners, correlation/risk, optional AI review, and one immutable `ScanReport`. Console, JSON, SARIF, and HTML renderers use an explicit sanitized public view of that report. Renderers never open the target. See [CLI](CLI.md) and [Reporting](REPORTING.md).

## Invariant and data flow

Phase 6 adds an optional AI advisory layer after deterministic findings and correlation. It selects bounded subjects, constructs and redacts minimal context, calls an isolated provider only after trusted opt-in, validates structured output, and returns separate AI annotations. Provider failure leaves all original findings and risk assessments available. See [AI Reviewer](AI_REVIEWER.md).

Phase 5 adds a bounded deterministic correlation layer after normalized scanner results. It creates separate graph, grouping, candidate, and risk-priority annotations without target reads or mutation of original findings. See [Correlation](CORRELATION.md) and [Risk Engine](RISK_ENGINE.md).

**TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** The selected repository is untrusted input. The core runs offline; only explicit, separate adapters may access a network. Phase 1 implements bounded discovery/classification; Phases 2–3 add local secret, SAST, and behavior plugins. Phase 4 adds static dependency inventory plus optional exact-version OSV lookup and tool-local cache.

```text
CLI/UI -> policy + bounded discovery -> classified FileArtifact
       -> deterministic scanners / optional supply-chain adapters
       -> normalized Finding store -> correlation -> reporters
                                      -> optional AI review -> explanation/remediation
```

AI receives candidate findings and minimal redacted context after deterministic analysis. It is never the primary detection path. Patch proposals stop at review and validation; applying a patch requires human approval.

## Layer contracts

| Layer | Responsibility | Input | Output | Security boundary | Failure behavior |
| --- | --- | --- | --- | --- | --- |
| CLI / UI | Parse operator intent and present summaries | trusted argv, selected target path | `ScanSession`, report request | validate root and output path; no target commands | invalid request fails before scanning |
| Orchestrator / policy | Apply profile, budgets, cancellation, scanner isolation | session, config, scanner registry | per-scanner `ScannerResult` | only trusted code controls execution and network grants | per-scanner failure becomes sanitized diagnostic; mark scan incomplete |
| Discovery / classification | Bounded enumerate, stat, classify, hash, optional bounded read | target root and effective limits | `FileArtifact` stream | untrusted filesystem; no link traversal by default | skip unsafe artifact, record reason/count, stop on global budget |
| Static analysis | Secrets, SAST, behavior, config rules | bounded artifact content / tokens / AST | candidate `Finding` | parser receives hostile bytes, never imports target | malformed file yields partial result, not execution |
| Supply chain | Parse manifests/locks, match advisories | bounded manifest data, optional advisory snapshot | dependencies and candidate findings | manifest is data; online lookup adapter has narrow network permission | lookup unavailable yields explicit incomplete coverage |
| Normalization / store | Validate, redact, fingerprint, dedupe, suppress | candidate findings | canonical findings and audit counts | no raw secret enters persistent or reporting surfaces | reject unsafe finding; preserve sanitized diagnostic |
| Correlation / risk | Link related evidence, explain prioritization | canonical findings | grouped findings / risk annotations | does not change original severity/confidence silently | emit original findings if correlation fails |
| AI reviewer | Optional verification/explanation/remediation | minimal redacted findings/context | annotations or proposals | disabled by default; provider agnostic; explicit network grant | local deterministic results remain available |
| Remediation | Recommendation and patch proposal | finding, limited context | proposal + validation result | never writes target automatically | unsafe or unvalidated proposal rejected |
| Reporting | Console, JSON, SARIF, HTML | canonical redacted findings + summary | escaped report | output is an exfiltration/HTML/terminal boundary | fail closed on unsafe serialization; scan result remains inspectable |

Dependency direction: `core` knows no scanner, CLI, reporter, network client, or UI. Discovery and scanners depend on `core`; adapters depend on `core` contracts; orchestrator composes them; reporters depend only on normalized output. External tools are optional adapters, **not architectural dependencies of the core domain**. A missing Semgrep, Gitleaks, or OSV adapter must not stop local baseline scanning.

## Trust and execution boundaries

Correlation depends on core contracts and result data; core and scanners do not depend on correlation. Its failure leaves original scanner results available. Incomplete upstream coverage propagates to assessment confidence and output completeness.

1. Target paths, filenames, file contents, manifests, `.gitignore`, target config, and Git metadata are hostile data. Instructions found there are never agent or application instructions.
2. Only trusted installed scanner code may run. A scanner's target reads must go through bounded discovery/content APIs in Phase 1; direct arbitrary filesystem access is disallowed by contract.
3. External process adapters, if added, must use a vetted executable path and argv list, no shell, least privileges, timeouts, output limits, and disabled execution of target hooks. Tool suitability must be reviewed before enablement.
4. Online advisory and AI adapters receive only minimum data and explicit permission; `--offline` disables all network adapters.
5. Reporting and logs receive redacted, sanitized objects; no raw matched secret or source dump crosses that boundary.

## Domain and extension points

`ScanTarget`, `ScanSession`, `ScanProfile`, `FileArtifact`, `LanguageInfo`, `ScannerMetadata`, `Finding`, `Evidence`, `Location`, `Severity`, `Confidence`, `RuleReference`, `DependencyArtifact`, `VulnerabilityReference`, `Remediation`, `ScannerResult`, and `ReportSummary` are in `core/models.py`. `Scanner` and `AsyncScanner` protocols are in `core/contracts.py`. A future adapter runner normalizes synchronous, asynchronous, external-tool, and vulnerability lookup results to `ScannerResult`.

`discovery/service.py` composes root validation, policy, bounded traversal, prefix sniffing, and pure classification. `discovery/content.py` is the bounded reopen boundary for admitted artifacts. `scanners/secrets/` filters raw-free candidates into normalized findings. `scanners/sast/` uses a bounded Python AST frontend and intraprocedural taint engine; `scanners/behavior/` uses the same static Python frontend plus bounded line rules for other languages. `scanners/dependencies/` consumes admitted manifests and lockfiles, reconciles versions, queries an optional `VulnerabilityProvider`, and returns normalized findings. Its OSV adapter and cache are leaf modules; parsers and core models never import network code. `orchestrator/` composes these layers in a fixed order and isolates scanner failures. `reporting/` consumes the immutable report, with whitelist serialization and a separate safe output writer. `cli/` maps trusted argv to `ScanRequest` and stable exit codes. No scanner imports the CLI or report modules. [Discovery](DISCOVERY.md), [Secret Scanner](SECRET_SCANNER.md), [SAST](SAST.md), [Behavior Scanner](BEHAVIOR_SCANNER.md), and [Dependency Scanner](DEPENDENCY_SCANNER.md) specify prior phase semantics.

## Configuration and profiles

Hierarchy: safe built-in defaults → optional project `security-auditor.toml` → trusted operator CLI overrides. Hard limits and trust restrictions sit outside this hierarchy and cannot be raised by target data. A config found in the scanned target is untrusted: it may narrow coverage/limits but cannot enable network, AI, external executables, symlink traversal, or writes. `load_config` still parses only an explicitly operator-selected TOML file; no automatic target config loading exists. Future merge logic must preserve these rules.

`quick`: discovery, secrets, behavior, and dependency inventory; Python SAST and correlation are explicitly disabled. `standard`: all current deterministic scanners plus correlation/risk. `deep`: the same current deterministic implementation with optional AI only after `--ai`; deeper analysis rules and larger budgets are future work. A profile is a coverage intent, not permission to relax resource caps. `--offline` remains meaningful for all profiles.

Discovery defaults are configurable: version-control `.gitignore` is separate from security scan excludes. `respect_gitignore=false` by default because `.env` may contain security-relevant data. Explicit includes override ordinary exclusions but never root boundaries or hard caps. Phase 1 pattern precedence and its bounded root-level `.gitignore` subset are in [Discovery](DISCOVERY.md).

## Reporting and CLI

The packaged entry point is `security-auditor scan <path>`. The CLI accepts explicit profile, format, output, offline/AI, trusted config, fail threshold, and verbosity. It does not load target config implicitly. Output paths are relative to the operator's current directory, and writing requires an existing safe parent. See [CLI](CLI.md).

Scanner → normalized Finding → correlation/risk and optional AI annotations → canonical `ScanReport` → whitelist serializer → Console/JSON/SARIF/HTML. JSON is the versioned machine contract for CI, Codex, and future GUI. SARIF maps deterministic rules, locations, severity, and fingerprints. HTML is inert and uses no JavaScript or remote assets. Coverage, skipped files, unavailable provider data, and truncation remain explicit. Renderer failure does not rescan the target. See [Reporting](REPORTING.md).

## Test strategy

- Unit: immutable models, config validation, redaction/fingerprint/normalization once implemented, path and budget helpers.
- Integration: orchestrator with in-memory fake scanners and temporary target trees; assert partial failures and offline behavior.
- Security regression: no target execution, no writes, no outbound requests offline, redacted logs/reports, escaped HTML and terminal controls.
- Malicious fixtures (all fake data): symlink and junction loops, huge files, malformed Python/JS, clearly fake secret samples, unusual Unicode filenames, terminal escape, HTML injection, path traversal payload, binary masquerade, long lines and malformed manifests. Fixtures are read as data only; no real secret or executable fixture is run.

Tests should assert meaningful boundaries rather than mirror implementation. Windows reparse fixtures may require platform support or privileges and must be reported as skipped when unavailable.
