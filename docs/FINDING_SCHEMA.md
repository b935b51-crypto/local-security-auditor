# Finding and normalization contract

The Python Phase 0 representation is `security_auditor.core.models.Finding`. A future stable JSON schema will carry `schema_version`; Phase 0 has no reporter. Serialized field names remain snake_case. All paths are root-relative POSIX-style paths, with no absolute host path or `..` segment. Positions are one-based; `null` means unavailable. Timestamps use UTC RFC 3339 in serialized output.

| Group | Fields | Contract |
| --- | --- | --- |
| Identity | `id`, `rule_id`, `scanner_id`, `category`, `title`, `description` | `id` is unique within a scan; rule IDs are namespaced and stable |
| Assessment | `severity`, `confidence` | independent enums, never collapsed to a score |
| Location | `path`, start/end line and column | end is exclusive when known; absent fields are null |
| Evidence | `kind`, `redacted_snippet`, `structured` | already redacted before persistence; no raw secret |
| Classification | `cwe`, `cve`, `cvss`, optional `owasp` | reference IDs/score with source context; no guessed mapping |
| Analysis | `source`, `sink`, `attack_scenario`, `rationale` | source/sink are locations or safe descriptors, not source dump |
| Remediation | `recommendation`, `references`, optional patch proposal ID | advice is separate from any write permission |
| Metadata | `tags`, `fingerprint`, `created_at`, `tool_version`, `rule` | version and provenance enable migration/auditing |
| Supply chain | optional `dependency`, `vulnerability` | package coordinates and advisory provenance |

`Severity` asks: **if true, how serious is the impact?** CRITICAL means likely catastrophic compromise or broad credential/production exposure; HIGH means major compromise; MEDIUM means meaningful but scoped impact; LOW means limited impact or difficult exploitation; INFO is security-relevant context without demonstrated exploit. `Confidence` asks: **how certain is this a real issue?** HIGH means direct static evidence with few assumptions; MEDIUM means evidence plus plausible assumptions; LOW means heuristic indication requiring review. A HIGH severity/LOW confidence finding stays exactly that; risk ranking may consider both but cannot overwrite either.

Phase 3 SAST and behavior plugins populate this same model. Their evidence snippet is a fixed redaction marker, structured evidence contains safe labels/categories/line numbers, and source/sink are structural descriptors. Behavior findings use category `behavior`; detection of an operation does not itself establish a vulnerability or intent. Phase 3 fingerprints use a versioned SHA-256 tuple of rule, sanitized relative path, line, column, and structural anchor. These location identities change when a finding moves; future normalization may introduce more stable AST anchors and reviewed collision handling.

Phase 4 dependency findings use category `dependency` and rule `DEPENDENCY.KNOWN_VULNERABILITY`. The public fingerprint is a length-prefixed SHA-256 over rule ID, ecosystem, normalized package name, exact version, and primary advisory ID; duplicate manifest/lock locations for the same tuple produce one finding with `DependencyArtifact.source_paths`. `VulnerabilityReference` carries bounded aliases, summary, fixed versions, timestamps, CVSS vector, and severity provenance. The evidence contains normalized coordinates, match status, provider, and stale-cache flag, never a raw manifest section or provider JSON. A matching package version is not evidence of application reachability or exploitability. [Dependency Scanner](DEPENDENCY_SCANNER.md) defines the precise policy.

## Stable identity and deduplication

The Phase 2 Secret Scanner implements a narrower location anchor: rule ID, redacted root-relative path, line/column, family, and safe structural label, length-prefixed and SHA-256 hashed. It never hashes the secret value, including when it appears in a filename. A value change at the same location preserves identity, while moving the finding changes it. Cross-file secret reuse correlation remains future work. The broader normalized-line/AST anchor below is a future normalization contract, not the implemented Phase 2 secret identity. [Secret Scanner](SECRET_SCANNER.md) documents overlap precedence and limits.

Fingerprint v1 is SHA-256 over a canonical UTF-8 tuple: fingerprint schema version, namespaced rule ID, normalized root-relative path, stable finding anchor, and a non-secret structural discriminator (for dependencies: ecosystem, normalized package name, version/advisory ID). Use length-prefixed fields, not ambiguous string concatenation. The anchor is a token/AST construct or bounded normalized line context with secret matches replaced by a fixed marker; avoid absolute paths, timestamps, line numbers alone, raw secret bytes, and variable prose. Scanner version changes do not automatically churn identity. Document future migration when the algorithm changes. Per-scan `id` may derive from fingerprint plus collision suffix.

Deduplicate exact fingerprint matches, preserving all scanner/rule provenance and the highest supported confidence only when corroboration is explicit. Different rules at one line remain distinct unless a reviewed equivalence map says otherwise. Correlation may group findings without deleting evidence. Collision or missing anchor falls back to a distinct safe identity and diagnostic rather than silently merging.

Suppressions are explicit reviewed records keyed by fingerprint or namespaced rule plus bounded path, with owner, reason, expiry, and source. They are applied after normalization and counted in summaries; they do not erase findings from internal audit evidence. Target-controlled inline comments or target config cannot suppress findings by default. Expired and unknown-rule suppressions surface as diagnostics. A suppression never changes scanner execution or disables safety limits.

Phase 5 consumes these immutable findings and emits separate graph edges, PRIMARY/SUPPORTING groups, attack-path candidates, and risk assessments. It never rewrites a Finding's original severity, confidence, or CVSS. It reports fingerprint collisions and malformed inputs instead of treating them as safe equivalence. [Correlation](CORRELATION.md) and [Risk Engine](RISK_ENGINE.md) define the annotation contract.

Phase 6 `AIReviewResult` is a separate immutable annotation keyed by subject ID and redacted review-input fingerprint. It has its own verdict and confidence; no AI field is added to or written back into `Finding`. See [AI Reviewer](AI_REVIEWER.md).

## Redaction and storage

Secret findings include type, safe location, and masked evidence such as `[REDACTED API KEY]`. Exact values, reversible encodings, or public hashes of secret values are forbidden in `Finding`, logs, JSON, SARIF, HTML, console, suppression keys, and AI context. The normalization gate rechecks all text fields, including descriptions and diagnostics, before storage/reporting. Because a generic schema cannot prove arbitrary text safe, scanners must construct evidence through future redaction helpers and output gates must fail closed on unsafe content. Do not persist raw scanner output.
