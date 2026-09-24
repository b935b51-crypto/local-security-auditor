# Security Gate policy 1.0

`security-auditor gate REPORT.json --format json` reads a previously produced canonical `ScanReport` JSON **without rescanning a target**. The same `evaluate_gate` function supplies the GUI Gate view. Built-in `SecurityGatePolicy` 1.0 is immutable for the CLI and GUI in this phase; there is no target-local policy file or manual override. A future trusted policy input must remain separate from scanned project data. The report itself is not cryptographically authenticated: operators must protect its provenance.

The gate accepts schema version `1.1` only. It reads at most 16 MiB from a regular, non-reparse file, rejects duplicate JSON keys and invalid UTF-8, and checks required decision and GUI fields, types, counts, roles, paths, item caps, and report truncation consistency. Unknown major and later minor versions fail closed until compatibility is reviewed. A malformed report returns a fixed error code without printing its contents. Gate output uses fixed reasons and finding fingerprints; it does not echo paths, source, AI text, or secrets.

An additive `discovery.scope` summary describes intentional default/user exclusions. It is not a gate override: the decision still uses validated coverage and findings. Default cache pruning may leave coverage `COMPLETE` within that declared scope, while any genuine `PARTIAL` or `ABORTED` scanner status still blocks under policy 1.0.

Policy 1.0 recognizes the built-in scanner/category pairs and 64-character SHA-256 finding fingerprints. An unknown future scanner requires an explicit policy review rather than silently inheriting a permissive rule.

| Status | Default meaning | Exit code |
| --- | --- | ---: |
| PASS | Deterministic coverage COMPLETE, no blocking primary finding, no other policy warning | 0 |
| WARN | Nonblocking primary finding, behavior signal, dependency `NO_DATA`, diagnostic, or a trusted future policy allowing PARTIAL | 10 |
| BLOCK | Qualifying HIGH/CRITICAL primary deterministic finding, high risk priority, PARTIAL/ABORTED/FAILED coverage, report truncation, or a configured blocking dependency no-data condition | 20 |

Usage/config errors use 2; invalid or unsafe reports use 3. The gate command's 10/20 are distinct from the scan command's optional `--fail-on` exit 10. A zero-finding result is never a claim of safety.

Primary findings are selected using the report's role/group data. Supporting/contextual/duplicate signals do not add blockers. INFO/LOW behavior signals warn by default; they cannot block solely from severity/priority. A HIGH/CRITICAL secret blocks. A high-confidence HIGH/CRITICAL SAST issue blocks; a lower-confidence HIGH SAST issue is not automatically a severity blocker, although a separate high risk priority can block. An exact-version HIGH/CRITICAL dependency advisory blocks by severity, while reachability remains unknown. `NO_DATA`, `OFFLINE_NO_CACHE`, and `QUERY_FAILED` are not `NO_MATCH`: summary no-data warns by default, and PARTIAL coverage blocks by default. Safety-critical scanner failures are represented by incomplete coverage. No automatic suppressions are introduced here.

AI verdicts, including `LIKELY_FALSE_POSITIVE`, and patch proposals are advisory. They are validated as report data for safe viewing but never promote or dismiss a deterministic gate decision. The gate does not auto-apply a proposal, run target code, change config, or access OSV/Gemini.

JSON result fields: `status`, `policy_version`, `blocking_findings`, `warning_findings`, `coverage_status`, `reasons`, `diagnostics`, `report_schema_version`. `blocking_findings` and `warning_findings` contain public fingerprints. Reasons are fixed codes such as `COVERAGE_PARTIAL`, `BLOCKING_PRIMARY_FINDINGS`, `DEPENDENCY_NO_DATA`, and `REPORT_TRUNCATED`.
