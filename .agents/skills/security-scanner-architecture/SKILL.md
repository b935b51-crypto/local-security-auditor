---
name: security-scanner-architecture
description: Apply when extending Local Security Auditor domain models, scanner plugins, normalization, adapters, or reports.
---

# Security scanner architecture

- Keep the domain and scanner contract independent of CLI, report formats, AI providers, and external tools.
- Scanner plugins consume bounded artifacts and return normalized `ScannerResult`; they do not mutate targets, print output, or create reports.
- Preserve severity and confidence separately; redact secret evidence at creation and again at every output boundary.
- Put external tools and online lookups behind optional adapters. Keep deterministic local scanning functional offline.
- Keep Phase 1 discovery as the only target filesystem entry point for future scanners: preserve root, reparse, identity, resource, and completeness checks; do not re-enumerate the target in a plugin.
- Secret scanners receive admitted `DiscoveryResult` artifacts, reopen only through bounded content reads, and construct raw-free candidates before `Finding`. Never propagate matched values into results, diagnostics, errors, logs, or reuse fingerprints.
- Python SAST and behavior plugins are separate. SAST requires a defensible source-to-sink path for injection claims; behavior describes observed APIs or patterns without asserting exploitability or intent. Keep both offline, source-free in evidence, and explicit about incomplete coverage.
- Dependency parsers consume only admitted bounded artifacts and never run target package managers, builds, or installers. Keep the provider behind an explicit offline/online boundary; query exact versions only, distinguish missing data from no match, and never infer application exploitability from a CVE.
- Correlation consumes normalized, redacted `ScannerResult` data only; it does not rerun scanners or mutate original findings. Use deterministic structural identities and bounded joins. Keep supporting findings separate from primary risk so severity is not double counted. Risk priority is neither exploit probability nor CVSS. Read [correlation](../../../docs/CORRELATION.md) and [risk engine](../../../docs/RISK_ENGINE.md) for the exact policy.
- AI review is advisory only: keep the original Finding immutable, isolate provider calls, treat target content and AI output as untrusted data, redact again at egress, and disable AI offline. Gemini requests have no tools and require trusted opt-in. Read [AI Reviewer](../../../docs/AI_REVIEWER.md) before changing this boundary.
- Reporters consume the canonical immutable `ScanReport` and never reopen targets. JSON is the versioned machine format; Console, SARIF, and static HTML derive from the same whitelist view. Sanitize again at output, display incomplete coverage prominently, and keep AI advisory separate from deterministic Findings. Read [Reporting](../../../docs/REPORTING.md) and [CLI](../../../docs/CLI.md).
- Remediation is proposal-only. Reopen only admitted bounded artifacts, apply edits in memory, reject forbidden paths/stale files, and rerun relevant static analysis. Never auto-apply, run target tests, or call a patch "safe" based on finding removal. AI patch generation requires a separate opt-in and the same deterministic validators. Every proposal requires human approval. Read [Remediation](../../../docs/REMEDIATION.md).
- The GUI consumes the canonical public ScanReport through its controller and never calls scanners or applies patches. The shared SecurityGate evaluator consumes JSON 1.1 without rescanning; incomplete coverage blocks by default, and AI remains advisory. Codex uses the JSON report and gate, not a visual guess. Read [GUI](../../../docs/GUI.md), [Security Gate](../../../docs/SECURITY_GATE.md), and [Codex integration](../../../docs/CODEX_INTEGRATION.md).

Read [architecture](../../../docs/ARCHITECTURE.md), [discovery](../../../docs/DISCOVERY.md), [secret scanner](../../../docs/SECRET_SCANNER.md), [SAST](../../../docs/SAST.md), [behavior scanner](../../../docs/BEHAVIOR_SCANNER.md), [dependency scanner](../../../docs/DEPENDENCY_SCANNER.md), [finding schema](../../../docs/FINDING_SCHEMA.md), and [scanner contract](../../../docs/SCANNER_CONTRACT.md) before changing those interfaces.
