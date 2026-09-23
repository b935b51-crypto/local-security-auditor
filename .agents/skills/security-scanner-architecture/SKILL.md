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

Read [architecture](../../../docs/ARCHITECTURE.md), [discovery](../../../docs/DISCOVERY.md), [secret scanner](../../../docs/SECRET_SCANNER.md), [finding schema](../../../docs/FINDING_SCHEMA.md), and [scanner contract](../../../docs/SCANNER_CONTRACT.md) before changing those interfaces.
