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

Read [architecture](../../../docs/ARCHITECTURE.md), [discovery](../../../docs/DISCOVERY.md), [finding schema](../../../docs/FINDING_SCHEMA.md), and [scanner contract](../../../docs/SCANNER_CONTRACT.md) before changing those interfaces.
