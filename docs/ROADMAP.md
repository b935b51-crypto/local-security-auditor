# Roadmap

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| 0 | Architecture, threat model, foundation | contracts/docs, basic tests, local Git checkpoint; no scanner |
| 1 | Safe File Discovery & Classification | implemented; bounded traversal and classification, with Windows symlink/junction/UNC verification gaps recorded in [Discovery](DISCOVERY.md) |
| 2 | Secret Scanner | implemented: deterministic redacted findings, bounded reads, synthetic leakage regressions; verification limits in [Secret Scanner](SECRET_SCANNER.md) |
| 3 | SAST + Dangerous Behavior Scanner | implemented: Python AST intraprocedural taint and distinct neutral behavior signals; bounded parsing, rule provenance, no target execution; verification limits in [SAST](SAST.md) and [Behavior Scanner](BEHAVIOR_SCANNER.md) |
| 4 | Dependency / CVE Scanner | manifest/lock parsing, offline advisory strategy, optional online adapter |
| 5 | Finding Correlation + Risk Engine | stable deduplication, grouping, explainable risk |
| 6 | Optional AI Security Reviewer | explicit opt-in, minimal redacted context, provider abstraction |
| 7 | Console / JSON / SARIF / HTML Reporting | versioned output, escaping, coverage/incomplete metadata |
| 8 | Remediation + Patch Proposal | validation and human approval before applying |
| 9 | GUI + Codex Integration | local workflow integration, no weakened boundaries |

Phases 1–3 are complete as implementation milestones, with verification limits recorded in [Discovery](DISCOVERY.md), [Secret Scanner](SECRET_SCANNER.md), [SAST](SAST.md), [Behavior Scanner](BEHAVIOR_SCANNER.md), and `PROJECT_STATUS.md`. Phase 4 requires a new request. Later phases may split by ecosystem if complexity warrants it, without changing the security boundary.
