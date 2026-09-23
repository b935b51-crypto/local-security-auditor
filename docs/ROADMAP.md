# Roadmap

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| 0 | Architecture, threat model, foundation | contracts/docs, basic tests, local Git checkpoint; no scanner |
| 1 | Safe File Discovery & Classification | implemented; bounded traversal and classification, with Windows symlink/junction/UNC verification gaps recorded in [Discovery](DISCOVERY.md) |
| 2 | Secret Scanner | implemented: deterministic redacted findings, bounded reads, synthetic leakage regressions; verification limits in [Secret Scanner](SECRET_SCANNER.md) |
| 3 | SAST + Dangerous Behavior Scanner | implemented: Python AST intraprocedural taint and distinct neutral behavior signals; bounded parsing, rule provenance, no target execution; verification limits in [SAST](SAST.md) and [Behavior Scanner](BEHAVIOR_SCANNER.md) |
| 4 | Dependency / CVE Scanner | implemented: static Python/npm/Cargo/Go inventory, exact-version OSV adapter, offline cache and explicit no-data semantics; limits in [Dependency Scanner](DEPENDENCY_SCANNER.md) |
| 5 | Finding Correlation + Risk Engine | implemented: bounded graph, same-sink support, conservative context/candidates, explainable priority; limits in [Correlation](CORRELATION.md) and [Risk Engine](RISK_ENGINE.md) |
| 6 | Optional AI Security Reviewer | explicit opt-in, minimal redacted context, provider abstraction |
| 7 | Console / JSON / SARIF / HTML Reporting | versioned output, escaping, coverage/incomplete metadata |
| 8 | Remediation + Patch Proposal | validation and human approval before applying |
| 9 | GUI + Codex Integration | local workflow integration, no weakened boundaries |

Phase 5 is an implementation milestone with limits recorded in [Correlation](CORRELATION.md) and [Risk Engine](RISK_ENGINE.md). Phase 6 begins only on a new user request.

Phases 1–5 are complete as implementation milestones, with verification limits recorded in the linked phase documents and `PROJECT_STATUS.md`. Later phases may split by ecosystem if complexity warrants it, without changing the security boundary.
