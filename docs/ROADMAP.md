# Roadmap

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| 0 | Architecture, threat model, foundation | contracts/docs, basic tests, local Git checkpoint; no scanner |
| 1 | Safe File Discovery & Classification | implemented; bounded traversal and classification, with Windows symlink/junction/UNC verification gaps recorded in [Discovery](DISCOVERY.md) |
| 2 | Secret Scanner | implemented: deterministic redacted findings, bounded reads, synthetic leakage regressions; verification limits in [Secret Scanner](SECRET_SCANNER.md) |
| 3 | SAST + Dangerous Behavior Scanner | implemented: Python AST intraprocedural taint and distinct neutral behavior signals; bounded parsing, rule provenance, no target execution; verification limits in [SAST](SAST.md) and [Behavior Scanner](BEHAVIOR_SCANNER.md) |
| 4 | Dependency / CVE Scanner | implemented: static Python/npm/Cargo/Go inventory, exact-version OSV adapter, offline cache and explicit no-data semantics; limits in [Dependency Scanner](DEPENDENCY_SCANNER.md) |
| 5 | Finding Correlation + Risk Engine | implemented: bounded graph, same-sink support, conservative context/candidates, explainable priority; limits in [Correlation](CORRELATION.md) and [Risk Engine](RISK_ENGINE.md) |
| 6 | Optional AI Security Reviewer | implemented library layer: explicit opt-in, redacted bounded context, optional Gemini 3.8 Flash adapter, separate annotations; limits in [AI Reviewer](AI_REVIEWER.md) |
| 7 | Console / JSON / SARIF / HTML Reporting | versioned output, escaping, coverage/incomplete metadata |
| 8 | Remediation + Patch Proposal | validation and human approval before applying |
| 9 | GUI + Codex Integration | local workflow integration, no weakened boundaries |

Phase 6 is an implementation milestone with limits recorded in [AI Reviewer](AI_REVIEWER.md). Phase 7 is the next planned phase; it has not started.

Phases 1–6 are complete as implementation milestones, with verification limits recorded in the linked phase documents and `PROJECT_STATUS.md`. Later phases may split by ecosystem if complexity warrants it, without changing the security boundary.
