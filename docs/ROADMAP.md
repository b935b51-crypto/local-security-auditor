# Roadmap

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| 0 | Architecture, threat model, foundation | contracts/docs, basic tests, local Git checkpoint; no scanner |
| 1 | Safe File Discovery & Classification | implemented; bounded traversal and classification, with Windows symlink/junction/UNC verification gaps recorded in [Discovery](DISCOVERY.md) |
| 2 | Secret Scanner | deterministic redacted findings and regression fixtures |
| 3 | SAST + Dangerous Behavior Scanner | bounded parsing, rule provenance, no target execution |
| 4 | Dependency / CVE Scanner | manifest/lock parsing, offline advisory strategy, optional online adapter |
| 5 | Finding Correlation + Risk Engine | stable deduplication, grouping, explainable risk |
| 6 | Optional AI Security Reviewer | explicit opt-in, minimal redacted context, provider abstraction |
| 7 | Console / JSON / SARIF / HTML Reporting | versioned output, escaping, coverage/incomplete metadata |
| 8 | Remediation + Patch Proposal | validation and human approval before applying |
| 9 | GUI + Codex Integration | local workflow integration, no weakened boundaries |

Phase 1 is complete as an implementation milestone, with its verification limits recorded in [Discovery](DISCOVERY.md) and `PROJECT_STATUS.md`. Phase 2 requires a new request. Later phases may split by ecosystem if complexity warrants it, without changing the security boundary.
