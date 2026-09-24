# v1 Finalization Assessment — 2026-09-24

**Decision: READY FOR 1.0.0 FINALIZATION.** This is an assessment of the current `0.9.0` RC at Git checkpoint `ed8d21d`, not a 1.0.0 release, version change, publication, or security certification. No production behavior or release artifact was changed in this assessment. The evidence below is bounded by the documented product scope and host-specific validation.

## v1 scope and phase review

The [roadmap](ROADMAP.md) defines v1 as an offline-first static auditor of untrusted repositories: bounded discovery, Secret scanning, Python SAST and distinct behavior signals, supported-manifest dependency inventory with optional exact-version OSV, correlation/risk, optional advisory Gemini review, CLI and Console/JSON/SARIF/HTML reports, proposal-only remediation, Windows Tk GUI, and the shared deterministic Security Gate. The core does not require third-party runtime packages. Phase 10 controlled patch application, target execution/testing, every-language deep SAST, every dependency ecosystem, standalone EXE/installer, and a cloud service are outside this defined scope.

| Phase | Assessment | Implementation and verification evidence | Explicit limit |
| --- | --- | --- | --- |
| 0 — Foundation | COMPLETE | Core models/contracts, [architecture](ARCHITECTURE.md), [threat model](THREAT_MODEL.md), [security boundaries](SECURITY_BOUNDARIES.md), and [Finding schema](FINDING_SCHEMA.md) are present. | Contracts describe a bounded static tool, not a sandbox for arbitrary target execution. |
| 1 — Discovery | COMPLETE WITH KNOWN LIMITATION | `discovery/service.py` and `content.py` implement root/reparse checks, scope pruning, identity and byte/count/depth/time budgets; real junction, loop, outside-root, and long-path tests passed. | Real symlink and UNC were not validated on this host; path-based race windows remain. |
| 2 — Secrets | COMPLETE WITH KNOWN LIMITATION | `scanners/secrets/` has redacted Findings, relative diagnostics, budgets, and Hardening #8 bounded large-text mode; source tests and installed-wheel boundary/fingerprint smoke passed. | Redaction is heuristic; applicable files above the 4 MiB default admission ceiling remain incomplete. |
| 3 — SAST and Behavior | COMPLETE WITH KNOWN LIMITATION | Separate Python AST SAST and behavior scanners have node/depth/file budgets and per-artifact isolation; Mosaic re-scan covered both Python artifacts. | Deep taint analysis is Python-focused; one parser call cannot be preempted by the elapsed-time check. |
| 4 — Dependencies | COMPLETE WITH KNOWN LIMITATION | Static parsers, first-party root identity, exact-version OSV, normalized cache, global request caps, advisory deduplication and overflow PARTIAL semantics were tested; bounded live OSV and offline replay succeeded. | Ecosystem/dialect support and external advisory quality are finite; a match does not establish exploitability. |
| 5 — Correlation/risk | COMPLETE WITH KNOWN LIMITATION | `correlation/` uses normalized redacted Findings and keeps original severity/confidence; grouping, bounded graph, and risk-priority tests exist. | Attack paths and relevance are conservative candidates, not proof of reachability. |
| 6 — AI reviewer | COMPLETE WITH KNOWN LIMITATION | `ai/` is an optional, separately granted adapter; synthetic Gemini live schema validation succeeded historically and the fresh wheel passed missing-key/offline extra smoke. | Model advice and heuristic egress redaction remain fallible; AI never overrides deterministic results. |
| 7 — CLI/reporting | COMPLETE WITH KNOWN LIMITATION | `cli/` and `reporting/` emit JSON 1.1, SARIF 2.1.0, static zh-TW HTML and Console with bounded output; clean wheel and sdist installs passed. | SARIF is a tested subset; the full official schema was not used as a local validator. |
| 8 — Remediation proposals | COMPLETE WITH KNOWN LIMITATION | `remediation/` supports guidance and bounded in-memory proposals with static validation and required human approval. | Runtime tests are always `NOT_RUN`; no patch is applied. |
| 9 — GUI/Gate/Codex | COMPLETE WITH KNOWN LIMITATION | Tk GUI, report reader, shared Gate 1.0, and Codex workflow are implemented and tested; clean-wheel GUI main window launched. | High-DPI, screen-reader behavior, and all dialogs are not fully validated. |

## Security boundaries and coverage

`PASS` means the reviewed implementation, tests, and validation support the invariant within declared scope. A known limitation remains explicit instead of being converted into a clean result.

| Invariant | Assessment | Evidence or boundary |
| --- | --- | --- |
| Target code is not executed, imported, tested, or installed | PASS | Passive discovery/static parsers only; real-world scans and target Git checks recorded no execution or dependency installation. |
| Scans do not automatically modify target files | PASS | Proposal-only remediation; CLI output writing requires an explicit operator destination. |
| Reparse traversal is denied by default | PASS | No-follow implementation and real junction/loop/outside-root validation. |
| Root escape is prevented | KNOWN LIMITATION | Containment, no-follow, identity and reopen checks are present; unusual UNC aliases and filesystem races remain unverified. |
| File reads, AST, Secrets, and OSV requests are bounded | KNOWN LIMITATION | Enforced count/byte/node/depth/request limits and honest incomplete states; one blocking filesystem/parser/provider operation is not forcibly preempted. |
| Secret values are redacted before public Findings | KNOWN LIMITATION | Raw-free candidate-to-Finding path and output regressions; novel credential shapes may evade heuristic redaction. |
| Raw OSV payload is not persisted | PASS | Cache accepts normalized complete lookups only; incomplete queries are not cached as complete. |
| AI cannot override deterministic Findings | PASS | Separate advisory annotations, explicit opt-in, offline disablement, no Gemini tools. |
| Incomplete coverage cannot default to Gate PASS | PASS | Gate policy 1.0 blocks PARTIAL/ABORTED/FAILED and report truncation by default. |
| `NO_DATA` differs from `NO_MATCH` | PASS | Explicit lookup statuses, offline no-cache and provider-failure tests; zero matches cannot be inferred from unavailable data. |
| Known vulnerable dependency does not imply application exploitability | PASS | Finding and provider docs retain affected version, confidence and reachability limits separately. |

`COMPLETE` means completed deterministic analysis **within the declared scan scope**, never proof of safety. Intentional exclusions are disclosed and do not create false PARTIAL; non-applicable artifacts are distinguished from failed applicable scans. Secret context loss, decode/limit failures, OSV advisory overflow, budget exhaustion, no data, and report truncation remain incomplete. `PARTIAL` and `ABORTED` block by default; `FAILED` denotes a scan that could not complete and also blocks. A fully analyzed large-text file can be COMPLETE. Gate may still return WARN or BLOCK for deterministic Findings when coverage is COMPLETE.

## Reporting, API and distribution

Console escapes controls and surfaces coverage; JSON is the versioned `1.1` machine contract; SARIF is `2.1.0` with deterministic results; HTML is inert `zh-TW` with escaping, restrictive CSP, no JavaScript and no remote assets. Reporters use a sanitized public whitelist and never reopen target files. Findings and diagnostics are capped; truncation is visible. Explicit output writes are validated and atomic. The CLI documents scan exit codes `0/2/3/4/10` and Gate exit codes `0/10/20/2/3`; Gate accepts JSON 1.1 only. Package identity is `local-security-auditor`, with Python `>=3.12,<3.13`, no core runtime dependency, and an optional `gemini` extra.

The ignored, locally retained `0.9.0` artifacts were reviewed without rebuilding: wheel `local_security_auditor-0.9.0-py3-none-any.whl` (SHA-256 `a1cafb552e455288bcf8e67eb42f1120fd01d6d10375c70b084b833bc2884a5e`) and sdist `local_security_auditor-0.9.0.tar.gz` (SHA-256 `181f1173eb17f4289f5305fa705fe190c708a82d7fcf9306f23335482c17598e`). [Release Candidate](RELEASE_CANDIDATE.md) records archive/privacy inspection, fresh Python 3.12 core/Gemini-extra/sdist installs, CLI/Gate/GUI smoke, Hardening #4–#8 installed behavior, and source-versus-wheel stable-field agreement. This assessment rechecked that those archive files and hashes still exist; it did not rerun the installation matrix.

## Real-world and test evidence

| Target | Latest evidenced result | Interpretation |
| --- | --- | --- |
| Mosaic | Offline discovery, Secrets, SAST, Behavior and overall COMPLETE; zero Findings. The existing final JSON report evaluated through Gate 1.0 during this assessment returned PASS. | “No findings detected in the analyzed coverage,” not “Mosaic is safe.” Earlier AST-limit/applicability and HTML wording issues were corrected. |
| Personal Automated Equity Trading Platform | Fresh installed-wheel `--offline --no-ai` scan: Discovery, Secrets, SAST, Behavior, Dependencies, Correlation and Overall COMPLETE; Gate WARN; 17 Findings (0 critical, 0 high, 3 medium, 0 low, 14 info). | Its 2,169,199-byte log used bounded large-text mode with nine long lines, no Secret diagnostic or log Secret Finding. Dependency replay had 341 cache hits and zero OSV requests. Target Git status and log hash were unchanged. WARN calls for review; it is not a safety certificate. |

The latest full **source** regression was run during Artifact Refresh #2, not repeated in this assessment: Python 3.12.11, `uv run --offline --no-sync python -m unittest discover -s tests -q`, **193 total, 187 passed, 0 failed, 6 skipped**. Four skips are explicit live gates: Gemini, OSV single-package, OSV budget pilot, and OSV diagnosis. Those online paths have separate historical bounded validation. Two skips are real symlink creation cases in discovery and Windows filesystem tests, limited by host privilege. No unexpected skip was found in the test declarations; actual skip classification here relies on those declarations and the recorded suite result, not a new verbose suite run. Junction/loop/outside-root/Unicode long-path tests passed on this host.

## Limitations, documentation and blocker decision

| Limitation | Classification for defined v1 | Reason |
| --- | --- | --- |
| Real symlink and UNC not validated on this host | ACCEPTABLE KNOWN LIMITATION | Default no-follow and root checks are implemented; real junction and path cases passed, while host-specific gaps remain documented. |
| High-DPI and assistive-technology checks incomplete | ACCEPTABLE KNOWN LIMITATION | GUI startup works from the wheel; no claim of full accessibility certification is made. |
| Standalone EXE and installer absent | FUTURE FEATURE | The documented distribution is a Python 3.12 wheel/sdist. |
| Heuristic Secret redaction | ACCEPTABLE KNOWN LIMITATION | Explicitly disclosed; prevents a guarantee for novel credential forms. |
| 4 MiB default Discovery admission ceiling and larger applicable files | ACCEPTABLE KNOWN LIMITATION | The limit is enforced and incomplete coverage is reported, not silently called COMPLETE. |
| TypeScript/non-Python deep SAST and additional dependency dialects | FUTURE FEATURE | The roadmap promises Python-focused SAST and specified static dependency formats. Unsupported applicable formats remain visible. |
| Phase 10 controlled patch application | FUTURE FEATURE | The v1 contract is proposal-only with human approval. |
| Remediation runtime tests `NOT_RUN` | ACCEPTABLE KNOWN LIMITATION | Static proposal validation never claims functional correctness. |

The active README, roadmap, CLI, Gate, reporting and release-status claims agree on `0.9.0` RC, Python 3.12, schema 1.1, SARIF 2.1.0, advisory AI, and proposal-only remediation. Searches found no active `0.0.0`, “Python 3.12 unverified,” “OSV unverified,” or claim that a zero-finding scan proves security. Some dated sections retain statements about stale artifacts or earlier PARTIAL scans as historical evidence; the current-status sections supersede them. One out-of-date “current recommendation” at the end of [Release Candidate](RELEASE_CANDIDATE.md) was corrected in this assessment. No known issue meets the stated blocker test: broken documented v1 behavior, known unsafe target mutation/escape, unusable distribution, or misleading coverage/reporting. **Release blockers: none identified in the reviewed evidence.** This does not prove absence of unknown defects.

| Release quality | Assessment | Basis |
| --- | --- | --- |
| Installability | PASS | Fresh core, extra, and sdist install evidence. |
| Determinism | PASS | Offline core, stable-field source/wheel comparison. |
| Safe defaults | PASS | No target execution, reparse traversal, AI or network by default. |
| Bounded resources | CONDITIONAL | Limits and partial states are implemented; individual blocking host/parser operations have best-effort deadlines. |
| Coverage honesty | PASS | Applicability, intentional scope and incomplete provider/large-text cases are explicit. |
| Reporting/API | PASS | Versioned JSON/Gate, SARIF subset, inert HTML, fixed exit codes and output caps. |
| External provider safety | PASS | Explicit grants, fixed HTTPS OSV, no Gemini tools, global request budgets and complete-only cache. |
| Real-world validation | PASS | Mosaic and Trading Platform passive scans plus bounded live OSV/Gemini history. |

The next separately authorized task is **v1 Finalization**: decide and apply `0.9.0 → 1.0.0`, rerun the full Python 3.12 regression, build final artifacts, calculate SHA-256, write release notes, and prepare a tag. No version bump, build, tag, push, publication, live service call, target re-scan or Phase 10 work was performed here.
