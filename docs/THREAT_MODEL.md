# Threat model — untrusted repository scanning

## Scope and assets

Adversary controls target directory contents, names, links/reparse points, manifests, ignore/config files, Git metadata, and apparent instructions. They may change files during a scan. They do not control trusted installed auditor code or the operator's explicit options. Assets: host filesystem, processes, credentials, network/privacy, report integrity, scanner availability, and user trust. Baseline is static and offline. Risk ratings are design priorities, not claims of implemented mitigation; Phase 1+ must test them.

| Threat | Attack vector | Impact | Planned mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Unbounded tree | millions of files, extreme depth, huge files/lines | CPU/RAM/disk exhaustion | count/depth/size/total-byte/time budgets; bounded reads; explicit incomplete result | adversary can still consume allowed budget |
| Link escape/loop | symlink, NTFS junction, reparse/mount point, UNC pivot | infinite traversal, outside-root access | default no-follow, file identity visited set, root/volume checks at open | TOCTOU races and unusual filesystems remain |
| Path confusion | `..`, ADS, reserved names, long/device/UNC paths, case/Unicode collisions | wrong file/report, boundary escape | native identity, strict root-relative output, reject ambiguity, no ADS baseline | normalization and filesystem edge cases need Windows tests |
| Binary/parse bomb | binary masquerade, compressed bomb, malformed source, enormous AST/token stream | crash/resource exhaustion | magic/classification, no archive expansion, parser budgets and exception isolation | trusted parser bugs remain possible |
| Malicious manifest/config | lifecycle scripts, poisoned project config, crafted ignore rules | code execution or disabled coverage | parse as data; target config cannot grant authority; never install/build | parser bugs, incomplete ecosystem coverage |
| Prompt/rule injection | README/comments pretending to instruct agent or AI | unsafe operation or misleading review | treat as data; deterministic first; AI minimal context and instruction isolation | AI may still produce bad advice |
| Secret leakage | raw match in logs, errors, JSON/HTML, AI request | credential compromise | redact at creation and output; no source dumps; no AI by default | heuristic redaction may miss novel credential formats |
| Unsafe subprocess | shell interpolation, target binary, target rule pack | host code execution | no subprocess in core; vetted binary/argv, no shell, timeout, output cap, isolated adapter | third-party binary vulnerability |
| Report injection | HTML/script payload, terminal escapes, control chars | browser or terminal compromise, misleading report | inert HTML/CSP, escaping, terminal sanitization, safe JSON | consumer bugs or unsafe downstream rendering |
| Output overwrite | report path inside target, traversal, temp collision | target mutation/data loss | refuse target-contained output by default, safe temp placement and atomic writes | operator explicitly choosing unsafe destination requires policy |
| Supply-chain compromise | malicious auditor dependency, typosquatting | scanner takeover | stdlib-only Phase 0, pin/review future dependencies, integrity checks | interpreter/OS compromise outside model |
| Network exfiltration | advisory/AI adapter uploads more than needed | repository/secret exposure | offline default, explicit opt-in, minimal data, redaction, provider isolation | external provider retention and metadata leakage |
| Silent partial scan | parser/advisory failure shown as clean | false assurance | per-scanner statuses, skipped counts, incomplete report flag | user may overlook warning |

## Security validation gates

Phase 1 must test symlink/junction loops, root escape, race-sensitive traversal decisions, long paths, weird Unicode names, huge files, and budgets without executing fixture content. Later phases add redaction, parser, adapter, HTML, and terminal regression tests. All fixture keys are clearly fake. No dynamic analysis is authorized by this threat model.
