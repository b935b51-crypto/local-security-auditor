# Changelog

## 1.0.5 — 2026-09-26

### Changed

- Excluded TypeScript `*.tsbuildinfo` incremental-build metadata by default during Discovery, before downstream scanner admission. The existing structured scope record identifies it as `GENERATED` with reason `EXCLUDED_DEFAULT_GENERATED`.
- Kept ordinary `.ts`, `.tsx`, `.js`, and `.jsx` files eligible. Built-in file exclusions match file basenames, so a directory with a matching name does not hide its source children.

### Compatibility

- This is a Discovery scope maintenance patch, not a vulnerability fix. Trusted include, optional `.gitignore` handling, and `--force` retain their existing behavior. Secret Scanner limits, JSON schema 1.1, SARIF 2.1.0, and Gate policy 1.0 are unchanged.

## 1.0.4 — 2026-09-25

### Changed

- Collapsed exact semantic duplicate Findings, including nested `exec(compile(...))`, before public counts and remediation proposals. Distinct evidence and independent operations remain visible.
- Linked specific command execution and generic process execution at the same sink as primary and supporting signals. Machine Findings remain distinct; the Gate still evaluates primary deterministic issues.
- Added bounded, source-free context for test paths and statically proven stored-source lookups. These tags do not imply safety, trusted upstream input, or sandboxing.
- Made dependency intelligence provenance auditable through assessed/unassessed exact records, fresh/stale cache keys, age, TTL, and actual provider request counts. Zero matches are described only within assessed coverage.
- Distinguished disabled AI review from a requested review with no eligible subjects. Patch AI availability remains separate from finding review status.

### Compatibility

- This patch does not add detector scope or change JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, offline-first behavior, OSV/Gemini opt-in, or provider budgets.

## 1.0.3 — 2026-09-25

### Changed

- Improved JavaScript/TypeScript Secret Scanner precision: generic hardcoded-credential claims now require source-literal evidence instead of treating arbitrary assignment expressions as literal secrets.
- Recognized direct `process.env` references and narrowly proven `NodeJS.ProcessEnv` parameter wrappers, including simple `trim()` transforms, without suppressing hardcoded literal fallbacks.
- Stopped generic contextual-entropy findings from using runtime token calls and property names as literal credential material.
- Narrowed synthetic generic credential handling in test fixtures while continuing to scan tests and detect provider-specific secret shapes there.

### Compatibility

- This is a detection-precision patch, not a security vulnerability fix or full JS/TS SAST. JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, network opt-in, and provider budgets are unchanged.

## 1.0.2 — 2026-09-24

### Changed

- Refined generic Secret detection so proven, directly imported Python `secrets` token generators are not described as hardcoded credentials; literal credentials and unknown helpers remain eligible.
- Narrowed treatment of clearly synthetic generic test credentials without excluding test files or provider-specific secret patterns.
- Kept local CLI path-write findings visible as Low/CWE-22 with trust-boundary wording; HTTP-controlled and mixed-source paths retain Medium severity.

### Compatibility

- This is a detection-precision patch, not a security vulnerability fix. JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, OSV opt-in, and provider budgets are unchanged.

## 1.0.1 — 2026-09-24

### Changed

- Added `scan --osv` as an explicit online OSV dependency lookup choice. Scans remain offline by default; `--offline` and `--osv` are mutually exclusive, and Gemini remains a separate `--ai` choice.
- Clarified the offline missing-cache diagnostic so users can distinguish unavailable vulnerability data from a clean `NO_MATCH` result.

### Compatibility

- JSON schema 1.1, SARIF 2.1.0, Gate policy 1.0, scanner rules, and OSV request budgets are unchanged.
- No cache algorithm or path behavior changed: the reported 0/341 cache-hit discrepancy was not reproducible in the current source or installed environment.

## 1.0.0 — 2026-09-24

### Added

- Offline-first static scanning of admitted project files: Secrets, Python SAST, dangerous behavior signals, and supported dependency manifests/lockfiles.
- Optional exact-version OSV advisory lookup and Gemini advisory review, each requiring a separate trusted online choice.
- Deterministic finding correlation, explainable risk priority, Windows Tk GUI, and a shared CLI/GUI Security Gate.
- Console, JSON 1.1, SARIF 2.1.0, and Traditional Chinese (`zh-TW`) HTML reports.
- Human-reviewed remediation guidance and bounded, non-applied patch proposals.

### Changed

- Default project scope prunes generated caches and vendored trees while retaining tests, manifests, lockfiles, and `.env` files for eligible analysis.
- Secret scanning supports admitted large UTF-8 text through bounded chunks and reports incomplete context honestly.
- First-party editable project roots are distinguished from unresolved third-party dependencies.

### Security

- Scanned target code, tests, modules, and dependency installers are never run automatically; the scanner does not auto-modify targets.
- Default reparse traversal is denied. File, AST, Secret, output, and external-provider work has explicit limits.
- OSV requests have scan-global batch/detail/total caps, advisory deduplication, and partial coverage when budgets or advisory limits are reached.
- Incomplete coverage blocks the default Gate; AI advice and remediation proposals cannot override deterministic Findings.

### Validation

- Python 3.12.11 full offline regression, clean wheel/sdist installs, installed-wheel reporting/Gate/GUI/optional-extra smoke, live Gemini and bounded live OSV history, and offline real-world Mosaic/Trading Platform scans are recorded in [release notes](RELEASE_NOTES.md).

### Known limitations

- Deep SAST is Python-focused; dependency ecosystems and formats are finite. Novel secrets may evade heuristic redaction.
- Discovery's default admission ceiling is 4 MiB; incomplete applicable coverage is reported rather than hidden.
- Real symlink and UNC paths, GUI high-DPI and assistive technology remain incompletely validated on this host.
- No standalone executable, installer, automatic patch application, or remediation runtime tests are included in 1.0.0.
