# Changelog

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
