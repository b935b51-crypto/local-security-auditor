# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 4 — Dependency / CVE Scanner
- Status: implementation complete; verified locally on Python 3.14.7 with the limits below

## Completed

- Phase 0 architecture, Phase 1 bounded discovery, Phase 2 native Secret Scanner, and Phase 3 separate Python SAST/Behavior Scanner remain in place.
- `DependencyScanner` implements the synchronous scanner contract and prefers `scan_discovery` or `scan_with_inventory` to retain discovery completeness. It reads only Phase 1 admitted artifacts through bounded identity-checked content reads; requirements includes must be admitted root-contained text files.
- Python requirements/PEP 621/limited Poetry/Pipfile and uv/Poetry/Pipfile locks, npm `package.json` and package-lock v1–v3, Cargo manifests/locks, and Go `go.mod` are statically parsed. Other classified ecosystems and yarn/pnpm/go.sum are explicitly unsupported and make coverage partial. No target package manager or build backend runs.
- Inventory models exact/constraint/unresolved/local/VCS/URL versions, direct/transitive/unknown, groups, registry source, lock precedence, multiple versions, source locations, and deterministic reconciliation. Only validated exact registry coordinates are eligible for advisory lookup.
- An optional `VulnerabilityProvider` abstraction has an OSV batch-ID plus detail adapter. It rejects malformed/paginated/oversize responses, excludes withdrawn advisories, normalizes severity and fixed versions, and makes no reachability or exploitability claim. Online lookup requires `ScanSession.offline=False`; no live OSV call was made during validation.
- A bounded tool-local JSON cache stores normalized advisory results outside the target, supports TTL and offline stale results, and distinguishes `OFFLINE_NO_CACHE`, `NO_MATCH`, and provider failure. Dependency findings are deduplicated by ecosystem/package/version/advisory and carry safe evidence and aggregated source paths.
- [Dependency Scanner](docs/DEPENDENCY_SCANNER.md), architecture/security/schema/scanner/roadmap docs, example config, README/AGENTS, and the architecture project skill reflect Phase 4. No third-party runtime dependency, scan CLI, reporter, AI integration, automatic remediation, or Phase 5 correlation was added.

## Decisions and security boundaries

- Target code and manifests remain hostile data. Never execute/import target code, install target dependencies, run package managers, follow reparse points, or write into the target. Provider endpoint is a tool-owned HTTPS constant; target config cannot enable network or relax hard caps.
- OSV exact-version query is authoritative for affected status. No generic ecosystem range engine, installed-environment inference, or constraint-to-version guess exists. A vulnerable dependency Finding does not establish use of vulnerable code or application exploitability.
- Offline is default. Offline cache miss and unsupported/partial coverage cannot appear as clean `NO_MATCH`. Cache staleness is explicit. Provider/cache/parse diagnostics contain fixed messages, no raw manifest or provider payload.
- Python baseline remains `>=3.12,<3.13` with uv and stdlib only. Python 3.12 is absent locally; no interpreter, system package, or other project environment was modified.

## Verification

- Ran `$env:PYTHONDONTWRITEBYTECODE='1'; $env:PYTHONPATH='src'; py -3.14 -m unittest discover -s tests -q`: 72 tests, 71 passed, 1 skipped (real Windows symlink creation unavailable). Includes Phase 4 parser, lock precedence, fake OSV, offline/stale/corrupt cache, include boundary/loop, unresolved-version negative, withdrawn advisory, provider failure/schema/byte budget, secret-shaped coordinates and paths, no package-manager execution, config, docs links, and earlier phases.
- Loaded `security-auditor.example.toml` and imported `DependencyScanner` on Python 3.14.7. `git diff --check` passed for tracked changes; staged diff check is performed at checkpoint. No lint/formatter is configured.
- Python 3.12 baseline **not verified**: `py -3.12 --version` reports no suitable runtime. Live OSV behavior, real junction/UNC/long-path behavior, race-free filesystem containment, and hard parser CPU/memory isolation remain unverified.

## Git and next action

- Branch `main`; Phase 4 local checkpoint is in Git history after the final commit. Inspect `git log -1` for its exact ID. No remote push requested.
- Phase 5 — Finding Correlation + Risk Engine is next only on a new user request. Do not start it in Phase 4.
