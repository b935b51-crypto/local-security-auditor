# Current Handoff

## Status

No active handoff. Phase 4 Dependency / CVE Scanner is implemented, locally tested, and checkpointed in Git; verify exact state with `git status` and `git log -1`.

## Verified state

- `DependencyScanner` statically consumes admitted artifacts, produces normalized inventory and scanner findings, and never invokes target code, package managers, or build backends.
- Python/npm/Cargo/Go v1 formats are supported as documented in [Dependency Scanner](../docs/DEPENDENCY_SCANNER.md). OSV is an optional exact-version online adapter; offline is default and may use a tool-local normalized cache. No live OSV request was used for the test suite.
- Python 3.14.7 unittest: 72 tests, 71 passed, 1 skipped because real Windows symlink creation is unavailable. Python 3.12 baseline, live OSV, junction/UNC/long-path behavior, and hard parser isolation remain unverified.
- Branch `main`; inspect current Git history and working tree for exact checkpoint. No push was made.

## Recommended Next Action

Read `AGENTS.md`, `PROJECT_STATUS.md`, [Dependency Scanner](../docs/DEPENDENCY_SCANNER.md), security boundaries, and the project skills; verify live Git and test state. Only on a new user request, start Phase 5 — Finding Correlation + Risk Engine.
