# Current Handoff

Local Security Auditor `1.0.1` patch is prepared locally on `main`. The existing 1.0.0 tag and GitHub Release predate this task; no 1.0.1 tag, push, or publication occurred. Phase 10 has not started.

The CLI now offers `--osv` for explicit bounded OSV permission, mutually exclusive with `--offline`; default scans remain offline, and `--ai` is independent. Offline missing-cache diagnostics are clearer. JSON 1.1, SARIF 2.1.0, Gate 1.0, provider budgets, scanner rules, and cache algorithms are unchanged. Python 3.12.11 offline regression passed 199 tests (193 passed, 0 failed, 6 skipped). The 1.0.1 wheel and sdist were built; separate repo-external clean Python 3.12.11 installs passed, including installed-wheel fake-provider CLI behavior and sdist import/version. Artifacts are ignored in `dist/` and are not committed.

Cache diagnosis: the 1.0.0 report recorded 0/341 hits and `scan.offline=true`. In the current shell, production source and installed 1.0.0 APIs each parse 341 current exact keys and read 341 fresh matching cache entries from the same default root. The entries and four manifests predate the failing report, but that report did not record its effective cache path or process environment. A historical cache-root mismatch is plausible, not proven. No speculative cache fix was made.

The clean 1.0.1 wheel scanned the authorized Trading Platform offline and with `--osv --no-ai`: both runs used 341 cache entries and zero OSV requests, had dependency/overall COMPLETE and Gate WARN; `scan.offline` correctly differed. Target Git status was empty before and after. The synthetic installed-wheel fake provider confirmed `--osv` reaches the provider on a cache miss; no Gemini or target code ran.

Read [project status](../PROJECT_STATUS.md), [CLI](../docs/CLI.md), [release notes](../RELEASE_NOTES.md), and [changelog](../CHANGELOG.md). Preserve pre-existing untracked audit reports and `uv.lock`. Confirm whether the historical cache environment warrants a follow-up before an annotated `v1.0.1` tag. Do not tag, push, publish, or start Phase 10 without separate instruction.
