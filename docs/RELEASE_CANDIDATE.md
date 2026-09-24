# v1 Release Candidate readiness — 0.9.0

Validated on 2026-09-24 with Windows NT 10.0.26200, uv 0.12.13, and CPython 3.12.11. This is a **release candidate baseline**, not a final 1.0.0 release or a certification of scanned projects. Phase 10 has not started.

## Version and artifacts

`pyproject.toml` is the single version source: `0.9.0`. Installed code uses `importlib.metadata`; an uninstalled source checkout reads that same `pyproject.toml` if distribution metadata is absent. The CLI, wheel `METADATA`, and JSON `tool.version` all returned `0.9.0`.

`uv build` produced `dist/local_security_auditor-0.9.0-py3-none-any.whl` and `dist/local_security_auditor-0.9.0.tar.gz`; uv built the wheel from the sdist. The wheel contained 97 Python modules plus four distribution metadata files, including the CLI entry point, GUI, Gate, all reporters, and `reporting/i18n.py`. The sdist contained package source, `pyproject.toml`, README, `.gitignore`, and generated `PKG-INFO`. Explicit sdist inclusion avoids untracked workspace material. The archive member lists contained no `.env`, audit reports, caches, tests, docs, skills, `.git`, or temp sandboxes. A bounded content inspection found no Mosaic/project path markers or credential assignment marker. Runtime schemas, prompts, HTML layout, and localization are Python modules/constants; repository JSON schemas under `docs/` are reference material, not runtime file dependencies. Byte-for-byte reproducibility was not required or tested.

Package metadata: `local-security-auditor`, Python `>=3.12,<3.13`, no core runtime dependencies, optional `gemini` extra with `google-genai>=2.25.0,<3.0.0`, Hatchling build backend, and `security-auditor = security_auditor.cli.main:main`. The declared Python range remains narrow because only 3.12 is the release baseline. Tk comes from the selected Python installation; there is no GUI extra.

## Clean installations and behavior

Two new temporary Python 3.12.11 environments were created outside the checkout. The core environment installed **only the built wheel**, with no `PYTHONPATH=src` and a working directory outside the repository. The installed package imported from that environment, had no `google-genai` package, and passed `--version`, root/scan/gate help, synthetic offline scan, JSON 1.1 with `tool.version=0.9.0`, zh-TW HTML, SARIF 2.1.0, and Gate PASS on a harmless synthetic file. Tk 8.6 imported; `security-auditor gui` created a new visible main window and was then closed. The GUI smoke checks launch only, not every dialog, high-DPI layout, or assistive technology behavior.

The second clean environment installed the same wheel with `[gemini]`, resolving `google-genai==2.25.0`; provider import and initialization succeeded. With the key removed from the test process environment and an inert synthetic high-priority finding, `scan --ai` completed deterministic analysis and returned `AI_API_KEY_MISSING` with AI failed. `scan --offline --ai` returned `AI_OFFLINE` with AI disabled. No Gemini request was made. The initial offline extra installation could not use an uncached SDK wheel; only this optional environment then downloaded its declared SDK dependency. No system Python or target package was modified.

Source-tree and installed-wheel offline scans of the **same synthetic target** matched on JSON schema, tool version, coverage, scanner IDs/statuses/counts, severity counts, finding rule IDs/severity/confidence/relative paths/fingerprints, and Gate result. Both reported COMPLETE coverage, five deterministic findings, four scanner entries, and Gate BLOCK for deliberately unsafe synthetic source. Scan ID, timestamps, and duration were excluded from comparison. This validates the compared behavior; it does not prove every platform or input produces identical results.

The source offline regression suite on Python 3.12.11 ran 149 tests: 145 passed, 0 failed, 4 skipped (two host-limited symlink tests and two gated live provider tests). The release smoke did not enable live OSV or Gemini. The synthetic target was never imported or executed; no target dependencies were installed. Build/install operated only on this auditor package. Temporary environments, reports, and synthetic files were removed after validation; the ignored `dist/` artifacts remain available locally and are not committed.

## RC limits and next validation

Real Windows symlink creation and UNC paths remain unvalidated on this host. Standalone executable and installer are not built. High-DPI and native assistive technology behavior need manual checks. Redaction is heuristic. Gemini's installed-wheel credential route was verified only for missing key and offline behavior; no new live Gemini request was made. Proposal-only remediation remains in force, with no controlled patch application.

Recommended next work is **v1 RC real-world validation** against a medium Python repository, a Node/TypeScript repository, and a mixed-language repository, always as untrusted static inputs. Review completeness and residual risks before deciding whether `0.9.0` is ready to become `1.0.0`.
