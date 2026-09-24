# CLI

`security-auditor scan PATH` runs static analysis of a local folder. **Scanned code is never executed.** The packaged entry point is `security-auditor`; from this checkout use `uv run security-auditor scan PATH --offline`. The project-local uv environment uses verified Python 3.12.11; the system Python is not modified. The default runtime has no third-party dependencies. The Gemini SDK is an optional `gemini` extra. The build backend is Hatchling and is required only to build/install the package.

## Installation and version

For development from this checkout, use `uv sync --python 3.12`, then `uv run security-auditor --version`. The locally built 1.0.0 wheel can be installed in a new Python 3.12 environment with `uv pip install --python <venv-python> dist/local_security_auditor-1.0.0-py3-none-any.whl` (or `python -m pip install <wheel-path>` where pip is available). This project has not been published to a package registry. To build artifacts, run `uv build`; the wheel and sdist are written to `dist/`. Do not use an editable install for release validation. The installed CLI and `ScanReport.tool.version` obtain `1.0.0` from installed distribution metadata; an uninstalled source checkout falls back to this project's `pyproject.toml`.

The core wheel has no third-party runtime requirements. Gemini is optional: install `<wheel-path>[gemini]` in a separate environment, which resolves `google-genai>=2.25.0,<3.0.0`. No Gemini package or key is needed for offline scans. The installed GUI uses `tkinter` from the selected Python installation; a Python build without Tk cannot launch it. The wheel bundles all runtime Python modules, including zh-TW HTML strings. `docs/`, `.agents/skills/`, and `tests/` are repository material, not runtime wheel resources. The sdist contains only package source, build metadata, README, and Hatchling's `.gitignore` entry. See [release notes](../RELEASE_NOTES.md) for current status and the historical [Release Candidate](RELEASE_CANDIDATE.md) for earlier verification.

```powershell
security-auditor --version
security-auditor scan . --offline
security-auditor scan D:\Repo --profile standard --format json --output audit.json
security-auditor scan D:\Repo --format sarif --output audit.sarif
security-auditor scan D:\Repo --format html --output audit.html
```

Defaults: `standard`, console stdout, offline, AI disabled, no report file. `quick` omits Python SAST and correlation; `standard` and `deep` run all current deterministic scanners and correlation. `deep` does **not** enable AI automatically. Current deep budgets are the same bounded defaults as standard; deeper analysis rules are future work. `--offline` disables OSV live lookup and Gemini. Offline dependency inventory and valid local advisory cache remain available. A trusted config with `[scan] offline=false` may enable OSV; `--ai` alone grants Gemini egress and keeps OSV live lookup disabled when the default config is offline. `--offline --ai` disables AI with a visible notice. Target-local config is never loaded automatically.

`--config PATH` selects trusted operator TOML. Precedence is safe built-in defaults, explicit trusted config, then CLI profile/offline/AI choices. Hard caps cannot be raised. `--no-ai` forces AI off. Missing Gemini key or optional SDK does not stop deterministic scanning; AI status and diagnostics explain the unavailable review. Real AI uses bounded redacted context only; see [AI Reviewer](AI_REVIEWER.md).

`--format console|json|sarif|html` selects one output. JSON and SARIF stdout contain only valid JSON. HTML requires `--output`; reports are UTF-8. A relative target or output path is interpreted from the current working directory. The output parent must already exist. Existing files are never overwritten without `--force`, and links/reparse points or special destinations are rejected. `--verbose` expands sanitized console diagnostics; `--no-color` is accepted (v1 never emits color). `--fail-on critical|high|medium|low|info` exits 10 after report generation if a deterministic primary finding meets the severity threshold; AI cannot trigger it.

Exit codes: `0` scan/report completed, `2` CLI/config usage error, `3` target validation or fatal scan failure, `4` report serialization/write failure, `10` requested deterministic threshold met. Partial coverage is a completed operation and does not by itself change exit code. Interrupts return a nonzero failure code. No telemetry or automatic target write is performed.

See [Reporting](REPORTING.md) for output schema, coverage meanings, and privacy rules.

The default project scope prunes known generated caches, virtual environments, dependency vendor trees, and build outputs before descending into them. `.env`, `tests/`, manifests, and lockfiles remain eligible. JSON `discovery.scope`, console totals, and the zh-TW HTML scope section disclose what was intentionally excluded; these exclusions are distinct from scanner failures. `--config` can provide trusted `default_exclude`, `exclude`, and explicit path-based `include` overrides; target-local files cannot silently change these rules. See [Discovery](DISCOVERY.md).

Phase 8 adds `--propose-fixes` for guidance and non-applied patch proposals. `--ai-remediation` requires `--propose-fixes` and separately grants Gemini patch egress when online; `--ai` alone remains advisory review only. `--offline` still allows deterministic proposals. There is no apply option and runtime target tests are never run. See [Remediation](REMEDIATION.md).

Phase 9 adds `security-auditor gui` for a local Tk desktop interface and `security-auditor gate REPORT.json [--format console|json]` for deterministic decisions over an existing canonical JSON 1.1 report. Gate never rescans the target; default policy 1.0 blocks incomplete coverage and HIGH primary findings, while AI remains advisory. Gate exit codes are 0 PASS, 10 WARN, 20 BLOCK, 2 usage, and 3 invalid report. The GUI is imported lazily; `scan`, `gate`, `--help`, and `--version` work without a Tk runtime. See [GUI](GUI.md) and [Security Gate](SECURITY_GATE.md).
