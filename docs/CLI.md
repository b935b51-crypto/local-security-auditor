# CLI

`security-auditor scan PATH` runs static analysis of a local folder. **Scanned code is never executed.** The packaged entry point is `security-auditor`; from this source checkout use `PYTHONPATH=src` and `py -3.12 -m security_auditor` once Python 3.12 is available. The current host has only Python 3.14 verified, so local development checks use `py -3.14` with `PYTHONPATH=src`. `uv` manages a project-local environment; the default runtime has no third-party dependencies. The Gemini SDK is an optional `gemini` extra. The build backend is Hatchling and is required only to build/install the package.

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
