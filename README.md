# Local Security Auditor

Offline-first static security auditor of untrusted local repositories. **TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** Phases 1–4 implement bounded discovery, local secret and Python SAST/behavior scanning, and static dependency inventory with optional OSV lookup. Phase 5 adds deterministic correlation and risk annotations. Phase 6 adds optional advisory AI review. Phase 7 adds the `security-auditor scan PATH` CLI and safe Console, JSON, SARIF, and HTML reports. Phase 8 adds optional remediation guidance and non-applied patch proposals; see [Remediation](docs/REMEDIATION.md).

Use Python 3.12 with `uv`; the system Python is not modified. From the project root:

```powershell
uv sync --python 3.12
uv run python -m unittest discover -s tests -q
```

Version 1.0.1 adds an explicit `--osv` choice for online dependency vulnerability queries while keeping scans offline by default. The 1.0.1 patch is prepared locally; the existing 1.0.0 release remains the published version until a separate release action. The default package has no third-party runtime dependencies. Gemini review uses the optional `gemini` extra and remains separately opt-in. Hatchling is a build-only dependency. See [release notes](RELEASE_NOTES.md), [current status](PROJECT_STATUS.md), and the historical [Release Candidate evidence](docs/RELEASE_CANDIDATE.md). See [CLI](docs/CLI.md), [Reporting](docs/REPORTING.md), [AI reviewer](docs/AI_REVIEWER.md), [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), and [roadmap](docs/ROADMAP.md).

Phase 9 adds a local Windows desktop GUI and a deterministic Codex/CI security gate. Tk is part of the Python standard library, so there is no GUI runtime extra. Run `security-auditor gui` to inspect a scan or existing JSON report, or run `security-auditor gate report.json --format json` to evaluate coverage and primary findings without rescanning. See [GUI](docs/GUI.md), [Security Gate](docs/SECURITY_GATE.md), and [Codex integration](docs/CODEX_INTEGRATION.md). No patch apply action exists.
