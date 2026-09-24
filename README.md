# Local Security Auditor

Offline-first static security auditor of untrusted local repositories. **TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** Phases 1–4 implement bounded discovery, local secret and Python SAST/behavior scanning, and static dependency inventory with optional OSV lookup. Phase 5 adds deterministic correlation and risk annotations. Phase 6 adds optional advisory AI review. Phase 7 adds the `security-auditor scan PATH` CLI and safe Console, JSON, SARIF, and HTML reports. Phase 8 adds optional remediation guidance and non-applied patch proposals; see [Remediation](docs/REMEDIATION.md).

Use Python 3.12 with `uv`; the system Python is not modified. From the project root:

```powershell
uv sync --python 3.12
uv run python -m unittest discover -s tests -q
```

Version 0.9.0 is the v1 Release Candidate baseline. The default package has no third-party runtime dependencies. Gemini review uses the optional `gemini` extra; it is disabled by default and never needed for local scans or tests. Hatchling is a build-only dependency. A clean Python 3.12.11 environment installed the wheel and ran CLI, Gate, reporting, and GUI smoke checks; see [Release Candidate](docs/RELEASE_CANDIDATE.md) and [current status](PROJECT_STATUS.md). See [CLI](docs/CLI.md), [Reporting](docs/REPORTING.md), [AI reviewer](docs/AI_REVIEWER.md), [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), and [roadmap](docs/ROADMAP.md).

Phase 9 adds a local Windows desktop GUI and a deterministic Codex/CI security gate. Tk is part of the Python standard library, so there is no GUI runtime extra. Run `security-auditor gui` to inspect a scan or existing JSON report, or run `security-auditor gate report.json --format json` to evaluate coverage and primary findings without rescanning. See [GUI](docs/GUI.md), [Security Gate](docs/SECURITY_GATE.md), and [Codex integration](docs/CODEX_INTEGRATION.md). No patch apply action exists.
