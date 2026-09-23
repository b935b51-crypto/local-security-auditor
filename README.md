# Local Security Auditor

Offline-first static security auditor of untrusted local repositories. **TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** Phases 1–4 implement bounded discovery, local secret and Python SAST/behavior scanning, and static dependency inventory with optional OSV lookup. Phase 5 adds deterministic correlation and risk annotations. Phase 6 adds an optional, advisory AI review library with explicit online opt-in and a Gemini adapter. No CLI scan command or reporter exists yet.

Use Python 3.12 with `uv`; the system Python is not modified. From the project root, when Python 3.12 is available:

```powershell
$env:PYTHONPATH='src'
uv run --no-sync --python 3.12 python -m unittest discover -s tests -v
```

The default package has no third-party runtime dependencies. Gemini review uses the optional `gemini` extra; it is disabled by default and never needed for local scans or tests. With an existing Python 3.12 interpreter, `py -3.12 -m unittest discover -s tests -v` also works with `PYTHONPATH=src`. See [AI reviewer](docs/AI_REVIEWER.md), [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), [roadmap](docs/ROADMAP.md), and [current status](PROJECT_STATUS.md).
