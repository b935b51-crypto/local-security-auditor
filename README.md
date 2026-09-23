# Local Security Auditor

Phase 0 foundation for an offline-first static security auditor of untrusted local repositories. **TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** No scanner or CLI scan command exists yet.

Use Python 3.12 with `uv`; the system Python is not modified. From the project root, when Python 3.12 is available:

```powershell
uv run --no-sync --python 3.12 python -m unittest discover -s tests -v
```

The package currently has no third-party dependencies. With an existing Python 3.12 interpreter, `py -3.12 -m unittest discover -s tests -v` also works with `PYTHONPATH=src`. See [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), [roadmap](docs/ROADMAP.md), and [current status](PROJECT_STATUS.md).
