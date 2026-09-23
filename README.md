# Local Security Auditor

Offline-first static security auditor of untrusted local repositories. **TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** Phase 1 provides passive, bounded file discovery and classification. Phase 2 adds a native offline Secret Scanner over admitted text artifacts with redacted findings. No CLI scan command or reporter exists yet.

Use Python 3.12 with `uv`; the system Python is not modified. From the project root, when Python 3.12 is available:

```powershell
$env:PYTHONPATH='src'
uv run --no-sync --python 3.12 python -m unittest discover -s tests -v
```

The package has no third-party dependencies. With an existing Python 3.12 interpreter, `py -3.12 -m unittest discover -s tests -v` also works with `PYTHONPATH=src`. See [discovery](docs/DISCOVERY.md), [secret scanner](docs/SECRET_SCANNER.md), [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), [roadmap](docs/ROADMAP.md), and [current status](PROJECT_STATUS.md).
