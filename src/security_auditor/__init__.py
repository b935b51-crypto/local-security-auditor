"""Local Security Auditor package metadata; no scanning is performed on import."""

from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path
import tomllib


def _resolve_version() -> str:
    """Use installed metadata, or the same pyproject when imported from source."""
    try:
        return distribution_version("local-security-auditor")
    except PackageNotFoundError:
        project_file = Path(__file__).resolve().parents[2] / "pyproject.toml"
        if not project_file.is_file():
            raise RuntimeError("Local Security Auditor package version is unavailable") from None
        with project_file.open("rb") as stream:
            project = tomllib.load(stream)["project"]
        if project["name"] != "local-security-auditor":
            raise RuntimeError("Local Security Auditor project metadata is invalid")
        return project["version"]


__version__ = _resolve_version()
