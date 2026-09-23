"""Path and display helpers for hostile filesystem names."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from security_auditor.core.redaction import safe_display


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{n}" for n in range(1, 10)), *(f"LPT{n}" for n in range(1, 10))}


def unsafe_component(name: str, *, windows: bool | None = None) -> bool:
    """Reject ambiguous path components before joining a target-controlled name."""
    if not name or name in {".", ".."} or "\x00" in name or "/" in name or "\\" in name:
        return True
    is_windows = os.name == "nt" if windows is None else windows
    if is_windows:
        if ":" in name or name.endswith((".", " ")):
            return True
        if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            return True
    return False


def is_reparse_point(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def is_within_root(root: Path, candidate: Path) -> bool:
    """Resolve and compare path components, never string prefixes."""
    try:
        actual = candidate.resolve(strict=True)
        return os.path.commonpath((os.path.normcase(str(root)), os.path.normcase(str(actual)))) == os.path.normcase(str(root))
    except (OSError, RuntimeError, ValueError):
        return False
