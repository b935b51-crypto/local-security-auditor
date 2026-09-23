"""Use fresh os.stat identity; never use cached Windows DirEntry.stat identity."""

from __future__ import annotations

import os
from pathlib import Path

from security_auditor.core.models import FileIdentity


def file_identity(path: Path, stat_result: os.stat_result) -> FileIdentity:
    """Return device/file identity, with a path fallback for unusual filesystems."""
    platform = "windows" if os.name == "nt" else "portable"
    if stat_result.st_ino:
        return FileIdentity(platform, stat_result.st_dev, stat_result.st_ino)
    # Identity can be unavailable on network or virtual filesystems. This
    # fallback only limits loops; it cannot prove two aliases are the same file.
    resolved = path.resolve(strict=True)
    key = os.path.normcase(str(resolved))
    return FileIdentity(platform, None, None, key)
