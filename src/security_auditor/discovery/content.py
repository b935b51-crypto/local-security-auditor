"""Bounded reopen of a Phase 1 admitted artifact; target bytes remain data."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from security_auditor.core.models import FileArtifact
from .path_safety import is_reparse_point, is_within_root, unsafe_component
from .platform.identity import file_identity


class ArtifactReadError(Exception):
    """A fixed safe code only; never place target bytes in exception arguments."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def read_admitted_artifact(root: Path, artifact: FileArtifact, *, max_bytes: int) -> bytes:
    """Read exactly one admitted regular file, with identity and containment checks.

    Path checks reduce races, but do not provide a Windows handle-relative sandbox.
    """
    if type(max_bytes) is not int or max_bytes < 0 or artifact.size_bytes > max_bytes:
        raise ArtifactReadError("SECRET_FILE_TOO_LARGE")
    parts = artifact.path.split("/")
    if not parts or any(unsafe_component(part) for part in parts):
        raise ArtifactReadError("SECRET_READ_FAILED")
    try:
        selected_info = os.stat(root, follow_symlinks=False)
        if is_reparse_point(selected_info) or not stat.S_ISDIR(selected_info.st_mode):
            raise ArtifactReadError("SECRET_READ_FAILED")
        canonical = root.resolve(strict=True)
        root_info = os.stat(canonical, follow_symlinks=False)
        if (is_reparse_point(root_info) or not stat.S_ISDIR(root_info.st_mode)
                or (selected_info.st_dev, selected_info.st_ino) != (root_info.st_dev, root_info.st_ino)):
            raise ArtifactReadError("SECRET_READ_FAILED")
        current = canonical
        for part in parts[:-1]:
            current = current / part
            info = os.stat(current, follow_symlinks=False)
            if (is_reparse_point(info) or not stat.S_ISDIR(info.st_mode)
                    or info.st_dev != root_info.st_dev or not is_within_root(canonical, current)):
                raise ArtifactReadError("SECRET_READ_FAILED")
        path = current / parts[-1]
        before = os.stat(path, follow_symlinks=False)
        if (is_reparse_point(before) or not stat.S_ISREG(before.st_mode)
                or before.st_dev != root_info.st_dev or not is_within_root(canonical, path)
                or before.st_size != artifact.size_bytes or before.st_mtime_ns != artifact.mtime_ns
                or artifact.identity is None or file_identity(path, before) != artifact.identity):
            raise ArtifactReadError("SECRET_READ_FAILED")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            fresh = os.stat(path, follow_symlinks=False)
            if (is_reparse_point(fresh) or not stat.S_ISREG(opened.st_mode)
                    or not is_within_root(canonical, path)
                    or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    or (fresh.st_dev, fresh.st_ino, fresh.st_size, fresh.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
                raise ArtifactReadError("SECRET_READ_FAILED")
            data = stream.read(artifact.size_bytes)
            after = os.fstat(stream.fileno())
            if (len(data) != artifact.size_bytes or
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
                raise ArtifactReadError("SECRET_READ_FAILED")
            return data
    except ArtifactReadError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise ArtifactReadError("SECRET_READ_FAILED") from None
