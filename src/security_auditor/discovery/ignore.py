"""Optional, bounded root .gitignore subset; separate from security excludes."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from .path_safety import is_reparse_point, is_within_root
from .policy import pattern_matches


MAX_GITIGNORE_BYTES = 64 * 1024
MAX_GITIGNORE_LINES = 1024


@dataclass(frozen=True, slots=True)
class GitIgnore:
    rules: tuple[tuple[bool, str], ...] = ()  # True is a negation/re-include

    @property
    def has_negation(self) -> bool:
        return any(negated for negated, _ in self.rules)

    def ignores(self, path: str, *, is_directory: bool) -> bool:
        ignored = False
        for negated, pattern in self.rules:
            if pattern_matches(pattern, path, is_directory=is_directory):
                ignored = not negated
        return ignored


def load_root_gitignore(root: Path) -> GitIgnore:
    """Read only a small regular file; unsupported/unsafe patterns fail closed."""
    path = root / ".gitignore"
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return GitIgnore()
    if is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_GITIGNORE_BYTES:
        raise ValueError("unavailable gitignore")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        fresh = os.stat(path, follow_symlinks=False)
        if (is_reparse_point(fresh) or not is_within_root(root, path)
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or (info.st_dev, info.st_ino) != (fresh.st_dev, fresh.st_ino)):
            raise ValueError("changed gitignore")
        data = stream.read(MAX_GITIGNORE_BYTES + 1)
        post = os.fstat(stream.fileno())
        if (opened.st_size, opened.st_mtime_ns) != (post.st_size, post.st_mtime_ns):
            raise ValueError("changed gitignore")
    if len(data) > MAX_GITIGNORE_BYTES:
        raise ValueError("unavailable gitignore")
    lines = data.decode("utf-8-sig", errors="strict").splitlines()
    if len(lines) > MAX_GITIGNORE_LINES:
        raise ValueError("unavailable gitignore")
    rules: list[tuple[bool, str]] = []
    for raw in lines:
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        if not pattern or "[" in pattern or "]" in pattern:
            raise ValueError("unsupported gitignore pattern")
        # The policy matcher validates path traversal and drive syntax.
        pattern_matches(pattern, "", is_directory=False)
        rules.append((negated, pattern))
    return GitIgnore(tuple(rules))
