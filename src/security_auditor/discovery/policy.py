"""Admission patterns and immutable discovery safety ceilings."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import os

from security_auditor.core.config import (
    AuditConfig, DEFAULT_EXCLUDE, DiscoveryLimits, HARD_MAX_DEPTH,
    HARD_MAX_DIRECTORIES, HARD_MAX_ELAPSED_SECONDS, HARD_MAX_ENTRIES,
    HARD_MAX_FILE_COUNT, HARD_MAX_FILE_SIZE, HARD_MAX_LINE_LENGTH,
    HARD_MAX_SNIFF_BYTES, HARD_MAX_TOTAL_BYTES,
)
from security_auditor.core.scope import (
    ExclusionReason, ScopeClass, classify_default_pattern,
)


def _normalized_pattern(pattern: str) -> str:
    value = pattern.replace("\\", "/")
    if not value or value.startswith("/") or ":" in value or "\x00" in value or ".." in value.split("/"):
        raise ValueError("unsafe discovery pattern")
    return value.removeprefix("./")


def pattern_matches(pattern: str, relative_path: str, *, is_directory: bool, windows: bool | None = None) -> bool:
    """Small documented glob subset; a trailing slash matches a directory tree."""
    pattern = _normalized_pattern(pattern)
    path = relative_path.replace("\\", "/").strip("/")
    case_insensitive = os.name == "nt" if windows is None else windows
    if case_insensitive:
        pattern, path = pattern.casefold(), path.casefold()
    parts = path.split("/")
    if pattern.endswith("/"):
        base = pattern.rstrip("/")
        if "/" in base:
            return path == base or path.startswith(base + "/")
        return base in (parts if is_directory else parts[:-1])
    if "/" not in pattern:
        return any(fnmatchcase(part, pattern) for part in parts)
    return fnmatchcase(path, pattern)


@dataclass(frozen=True, slots=True)
class DiscoveryPolicy:
    limits: DiscoveryLimits = DiscoveryLimits()
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    default_exclude: tuple[str, ...] = DEFAULT_EXCLUDE
    respect_gitignore: bool = False

    def __post_init__(self) -> None:
        hard_caps = (
            (self.limits.max_file_size_bytes, HARD_MAX_FILE_SIZE),
            (self.limits.max_file_count, HARD_MAX_FILE_COUNT),
            (self.limits.max_directory_depth, HARD_MAX_DEPTH),
            (self.limits.max_directories, HARD_MAX_DIRECTORIES),
            (self.limits.max_entries, HARD_MAX_ENTRIES),
            (self.limits.max_total_bytes_inspected, HARD_MAX_TOTAL_BYTES),
            (self.limits.max_sniff_bytes, HARD_MAX_SNIFF_BYTES),
            (self.limits.max_single_text_read, HARD_MAX_SNIFF_BYTES),
            (self.limits.max_line_length, HARD_MAX_LINE_LENGTH),
            (self.limits.max_elapsed_seconds, HARD_MAX_ELAPSED_SECONDS),
        )
        if any(type(value) is not int or not 1 <= value <= cap for value, cap in hard_caps):
            raise ValueError("discovery limit outside safety ceiling")
        if type(self.respect_gitignore) is not bool:
            raise ValueError("invalid gitignore policy")
        for item in (*self.include, *self.exclude, *self.default_exclude):
            if not isinstance(item, str):
                raise ValueError("invalid discovery pattern")
            _normalized_pattern(item)

    @classmethod
    def from_config(cls, config: AuditConfig) -> DiscoveryPolicy:
        return cls(config.limits, config.include, config.exclude,
                   config.default_exclude, config.respect_gitignore)

    def included(self, path: str, *, is_directory: bool = False) -> bool:
        return any(pattern_matches(p, path, is_directory=is_directory) for p in self.include)

    def excluded(self, path: str, *, is_directory: bool = False) -> bool:
        return self.exclusion(path, is_directory=is_directory) is not None

    def exclusion(self, path: str, *, is_directory: bool = False
                  ) -> tuple[ScopeClass, ExclusionReason] | None:
        if self.included(path, is_directory=is_directory):
            return None
        for pattern in self.default_exclude:
            if pattern_matches(pattern, path, is_directory=is_directory):
                return classify_default_pattern(pattern)
        if any(pattern_matches(p, path, is_directory=is_directory) for p in self.exclude):
            return ScopeClass.UNKNOWN, ExclusionReason.EXCLUDED_USER_POLICY
        return None

    def may_include_descendant(self, directory: str) -> bool:
        """Only a trusted include naming this tree may reopen an excluded directory."""
        if self.included(directory, is_directory=True):
            return True
        prefix = directory.replace("\\", "/").strip("/") + "/"
        if os.name == "nt":
            prefix = prefix.casefold()
        for pattern in self.include:
            normalized = _normalized_pattern(pattern)
            if os.name == "nt":
                normalized = normalized.casefold()
            if normalized.startswith(prefix):
                return True
        return False

    def admits_file(self, path: str) -> bool:
        return not self.include or self.included(path)
