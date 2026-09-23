"""Structured discovery outcomes, separate from vulnerability findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from security_auditor.core.models import FileArtifact


class ScanCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    ABORTED = "aborted"
    FAILED = "failed"


class SkipReason(StrEnum):
    EXCLUDED_BY_POLICY = "excluded_by_policy"
    NOT_INCLUDED = "not_included"
    REPARSE_POINT = "reparse_point"
    OUTSIDE_ROOT = "outside_root"
    TOO_LARGE = "too_large"
    RESOURCE_LIMIT = "resource_limit"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_TYPE = "unsupported_type"
    READ_ERROR = "read_error"
    BROKEN_LINK = "broken_link"
    SPECIAL_FILE = "special_file"
    CHANGED_DURING_SCAN = "changed_during_scan"
    UNSAFE_PATH = "unsafe_path"


class DiagnosticSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DiagnosticCode(StrEnum):
    ROOT_NOT_FOUND = "ROOT_NOT_FOUND"
    ROOT_NOT_DIRECTORY = "ROOT_NOT_DIRECTORY"
    ROOT_REPARSE_POINT = "ROOT_REPARSE_POINT"
    ACCESS_DENIED = "ACCESS_DENIED"
    FILE_DISAPPEARED = "FILE_DISAPPEARED"
    REPARSE_POINT_SKIPPED = "REPARSE_POINT_SKIPPED"
    OUTSIDE_ROOT_SKIPPED = "OUTSIDE_ROOT_SKIPPED"
    MAX_DEPTH_REACHED = "MAX_DEPTH_REACHED"
    MAX_FILES_REACHED = "MAX_FILES_REACHED"
    MAX_DIRECTORIES_REACHED = "MAX_DIRECTORIES_REACHED"
    MAX_ENTRIES_REACHED = "MAX_ENTRIES_REACHED"
    MAX_TOTAL_BYTES_REACHED = "MAX_TOTAL_BYTES_REACHED"
    MAX_TIME_REACHED = "MAX_TIME_REACHED"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    DECODE_FAILED = "DECODE_FAILED"
    STAT_FAILED = "STAT_FAILED"
    READ_FAILED = "READ_FAILED"
    FILE_CHANGED = "FILE_CHANGED"
    IDENTITY_FALLBACK = "IDENTITY_FALLBACK"
    DIRECTORY_ALREADY_VISITED = "DIRECTORY_ALREADY_VISITED"
    GITIGNORE_UNAVAILABLE = "GITIGNORE_UNAVAILABLE"
    LONG_LINE = "LONG_LINE"
    UNSAFE_PATH_SKIPPED = "UNSAFE_PATH_SKIPPED"


@dataclass(frozen=True, slots=True)
class SkippedArtifact:
    path: str
    reason: SkipReason
    is_directory: bool = False


@dataclass(frozen=True, slots=True)
class DiscoveryDiagnostic:
    code: DiagnosticCode
    severity: DiagnosticSeverity
    path: str | None
    message: str  # fixed text, never an exception string or source snippet
    exception_kind: str | None = None
    affects_completeness: bool = False


@dataclass(frozen=True, slots=True)
class TraversalStats:
    directories_visited: int = 0
    entries_seen: int = 0
    files_discovered: int = 0
    files_admitted: int = 0
    files_inspected: int = 0
    bytes_inspected: int = 0
    files_skipped: int = 0
    directories_skipped: int = 0


@dataclass(frozen=True, slots=True)
class DiscoverySummary:
    stats: TraversalStats
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    root: Path | None
    artifacts: tuple[FileArtifact, ...]
    skipped: tuple[SkippedArtifact, ...]
    diagnostics: tuple[DiscoveryDiagnostic, ...]
    summary: DiscoverySummary
    completeness: ScanCompleteness
