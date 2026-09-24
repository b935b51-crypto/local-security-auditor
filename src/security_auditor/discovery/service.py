"""Deterministic, bounded traversal of an untrusted directory tree."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from time import monotonic
from typing import Callable

from security_auditor.core.models import FileArtifact, FileIdentity, ScanTarget
from security_auditor.core.scope import ExclusionReason, ScopeClass
from .classifier import classify
from .ignore import GitIgnore, load_root_gitignore
from .models import (
    DiagnosticCode, DiagnosticSeverity, DiscoveryDiagnostic, DiscoveryResult,
    DiscoverySummary, ScanCompleteness, ScopeExclusion, SkipReason, SkippedArtifact,
    TraversalStats,
)
from .path_safety import is_reparse_point, is_within_root, unsafe_component
from .platform.identity import file_identity
from .policy import DiscoveryPolicy
from .sniffing import sniff_prefix


@dataclass(slots=True)
class _Counters:
    directories_visited: int = 0
    entries_seen: int = 0
    files_discovered: int = 0
    files_admitted: int = 0
    files_inspected: int = 0
    bytes_inspected: int = 0
    files_skipped: int = 0
    directories_skipped: int = 0
    files_excluded: int = 0
    directories_excluded: int = 0
    default_exclusions: int = 0
    user_exclusions: int = 0

    def freeze(self) -> TraversalStats:
        return TraversalStats(
            self.directories_visited, self.entries_seen, self.files_discovered,
            self.files_admitted, self.files_inspected, self.bytes_inspected,
            self.files_skipped, self.directories_skipped,
            self.files_excluded, self.directories_excluded,
            self.default_exclusions, self.user_exclusions,
        )


def _sort_key(path: str) -> tuple[str, str]:
    return path.casefold(), path


def _exception_code(error: OSError) -> tuple[DiagnosticCode, SkipReason]:
    if isinstance(error, FileNotFoundError):
        return DiagnosticCode.FILE_DISAPPEARED, SkipReason.CHANGED_DURING_SCAN
    if isinstance(error, PermissionError):
        return DiagnosticCode.ACCESS_DENIED, SkipReason.ACCESS_DENIED
    return DiagnosticCode.STAT_FAILED, SkipReason.READ_ERROR


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns,
    )


def discover(target: ScanTarget, policy: DiscoveryPolicy,
             cancelled: Callable[[], bool] | None = None) -> DiscoveryResult:
    """Classify a target tree without executing target code or writing to it."""
    started = monotonic()
    stats = _Counters()
    artifacts: list[FileArtifact] = []
    skipped: list[SkippedArtifact] = []
    exclusions: list[ScopeExclusion] = []
    exclusions_omitted = 0
    diagnostics: list[DiscoveryDiagnostic] = []
    completeness = ScanCompleteness.COMPLETE
    root: Path | None = None

    def diagnostic(code: DiagnosticCode, path: str | None, *,
                   severity: DiagnosticSeverity = DiagnosticSeverity.WARNING,
                   exception_kind: str | None = None,
                   affects: bool = True) -> None:
        nonlocal completeness
        diagnostics.append(DiscoveryDiagnostic(
            code, severity, path, code.value.replace("_", " ").lower(),
            exception_kind, affects,
        ))
        if affects and completeness is ScanCompleteness.COMPLETE:
            completeness = ScanCompleteness.PARTIAL

    def skip(path: str, reason: SkipReason, *, is_directory: bool = False) -> None:
        skipped.append(SkippedArtifact(path, reason, is_directory))
        if is_directory:
            stats.directories_skipped += 1
        else:
            stats.files_skipped += 1

    def exclude(path: str, scope: ScopeClass, reason: ExclusionReason, *,
                is_directory: bool = False) -> None:
        nonlocal exclusions_omitted
        if len(exclusions) < 200:
            exclusions.append(ScopeExclusion(path, scope, reason, is_directory))
        else:
            exclusions_omitted += 1
        if is_directory:
            stats.directories_excluded += 1
        else:
            stats.files_excluded += 1
        if reason is ExclusionReason.EXCLUDED_USER_POLICY:
            stats.user_exclusions += 1
        else:
            stats.default_exclusions += 1

    def result() -> DiscoveryResult:
        return DiscoveryResult(
            root, tuple(sorted(artifacts, key=lambda a: _sort_key(a.path))),
            tuple(sorted(skipped, key=lambda a: (*_sort_key(a.path), a.reason.value))),
            tuple(sorted(diagnostics, key=lambda d: (*_sort_key(d.path or ""), d.code.value))),
            DiscoverySummary(stats.freeze(), monotonic() - started), completeness,
            tuple(sorted(exclusions, key=lambda x: _sort_key(x.path))), exclusions_omitted,
        )

    try:
        raw_target = os.fspath(target.root)
        if os.name == "nt" and (raw_target.startswith("\\\\.\\") or raw_target.lower().startswith("\\\\?\\globalroot")):
            raise ValueError("device namespace root")
        selected = Path(target.root).expanduser().absolute()
        root_info = os.stat(selected, follow_symlinks=False)
        if is_reparse_point(root_info):
            diagnostic(DiagnosticCode.ROOT_REPARSE_POINT, None, severity=DiagnosticSeverity.ERROR)
            completeness = ScanCompleteness.FAILED
            return result()
        if not stat.S_ISDIR(root_info.st_mode):
            diagnostic(DiagnosticCode.ROOT_NOT_DIRECTORY, None, severity=DiagnosticSeverity.ERROR)
            completeness = ScanCompleteness.FAILED
            return result()
        root = selected.resolve(strict=True)
        root_info = os.stat(root, follow_symlinks=False)
        root_identity = file_identity(root, root_info)
    except FileNotFoundError:
        diagnostic(DiagnosticCode.ROOT_NOT_FOUND, None, severity=DiagnosticSeverity.ERROR)
        completeness = ScanCompleteness.FAILED
        return result()
    except PermissionError:
        diagnostic(DiagnosticCode.ACCESS_DENIED, None, severity=DiagnosticSeverity.ERROR,
                   exception_kind="PermissionError")
        completeness = ScanCompleteness.FAILED
        return result()
    except (OSError, RuntimeError, ValueError) as error:
        diagnostic(DiagnosticCode.STAT_FAILED, None, severity=DiagnosticSeverity.ERROR,
                   exception_kind=type(error).__name__)
        completeness = ScanCompleteness.FAILED
        return result()

    if root_identity.fallback_key is not None:
        diagnostic(DiagnosticCode.IDENTITY_FALLBACK, None, affects=True)
    visited: set[FileIdentity] = {root_identity}
    gitignore = GitIgnore()
    if policy.respect_gitignore:
        try:
            gitignore = load_root_gitignore(root)
        except (OSError, UnicodeError, ValueError) as error:
            diagnostic(DiagnosticCode.GITIGNORE_UNAVAILABLE, ".gitignore",
                       exception_kind=type(error).__name__)

    # A stack avoids Python recursion limits. Each directory is enumerated once.
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        if cancelled is not None and cancelled():
            diagnostic(DiagnosticCode.SCAN_CANCELLED, None)
            completeness = ScanCompleteness.ABORTED
            break
        if monotonic() - started >= policy.limits.max_elapsed_seconds:
            diagnostic(DiagnosticCode.MAX_TIME_REACHED, None)
            completeness = ScanCompleteness.ABORTED
            break
        directory, depth = pending.pop()
        relative_dir = "." if directory == root else directory.relative_to(root).as_posix()
        if stats.directories_visited >= policy.limits.max_directories:
            diagnostic(DiagnosticCode.MAX_DIRECTORIES_REACHED, relative_dir)
            skip(relative_dir, SkipReason.RESOURCE_LIMIT, is_directory=True)
            completeness = ScanCompleteness.ABORTED
            break
        try:
            current_info = os.stat(directory, follow_symlinks=False)
            if is_reparse_point(current_info) or not stat.S_ISDIR(current_info.st_mode):
                diagnostic(DiagnosticCode.REPARSE_POINT_SKIPPED, relative_dir)
                skip(relative_dir, SkipReason.REPARSE_POINT, is_directory=True)
                continue
            if current_info.st_dev != root_info.st_dev or not is_within_root(root, directory):
                diagnostic(DiagnosticCode.OUTSIDE_ROOT_SKIPPED, relative_dir)
                skip(relative_dir, SkipReason.OUTSIDE_ROOT, is_directory=True)
                continue
            with os.scandir(directory) as entries:
                names: list[str] = []
                for entry in entries:
                    if cancelled is not None and cancelled():
                        diagnostic(DiagnosticCode.SCAN_CANCELLED, relative_dir)
                        completeness = ScanCompleteness.ABORTED
                        break
                    stats.entries_seen += 1
                    if stats.entries_seen > policy.limits.max_entries:
                        diagnostic(DiagnosticCode.MAX_ENTRIES_REACHED, relative_dir)
                        completeness = ScanCompleteness.ABORTED
                        break
                    names.append(entry.name)
            if completeness is ScanCompleteness.ABORTED:
                break
            fresh_directory = os.stat(directory, follow_symlinks=False)
            if (is_reparse_point(fresh_directory) or
                    not _same_file(current_info, fresh_directory) or
                    not is_within_root(root, directory)):
                diagnostic(DiagnosticCode.FILE_CHANGED, relative_dir)
                skip(relative_dir, SkipReason.CHANGED_DURING_SCAN, is_directory=True)
                continue
        except OSError as error:
            code, reason = _exception_code(error)
            diagnostic(code, relative_dir, exception_kind=type(error).__name__)
            skip(relative_dir, reason, is_directory=True)
            if directory == root:
                completeness = ScanCompleteness.FAILED
                break
            continue
        stats.directories_visited += 1
        child_directories: list[tuple[Path, int]] = []
        for name in sorted(names, key=_sort_key):
            if cancelled is not None and cancelled():
                diagnostic(DiagnosticCode.SCAN_CANCELLED, relative_dir)
                completeness = ScanCompleteness.ABORTED
                break
            if monotonic() - started >= policy.limits.max_elapsed_seconds:
                diagnostic(DiagnosticCode.MAX_TIME_REACHED, relative_dir)
                completeness = ScanCompleteness.ABORTED
                break
            if unsafe_component(name):
                unsafe_path = name if relative_dir == "." else f"{relative_dir}/{name}"
                diagnostic(DiagnosticCode.UNSAFE_PATH_SKIPPED, unsafe_path)
                skip(unsafe_path, SkipReason.UNSAFE_PATH)
                continue
            child = directory / name
            relative = child.relative_to(root).as_posix()
            try:
                info = os.stat(child, follow_symlinks=False)
            except OSError as error:
                code, reason = _exception_code(error)
                diagnostic(code, relative, exception_kind=type(error).__name__)
                skip(relative, reason)
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            if is_reparse_point(info):
                reason = SkipReason.REPARSE_POINT
                try:
                    if not child.exists():
                        reason = SkipReason.BROKEN_LINK
                    elif not is_within_root(root, child):
                        diagnostic(DiagnosticCode.OUTSIDE_ROOT_SKIPPED, relative)
                except (OSError, RuntimeError):
                    pass
                diagnostic(DiagnosticCode.REPARSE_POINT_SKIPPED, relative)
                skip(relative, reason, is_directory=is_dir)
                continue
            if info.st_dev != root_info.st_dev or not is_within_root(root, child):
                diagnostic(DiagnosticCode.OUTSIDE_ROOT_SKIPPED, relative)
                skip(relative, SkipReason.OUTSIDE_ROOT, is_directory=is_dir)
                continue
            if is_dir:
                scope_exclusion = policy.exclusion(relative, is_directory=True)
                if scope_exclusion and not policy.may_include_descendant(relative):
                    exclude(relative, *scope_exclusion, is_directory=True)
                    continue
                if (gitignore.ignores(relative, is_directory=True)
                        and not (policy.may_include_descendant(relative) or gitignore.has_negation)):
                    exclude(relative, ScopeClass.UNKNOWN,
                            ExclusionReason.EXCLUDED_USER_POLICY, is_directory=True)
                    continue
                if depth + 1 > policy.limits.max_directory_depth:
                    diagnostic(DiagnosticCode.MAX_DEPTH_REACHED, relative)
                    skip(relative, SkipReason.RESOURCE_LIMIT, is_directory=True)
                    continue
                try:
                    identity = file_identity(child, info)
                except (OSError, RuntimeError) as error:
                    diagnostic(DiagnosticCode.STAT_FAILED, relative, exception_kind=type(error).__name__)
                    skip(relative, SkipReason.READ_ERROR, is_directory=True)
                    continue
                if identity in visited:
                    diagnostic(DiagnosticCode.DIRECTORY_ALREADY_VISITED, relative)
                    skip(relative, SkipReason.RESOURCE_LIMIT, is_directory=True)
                    continue
                if identity.fallback_key is not None:
                    diagnostic(DiagnosticCode.IDENTITY_FALLBACK, relative)
                visited.add(identity)
                child_directories.append((child, depth + 1))
                continue
            if not stat.S_ISREG(info.st_mode):
                diagnostic(DiagnosticCode.UNSUPPORTED_FILE_TYPE, relative)
                skip(relative, SkipReason.SPECIAL_FILE)
                continue
            if info.st_size < 0:
                diagnostic(DiagnosticCode.STAT_FAILED, relative)
                skip(relative, SkipReason.UNSUPPORTED_TYPE)
                continue
            scope_exclusion = policy.exclusion(relative)
            if scope_exclusion:
                exclude(relative, *scope_exclusion)
                continue
            if gitignore.ignores(relative, is_directory=False) and not policy.included(relative):
                exclude(relative, ScopeClass.UNKNOWN, ExclusionReason.EXCLUDED_USER_POLICY)
                continue
            if not policy.admits_file(relative):
                exclude(relative, ScopeClass.UNKNOWN, ExclusionReason.EXCLUDED_USER_POLICY)
                continue
            stats.files_discovered += 1
            if stats.files_discovered > policy.limits.max_file_count:
                diagnostic(DiagnosticCode.MAX_FILES_REACHED, relative)
                skip(relative, SkipReason.RESOURCE_LIMIT)
                completeness = ScanCompleteness.ABORTED
                break
            if info.st_size > policy.limits.max_file_size_bytes:
                diagnostic(DiagnosticCode.FILE_TOO_LARGE, relative)
                skip(relative, SkipReason.TOO_LARGE)
                continue
            stats.files_admitted += 1
            remaining = policy.limits.max_total_bytes_inspected - stats.bytes_inspected
            size_to_read = min(info.st_size, policy.limits.max_sniff_bytes,
                               policy.limits.max_single_text_read)
            if size_to_read > remaining:
                diagnostic(DiagnosticCode.MAX_TOTAL_BYTES_REACHED, relative)
                skip(relative, SkipReason.RESOURCE_LIMIT)
                completeness = ScanCompleteness.ABORTED
                break
            try:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(child, flags)
                with os.fdopen(descriptor, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    fresh = os.stat(child, follow_symlinks=False)
                    if (not stat.S_ISREG(opened.st_mode) or is_reparse_point(fresh)
                            or not _same_file(info, opened) or not _same_file(info, fresh)
                            or not is_within_root(root, child)):
                        diagnostic(DiagnosticCode.FILE_CHANGED, relative)
                        skip(relative, SkipReason.CHANGED_DURING_SCAN)
                        continue
                    prefix = stream.read(size_to_read)
                    stats.bytes_inspected += len(prefix)
                    if len(prefix) != size_to_read or not _same_file(info, os.fstat(stream.fileno())):
                        diagnostic(DiagnosticCode.FILE_CHANGED, relative)
                        skip(relative, SkipReason.CHANGED_DURING_SCAN)
                        continue
            except OSError as error:
                code, reason = _exception_code(error)
                diagnostic(DiagnosticCode.READ_FAILED if code is DiagnosticCode.STAT_FAILED else code,
                           relative, exception_kind=type(error).__name__)
                skip(relative, reason)
                continue
            stats.files_inspected += 1
            sniff = sniff_prefix(prefix, max_line_length=policy.limits.max_line_length)
            if sniff.decode_failed:
                diagnostic(DiagnosticCode.DECODE_FAILED, relative)
            if sniff.long_line:
                diagnostic(DiagnosticCode.LONG_LINE, relative, affects=False)
            classification = classify(relative, sniff)
            try:
                identity = file_identity(child, info)
            except (OSError, RuntimeError) as error:
                diagnostic(DiagnosticCode.FILE_CHANGED, relative, exception_kind=type(error).__name__)
                skip(relative, SkipReason.CHANGED_DURING_SCAN)
                continue
            artifacts.append(FileArtifact(
                path=relative, size_bytes=info.st_size, kind=classification.kind,
                language=classification.language, content_kind=sniff.content_kind,
                script_kind=classification.script_kind, manifest_kind=classification.manifest_kind,
                identity=identity, basename=name, suffixes=tuple(Path(name).suffixes),
                mtime_ns=info.st_mtime_ns, encoding=sniff.encoding,
                classification_confidence=classification.confidence,
                is_executable_like=classification.executable_like,
                sniffed_bytes=len(prefix),
            ))
        if completeness is ScanCompleteness.ABORTED:
            break
        pending.extend(reversed(child_directories))
    return result()
