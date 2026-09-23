"""Small parser helpers; only fixed error codes cross the parser boundary."""

from __future__ import annotations

from dataclasses import dataclass

from security_auditor.scanners.dependencies.models import (
    DependencyGroup, DependencyRecord, Directness, VersionKind,
    normalize_name, safe_exact_version,
)
from security_auditor.scanners._common import safe_finding_path


class ParseError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ParseResult:
    records: tuple[DependencyRecord, ...] = ()
    includes: tuple[IncludeRef, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IncludeRef:
    path: str
    constraint_only: bool = False


def record(ecosystem: str, name: str, version: str | None, kind: VersionKind,
           direct: Directness, group: DependencyGroup, path: str, *, line: int | None = None,
           constraint: str | None = None, source: str = "registry",
           logical_path: str = "", resolved: bool = False) -> DependencyRecord | None:
    normalized = normalize_name(ecosystem, name)
    if normalized is None or (version is not None and (len(version) > 100 or any(ord(c) < 32 for c in version))):
        return None
    if len(logical_path) > 300 or any(ord(c) < 32 for c in logical_path):
        return None
    if kind is VersionKind.EXACT and (version is None or not safe_exact_version(version)):
        return None
    if (kind in {VersionKind.VCS, VersionKind.LOCAL_PATH, VersionKind.URL} or
            (constraint is not None and (len(constraint) > 200 or
             safe_finding_path(constraint) != constraint or
             not all(c.isalnum() or c in "<>=!~^*|.,+ -_" for c in constraint)))):
        constraint = None
    return DependencyRecord(ecosystem, normalized, version, kind, direct, group, safe_finding_path(path),
                            line, constraint, source, safe_finding_path(logical_path), (), resolved)


def append_record(records: list[DependencyRecord], diagnostics: list[str], item: DependencyRecord | None) -> None:
    if item is None:
        diagnostics.append("DEPENDENCY_PARSE_FAILED")
    else:
        records.append(item)


def version_kind(value: str, ecosystem: str) -> tuple[str | None, VersionKind]:
    value = value.strip()
    if not value:
        return None, VersionKind.UNRESOLVED
    lower = value.lower()
    if lower.startswith(("git+", "github:", "git://", "git@")):
        return None, VersionKind.VCS
    if lower.startswith(("file:", "workspace:", "link:", "path:", "./", "../", "/")):
        return None, VersionKind.LOCAL_PATH
    if lower.startswith(("https://", "http://")):
        return None, VersionKind.URL
    if ecosystem == "PyPI":
        if value.startswith("==="):
            return None, VersionKind.CONSTRAINT
        if value.startswith("==") and safe_exact_version(value[2:].strip()):
            return value[2:].strip(), VersionKind.EXACT
        return None, VersionKind.CONSTRAINT
    if ecosystem == "npm":
        if safe_exact_version(value) and value[0].isdigit() and not any(x in value for x in ("^", "~", "*", "x", "X", ">", "<", "|")):
            return value, VersionKind.EXACT
        return None, VersionKind.CONSTRAINT
    if ecosystem == "crates.io":
        if value.startswith("=") and safe_exact_version(value[1:].strip()):
            return value[1:].strip(), VersionKind.EXACT
        return None, VersionKind.CONSTRAINT
    if ecosystem == "Go" and safe_exact_version(value) and value.startswith("v"):
        return value, VersionKind.EXACT
    return None, VersionKind.CONSTRAINT
