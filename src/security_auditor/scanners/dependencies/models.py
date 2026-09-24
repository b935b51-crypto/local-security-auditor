"""Bounded, normalized supply-chain data. No source or provider payloads."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import re

from security_auditor.core.models import Severity
from security_auditor.scanners._common import safe_finding_path


class VersionKind(StrEnum):
    EXACT = "exact"
    CONSTRAINT = "constraint"
    UNRESOLVED = "unresolved"
    VCS = "vcs"
    LOCAL_PATH = "local_path"
    URL = "url"


class DependencyIdentity(StrEnum):
    REGISTRY = "REGISTRY"
    FIRST_PARTY_ROOT = "FIRST_PARTY_ROOT"
    LOCAL_PATH = "LOCAL_PATH"
    VCS = "VCS"
    URL = "URL"
    UNRESOLVED = "UNRESOLVED"


class Directness(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class DependencyGroup(StrEnum):
    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    BUILD = "build"
    TEST = "test"
    PEER = "peer"
    UNKNOWN = "unknown"


class LookupStatus(StrEnum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    NO_DATA = "no_data"
    QUERY_FAILED = "query_failed"
    OFFLINE_NO_CACHE = "offline_no_cache"
    UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"
    UNRESOLVED_VERSION = "unresolved_version"


ECOSYSTEMS = frozenset({"PyPI", "npm", "crates.io", "Go"})
_SAFE_NAME = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._/@+-]{0,199}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!~-]{0,99}$")


def normalize_name(ecosystem: str, name: str) -> str | None:
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name) or safe_finding_path(name) != name:
        return None
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        if name.startswith("@") and name.count("/") != 1:
            return None
        return name.lower()
    if ecosystem == "crates.io":
        return name.lower()
    return name


def safe_exact_version(version: str) -> bool:
    return (isinstance(version, str) and bool(_SAFE_VERSION.fullmatch(version))
            and "*" not in version and safe_finding_path(version) == version)


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    ecosystem: str
    name: str
    version: str | None
    version_kind: VersionKind
    directness: Directness
    group: DependencyGroup
    source_path: str
    line: int | None = None
    declared_constraint: str | None = None
    package_source: str = "registry"
    logical_path: str = ""
    source_paths: tuple[str, ...] = ()
    resolved: bool = False
    identity: DependencyIdentity = DependencyIdentity.REGISTRY
    root_editable_candidate: bool = False

    @property
    def key(self) -> tuple[str, str, str] | None:
        if (self.identity is DependencyIdentity.REGISTRY and self.version_kind is VersionKind.EXACT
                and self.version and self.package_source == "registry"):
            return (self.ecosystem, self.name, self.version)
        return None


@dataclass(frozen=True, slots=True)
class DependencyInventory:
    records: tuple[DependencyRecord, ...]
    diagnostics: tuple[str, ...] = ()
    complete: bool = True

    def exact_keys(self) -> tuple[tuple[str, str, str], ...]:
        return tuple(sorted({record.key for record in self.records if record.key is not None}))


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    severity_source: str = "conservative_default"
    cvss_vector: str | None = None
    fixed_versions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    withdrawn: bool = False


@dataclass(frozen=True, slots=True)
class LookupResult:
    key: tuple[str, str, str]
    status: LookupStatus
    vulnerabilities: tuple[Vulnerability, ...] = ()
    stale: bool = False
    diagnostic: str | None = None
    incomplete: bool = False


def reconcile(records: list[DependencyRecord]) -> tuple[DependencyRecord, ...]:
    """Lock exact versions win over declarations in the same project directory."""
    ordered = sorted(records, key=lambda r: (r.ecosystem, r.name, r.source_path, r.logical_path, r.version or ""))
    exact = [r for r in ordered if r.resolved and r.key is not None]
    declarations = [r for r in ordered if not r.resolved or r.key is None]
    result: list[DependencyRecord] = []
    for record in exact:
        folder = record.source_path.rpartition("/")[0]
        matching = [r for r in declarations if r.ecosystem == record.ecosystem and r.name == record.name
                    and r.source_path.rpartition("/")[0] == folder]
        if matching:
            direct = (Directness.DIRECT if record.directness is not Directness.TRANSITIVE
                      and any(r.directness is Directness.DIRECT for r in matching) else record.directness)
            groups = [r.group for r in matching if r.group is not DependencyGroup.UNKNOWN]
            constraint = next((r.declared_constraint for r in matching if r.declared_constraint), None)
            paths = tuple(sorted({record.source_path, *(r.source_path for r in matching)}))
            result.append(replace(record, directness=direct, group=groups[0] if groups else record.group,
                                  declared_constraint=constraint, source_paths=paths))
        else:
            result.append(replace(record, source_paths=(record.source_path,)))
    for record in declarations:
        folder = record.source_path.rpartition("/")[0]
        if not any(r.ecosystem == record.ecosystem and r.name == record.name and
                   r.source_path.rpartition("/")[0] == folder for r in exact):
            result.append(replace(record, source_paths=(record.source_path,)))
    unique: dict[tuple[str, str, str | None, str, str], DependencyRecord] = {}
    for record in result:
        key = (record.ecosystem, record.name, record.version, record.source_path, record.logical_path)
        unique.setdefault(key, record)
    return tuple(sorted(unique.values(), key=lambda r: (r.ecosystem, r.name, r.version or "", r.source_path, r.logical_path)))
