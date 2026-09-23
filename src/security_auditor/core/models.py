"""Data-only, immutable Phase 0 contracts. No target I/O occurs here."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ContentKind(StrEnum):
    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"


class ArtifactKind(StrEnum):
    SOURCE_CODE = "source_code"
    SCRIPT = "script"
    CONFIG = "config"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    LOCKFILE = "lockfile"
    CI_CONFIG = "ci_config"
    CONTAINER_CONFIG = "container_config"
    DOCUMENTATION = "documentation"
    ARCHIVE = "archive"
    BINARY = "binary"
    EXECUTABLE = "executable"
    CERTIFICATE_LIKE = "certificate_like"
    KEY_MATERIAL_LIKE = "key_material_like"
    ENV_FILE = "env_file"
    UNKNOWN = "unknown"


class ScriptKind(StrEnum):
    POWERSHELL = "powershell"
    BATCH = "batch"
    SHELL = "shell"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    OTHER = "other"


class ManifestKind(StrEnum):
    PYTHON = "python"
    NODE = "node"
    RUST = "rust"
    GO = "go"
    DOTNET = "dotnet"
    JAVA = "java"
    RUBY = "ruby"
    PHP = "php"


@dataclass(frozen=True, slots=True)
class ScanTarget:
    root: Path
    display_name: str


@dataclass(frozen=True, slots=True)
class ScanSession:
    id: str
    target: ScanTarget
    profile: ScanProfile
    started_at: datetime
    offline: bool = True


@dataclass(frozen=True, slots=True)
class LanguageInfo:
    language: str | None
    dialect: str | None = None
    detection: str = "unknown"
    confidence: Confidence = Confidence.LOW


@dataclass(frozen=True, slots=True)
class FileIdentity:
    platform: str
    volume_id: int | None
    file_id: int | None
    fallback_key: str | None = None


@dataclass(frozen=True, slots=True)
class FileArtifact:
    path: str  # root-relative POSIX-style path, never a report host path
    size_bytes: int
    kind: ArtifactKind
    language: LanguageInfo
    sha256: str | None = None
    content_kind: ContentKind = ContentKind.UNKNOWN
    script_kind: ScriptKind | None = None
    manifest_kind: ManifestKind | None = None
    identity: FileIdentity | None = None
    basename: str = ""
    suffixes: tuple[str, ...] = ()
    mtime_ns: int | None = None
    encoding: str | None = None
    classification_confidence: Confidence = Confidence.LOW
    is_executable_like: bool = False
    sniffed_bytes: int = 0
    filesystem_type: str = "regular"
    is_reparse_point: bool = False

    @property
    def artifact_kind(self) -> ArtifactKind:
        return self.kind


@dataclass(frozen=True, slots=True)
class ScannerMetadata:
    id: str
    version: str
    name: str
    deterministic: bool
    requires_network: bool = False


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    redacted_snippet: str | None = None
    structured: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class RuleReference:
    id: str
    title: str
    help_uri: str | None = None


@dataclass(frozen=True, slots=True)
class DependencyArtifact:
    ecosystem: str
    name: str
    version: str | None
    manifest_path: str
    direct: bool | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilityReference:
    advisory_id: str
    source: str
    cve: str | None = None
    cvss: str | None = None
    reference_uri: str | None = None


@dataclass(frozen=True, slots=True)
class Remediation:
    recommendation: str
    references: tuple[str, ...] = ()
    proposed_patch_id: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    rule_id: str
    scanner_id: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: Evidence
    rationale: str
    remediation: Remediation
    fingerprint: str
    created_at: datetime
    tool_version: str
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    cvss: str | None = None
    owasp: tuple[str, ...] = ()
    source: str | None = None
    sink: str | None = None
    attack_scenario: str | None = None
    tags: tuple[str, ...] = ()
    rule: RuleReference | None = None
    dependency: DependencyArtifact | None = None
    vulnerability: VulnerabilityReference | None = None


@dataclass(frozen=True, slots=True)
class ScannerResult:
    scanner: ScannerMetadata
    findings: tuple[Finding, ...] = ()
    status: Literal["completed", "partial", "skipped", "failed"] = "completed"
    diagnostics: tuple[str, ...] = ()  # sanitized, no source/secret bytes


@dataclass(frozen=True, slots=True)
class ReportSummary:
    scan_id: str
    profile: ScanProfile
    total_findings: int
    counts_by_severity: tuple[tuple[Severity, int], ...]
    scanner_statuses: tuple[tuple[str, str], ...]
    incomplete: bool = False
