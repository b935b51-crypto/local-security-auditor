"""Minimal, bounded Phase 0 configuration schema for trusted operator input."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .models import ScanProfile


HARD_MAX_FILE_SIZE = 32 * 1024 * 1024
HARD_MAX_FILE_COUNT = 250_000
HARD_MAX_DEPTH = 128
HARD_MAX_DIRECTORIES = 100_000
HARD_MAX_ENTRIES = 500_000
HARD_MAX_TOTAL_BYTES = 512 * 1024 * 1024
HARD_MAX_SNIFF_BYTES = 16 * 1024
HARD_MAX_LINE_LENGTH = 64 * 1024
HARD_MAX_ELAPSED_SECONDS = 3600
DEFAULT_MAX_FILE_SIZE = 4 * 1024 * 1024
DEFAULT_MAX_FILE_COUNT = 100_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_DIRECTORIES = 50_000
DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_SNIFF_BYTES = 8 * 1024
DEFAULT_MAX_LINE_LENGTH = 8 * 1024
DEFAULT_MAX_ELAPSED_SECONDS = 300
DEFAULT_EXCLUDE = (
    ".git/", "node_modules/", ".venv/", "venv/", "dist/",
    "build/", "coverage/", "__pycache__/", ".cache/",
)

SECRET_HARD_CAPS = {
    "max_file_bytes": 4 * 1024 * 1024,
    "max_total_bytes": 256 * 1024 * 1024,
    "max_line_bytes": 64 * 1024,
    "max_matches_per_rule_per_file": 1000,
    "max_findings_per_file": 1000,
    "max_findings_total": 10000,
    "max_elapsed_seconds": 3600,
}

SAST_HARD_CAPS = {
    "max_file_bytes": 2 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
    "max_ast_nodes": 50000,
    "max_ast_depth": 200,
    "max_function_nodes": 20000,
    "max_findings_per_file": 1000,
    "max_findings_total": 10000,
    "max_seconds": 3600,
}
BEHAVIOR_HARD_CAPS = {
    "max_file_bytes": 2 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
    "max_line_bytes": 64 * 1024,
    "max_ast_nodes": 50000,
    "max_ast_depth": 200,
    "max_matches_per_file": 1000,
    "max_findings_total": 10000,
    "max_seconds": 3600,
}
DEPENDENCY_HARD_CAPS = {
    "max_file_bytes": 8 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
    "max_entries": 100000,
    "max_dependencies": 100000,
    "max_include_depth": 16,
    "max_seconds": 3600,
}
VULNERABILITY_HARD_CAPS = {
    "max_queries": 5000,
    "max_batch_size": 100,
    "max_response_bytes": 4 * 1024 * 1024,
    "timeout_seconds": 30,
    "max_provider_seconds": 600,
    "max_provider_bytes_total": 64 * 1024 * 1024,
    "cache_ttl_seconds": 30 * 24 * 3600,
    "max_advisories": 10000,
}
CORRELATION_HARD_CAPS = {
    "max_findings": 100000, "max_nodes": 200000, "max_edges": 300000,
    "max_attack_paths": 10000, "max_seconds": 3600,
    "proximity_lines": 20,
}


def _validate_limits(instance: object, caps: dict[str, int]) -> None:
    if type(getattr(instance, "enabled")) is not bool:
        raise ValueError("enabled must be boolean")
    for key, ceiling in caps.items():
        value = getattr(instance, key)
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValueError(f"{key} outside safe range")


@dataclass(frozen=True, slots=True)
class SASTLimits:
    enabled: bool = True
    max_file_bytes: int = 512 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_ast_nodes: int = 10000
    max_ast_depth: int = 100
    max_function_nodes: int = 5000
    max_findings_per_file: int = 100
    max_findings_total: int = 1000
    max_seconds: int = 300

    def __post_init__(self) -> None:
        _validate_limits(self, SAST_HARD_CAPS)


@dataclass(frozen=True, slots=True)
class BehaviorLimits:
    enabled: bool = True
    max_file_bytes: int = 512 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_line_bytes: int = 8 * 1024
    max_ast_nodes: int = 10000
    max_ast_depth: int = 100
    max_matches_per_file: int = 100
    max_findings_total: int = 1000
    max_seconds: int = 300

    def __post_init__(self) -> None:
        _validate_limits(self, BEHAVIOR_HARD_CAPS)


@dataclass(frozen=True, slots=True)
class SecretLimits:
    enabled: bool = True
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_line_bytes: int = 16 * 1024
    max_matches_per_rule_per_file: int = 100
    max_findings_per_file: int = 100
    max_findings_total: int = 1000
    max_elapsed_seconds: int = 300
    enable_entropy: bool = True
    enable_generic_assignment: bool = True

    def __post_init__(self) -> None:
        for key, ceiling in SECRET_HARD_CAPS.items():
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{key} outside safe range")
        for key in ("enabled", "enable_entropy", "enable_generic_assignment"):
            if type(getattr(self, key)) is not bool:
                raise ValueError(f"{key} must be boolean")


@dataclass(frozen=True, slots=True)
class DependencyLimits:
    enabled: bool = True
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_entries: int = 20000
    max_dependencies: int = 20000
    max_include_depth: int = 8
    max_seconds: int = 300

    def __post_init__(self) -> None:
        _validate_limits(self, DEPENDENCY_HARD_CAPS)


@dataclass(frozen=True, slots=True)
class VulnerabilityLimits:
    enabled: bool = True
    provider: str = "osv"
    max_queries: int = 500
    max_batch_size: int = 50
    max_response_bytes: int = 1024 * 1024
    timeout_seconds: int = 10
    max_provider_seconds: int = 120
    max_provider_bytes_total: int = 16 * 1024 * 1024
    cache_enabled: bool = True
    cache_ttl_seconds: int = 86400
    max_advisories: int = 100

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(self.cache_enabled) is not bool:
            raise ValueError("vulnerability flags must be boolean")
        if self.provider != "osv":
            raise ValueError("unsupported vulnerability provider")
        for key, ceiling in VULNERABILITY_HARD_CAPS.items():
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{key} outside safe range")


@dataclass(frozen=True, slots=True)
class CorrelationLimits:
    enabled: bool = True
    max_findings: int = 10000
    max_nodes: int = 20000
    max_edges: int = 30000
    max_attack_paths: int = 1000
    max_seconds: int = 300
    proximity_lines: int = 5

    def __post_init__(self) -> None:
        _validate_limits(self, CORRELATION_HARD_CAPS)


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_directory_depth: int = DEFAULT_MAX_DEPTH
    max_directories: int = DEFAULT_MAX_DIRECTORIES
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_total_bytes_inspected: int = DEFAULT_MAX_TOTAL_BYTES
    max_sniff_bytes: int = DEFAULT_MAX_SNIFF_BYTES
    max_single_text_read: int = DEFAULT_MAX_SNIFF_BYTES
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    max_elapsed_seconds: int = DEFAULT_MAX_ELAPSED_SECONDS


@dataclass(frozen=True, slots=True)
class AuditConfig:
    profile: ScanProfile = ScanProfile.STANDARD
    offline: bool = True
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()  # security-scan excludes, separate from defaults
    default_exclude: tuple[str, ...] = DEFAULT_EXCLUDE
    respect_gitignore: bool = False
    follow_symlinks: bool = False
    follow_reparse_points: bool = False
    limits: DiscoveryLimits = DiscoveryLimits()
    secrets: SecretLimits = SecretLimits()
    sast: SASTLimits = SASTLimits()
    behavior: BehaviorLimits = BehaviorLimits()
    dependencies: DependencyLimits = DependencyLimits()
    vulnerability: VulnerabilityLimits = VulnerabilityLimits()
    correlation: CorrelationLimits = CorrelationLimits()


def load_config(path: Path) -> AuditConfig:
    """Load operator-selected TOML; rejects unknown keys and unsafe limit increases."""
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    if set(raw) - {"scan", "discovery", "secrets", "sast", "behavior", "dependencies", "vulnerability", "correlation"}:
        raise ValueError("unknown top-level config key")
    scan = raw.get("scan", {})
    discovery = raw.get("discovery", {})
    secrets = raw.get("secrets", {})
    sast = raw.get("sast", {})
    behavior = raw.get("behavior", {})
    dependencies = raw.get("dependencies", {})
    vulnerability = raw.get("vulnerability", {})
    correlation = raw.get("correlation", {})
    if any(not isinstance(table, dict) for table in (scan, discovery, secrets, sast, behavior, dependencies, vulnerability, correlation)):
        raise ValueError("invalid config table")
    if set(scan) - {"profile", "offline"} or set(discovery) - {
        "include", "exclude", "default_exclude", "respect_gitignore",
        "follow_symlinks", "follow_reparse_points", "max_file_size_bytes",
        "max_file_count", "max_directory_depth", "max_directories",
        "max_entries", "max_total_bytes_inspected", "max_sniff_bytes",
        "max_single_text_read", "max_line_length", "max_elapsed_seconds",
    }:
        raise ValueError("unknown config key")
    if set(secrets) - set(SECRET_HARD_CAPS) - {
        "enabled", "enable_entropy", "enable_generic_assignment",
    }:
        raise ValueError("unknown secrets config key")
    if set(sast) - set(SAST_HARD_CAPS) - {"enabled"}:
        raise ValueError("unknown sast config key")
    if set(behavior) - set(BEHAVIOR_HARD_CAPS) - {"enabled"}:
        raise ValueError("unknown behavior config key")
    if set(dependencies) - set(DEPENDENCY_HARD_CAPS) - {"enabled"}:
        raise ValueError("unknown dependencies config key")
    if set(vulnerability) - set(VULNERABILITY_HARD_CAPS) - {"enabled", "provider", "cache_enabled"}:
        raise ValueError("unknown vulnerability config key")
    if set(correlation) - set(CORRELATION_HARD_CAPS) - {"enabled"}:
        raise ValueError("unknown correlation config key")
    profile = ScanProfile(scan.get("profile", "standard"))
    offline = scan.get("offline", True)
    respect_gitignore = discovery.get("respect_gitignore", False)
    if type(offline) is not bool or type(respect_gitignore) is not bool:
        raise ValueError("invalid boolean config value")
    for key in ("follow_symlinks", "follow_reparse_points"):
        if discovery.get(key, False) is not False:
            raise ValueError(f"{key} is unavailable in Phase 1")
    values = {}
    for key, hard_max, default in (
        ("max_file_size_bytes", HARD_MAX_FILE_SIZE, DEFAULT_MAX_FILE_SIZE),
        ("max_file_count", HARD_MAX_FILE_COUNT, DEFAULT_MAX_FILE_COUNT),
        ("max_directory_depth", HARD_MAX_DEPTH, DEFAULT_MAX_DEPTH),
        ("max_directories", HARD_MAX_DIRECTORIES, DEFAULT_MAX_DIRECTORIES),
        ("max_entries", HARD_MAX_ENTRIES, DEFAULT_MAX_ENTRIES),
        ("max_total_bytes_inspected", HARD_MAX_TOTAL_BYTES, DEFAULT_MAX_TOTAL_BYTES),
        ("max_sniff_bytes", HARD_MAX_SNIFF_BYTES, DEFAULT_MAX_SNIFF_BYTES),
        ("max_single_text_read", HARD_MAX_SNIFF_BYTES, DEFAULT_MAX_SNIFF_BYTES),
        ("max_line_length", HARD_MAX_LINE_LENGTH, DEFAULT_MAX_LINE_LENGTH),
        ("max_elapsed_seconds", HARD_MAX_ELAPSED_SECONDS, DEFAULT_MAX_ELAPSED_SECONDS),
    ):
        value = discovery.get(key, default)
        if type(value) is not int or not 1 <= value <= hard_max:
            raise ValueError(f"{key} outside safe range")
        values[key] = value
    patterns = {}
    for key, default in (("include", ()), ("exclude", ()), ("default_exclude", DEFAULT_EXCLUDE)):
        value = discovery.get(key, default)
        if not isinstance(value, list | tuple) or any(
            not isinstance(item, str) or not item or "\x00" in item or
            item.replace("\\", "/").startswith("/") or
            ":" in item or ".." in item.replace("\\", "/").split("/")
            for item in value
        ):
            raise ValueError(f"invalid {key} patterns")
        patterns[key] = tuple(value)
    secret_values = {key: secrets.get(key, getattr(SecretLimits(), key))
                     for key in SecretLimits.__dataclass_fields__}
    sast_defaults = SASTLimits()
    sast_values = {key: sast.get(key, getattr(sast_defaults, key))
                   for key in SASTLimits.__dataclass_fields__}
    behavior_defaults = BehaviorLimits()
    behavior_values = {key: behavior.get(key, getattr(behavior_defaults, key))
                       for key in BehaviorLimits.__dataclass_fields__}
    dependency_defaults = DependencyLimits()
    dependency_values = {key: dependencies.get(key, getattr(dependency_defaults, key))
                         for key in DependencyLimits.__dataclass_fields__}
    vulnerability_defaults = VulnerabilityLimits()
    vulnerability_values = {key: vulnerability.get(key, getattr(vulnerability_defaults, key))
                            for key in VulnerabilityLimits.__dataclass_fields__}
    correlation_defaults = CorrelationLimits()
    correlation_values = {key: correlation.get(key, getattr(correlation_defaults, key))
                          for key in CorrelationLimits.__dataclass_fields__}
    return AuditConfig(
        profile=profile, offline=offline, respect_gitignore=respect_gitignore,
        limits=DiscoveryLimits(**values), secrets=SecretLimits(**secret_values),
        sast=SASTLimits(**sast_values), behavior=BehaviorLimits(**behavior_values),
        dependencies=DependencyLimits(**dependency_values),
        vulnerability=VulnerabilityLimits(**vulnerability_values),
        correlation=CorrelationLimits(**correlation_values), **patterns,
    )
