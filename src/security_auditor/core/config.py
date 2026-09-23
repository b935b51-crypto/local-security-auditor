"""Minimal, bounded Phase 0 configuration schema for trusted operator input."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .models import ScanProfile


HARD_MAX_FILE_SIZE = 32 * 1024 * 1024
HARD_MAX_FILE_COUNT = 250_000
HARD_MAX_DEPTH = 128
DEFAULT_MAX_FILE_SIZE = 4 * 1024 * 1024
DEFAULT_MAX_FILE_COUNT = 100_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_EXCLUDE = (
    ".git/**", "node_modules/**", ".venv/**", "venv/**",
    "dist/**", "build/**", "coverage/**", "**/__pycache__/**",
)


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_directory_depth: int = DEFAULT_MAX_DEPTH


@dataclass(frozen=True, slots=True)
class AuditConfig:
    profile: ScanProfile = ScanProfile.STANDARD
    offline: bool = True
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = DEFAULT_EXCLUDE
    respect_gitignore: bool = False
    limits: DiscoveryLimits = DiscoveryLimits()


def load_config(path: Path) -> AuditConfig:
    """Load operator-selected TOML; rejects unknown keys and unsafe limit increases."""
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    if set(raw) - {"scan", "discovery"}:
        raise ValueError("unknown top-level config key")
    scan = raw.get("scan", {})
    discovery = raw.get("discovery", {})
    if not isinstance(scan, dict) or not isinstance(discovery, dict):
        raise ValueError("invalid config table")
    if set(scan) - {"profile", "offline"} or set(discovery) - {
        "include", "exclude", "respect_gitignore", "max_file_size_bytes",
        "max_file_count", "max_directory_depth",
    }:
        raise ValueError("unknown config key")
    profile = ScanProfile(scan.get("profile", "standard"))
    offline = scan.get("offline", True)
    respect_gitignore = discovery.get("respect_gitignore", False)
    if type(offline) is not bool or type(respect_gitignore) is not bool:
        raise ValueError("invalid boolean config value")
    values = {}
    for key, hard_max, default in (
        ("max_file_size_bytes", HARD_MAX_FILE_SIZE, DEFAULT_MAX_FILE_SIZE),
        ("max_file_count", HARD_MAX_FILE_COUNT, DEFAULT_MAX_FILE_COUNT),
        ("max_directory_depth", HARD_MAX_DEPTH, DEFAULT_MAX_DEPTH),
    ):
        value = discovery.get(key, default)
        if type(value) is not int or not 1 <= value <= hard_max:
            raise ValueError(f"{key} outside safe range")
        values[key] = value
    patterns = {}
    for key, default in (("include", ()), ("exclude", DEFAULT_EXCLUDE)):
        value = discovery.get(key, default)
        if not isinstance(value, list | tuple) or any(
            not isinstance(item, str) or not item or "\x00" in item for item in value
        ):
            raise ValueError(f"invalid {key} patterns")
        patterns[key] = tuple(value)
    return AuditConfig(
        profile=profile, offline=offline, respect_gitignore=respect_gitignore,
        limits=DiscoveryLimits(**values), **patterns,
    )
