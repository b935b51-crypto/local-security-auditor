"""Trusted default scan scope; target content never supplies these rules."""

from __future__ import annotations

from enum import StrEnum


class ScopeClass(StrEnum):
    FIRST_PARTY = "FIRST_PARTY"
    GENERATED = "GENERATED"
    CACHE = "CACHE"
    ENVIRONMENT = "ENVIRONMENT"
    DEPENDENCY_VENDOR = "DEPENDENCY_VENDOR"
    BUILD_OUTPUT = "BUILD_OUTPUT"
    UNKNOWN = "UNKNOWN"


class ExclusionReason(StrEnum):
    EXCLUDED_DEFAULT_CACHE = "EXCLUDED_DEFAULT_CACHE"
    EXCLUDED_DEFAULT_ENVIRONMENT = "EXCLUDED_DEFAULT_ENVIRONMENT"
    EXCLUDED_DEFAULT_VENDOR = "EXCLUDED_DEFAULT_VENDOR"
    EXCLUDED_DEFAULT_BUILD = "EXCLUDED_DEFAULT_BUILD"
    EXCLUDED_DEFAULT_GENERATED = "EXCLUDED_DEFAULT_GENERATED"
    EXCLUDED_DEFAULT_POLICY = "EXCLUDED_DEFAULT_POLICY"
    EXCLUDED_USER_POLICY = "EXCLUDED_USER_POLICY"


DEFAULT_SCOPE_DIRECTORIES: dict[ScopeClass, tuple[str, ...]] = {
    ScopeClass.CACHE: (
        ".uv-cache", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ".pyright", ".pyre", "__pycache__", ".cache", ".tox", ".nox",
    ),
    ScopeClass.ENVIRONMENT: (".venv", "venv", "env"),
    ScopeClass.DEPENDENCY_VENDOR: ("node_modules",),
    ScopeClass.BUILD_OUTPUT: (
        "dist", "build", "out", "target", ".next", ".nuxt",
        ".svelte-kit", "coverage", "htmlcov",
    ),
    ScopeClass.GENERATED: (".git", ".hg", ".svn"),
}

DEFAULT_SCOPE_FILES: dict[ScopeClass, tuple[str, ...]] = {
    ScopeClass.GENERATED: (".coverage", "coverage.xml", "*.tsbuildinfo"),
}

DEFAULT_EXCLUDE = tuple(
    f"{name}/" for names in DEFAULT_SCOPE_DIRECTORIES.values() for name in names
) + tuple(name for names in DEFAULT_SCOPE_FILES.values() for name in names)


_CLASS_REASON = {
    ScopeClass.CACHE: ExclusionReason.EXCLUDED_DEFAULT_CACHE,
    ScopeClass.ENVIRONMENT: ExclusionReason.EXCLUDED_DEFAULT_ENVIRONMENT,
    ScopeClass.DEPENDENCY_VENDOR: ExclusionReason.EXCLUDED_DEFAULT_VENDOR,
    ScopeClass.BUILD_OUTPUT: ExclusionReason.EXCLUDED_DEFAULT_BUILD,
    ScopeClass.GENERATED: ExclusionReason.EXCLUDED_DEFAULT_GENERATED,
}


def classify_default_pattern(pattern: str) -> tuple[ScopeClass, ExclusionReason]:
    name = pattern.replace("\\", "/").rstrip("/").split("/")[-1].casefold()
    for scope_class, names in (*DEFAULT_SCOPE_DIRECTORIES.items(), *DEFAULT_SCOPE_FILES.items()):
        if name in names:
            return scope_class, _CLASS_REASON[scope_class]
    return ScopeClass.UNKNOWN, ExclusionReason.EXCLUDED_DEFAULT_POLICY
