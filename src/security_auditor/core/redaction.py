"""Shared display-safe path redaction without scanner dependencies."""

from __future__ import annotations

import re
import unicodedata


_PATH_TOKENS = tuple(re.compile(pattern) for pattern in (
    r"gh[pousr]_[A-Za-z0-9]{36}", r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    r"sk_(?:live|test)_[A-Za-z0-9]{24,128}",
    r"xox[baprs]-[A-Za-z0-9-]{20,128}", r"glpat-[A-Za-z0-9_-]{20,128}",
))
_PATH_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(password|token|secret|api[_-]?key|credential)([=_:-])[^/\\]{4,}"
)


def safe_display(value: str) -> str:
    """Keep useful Unicode while escaping terminal controls and bidi format chars."""
    parts: list[str] = []
    for char in value:
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            parts.append(char.encode("unicode_escape").decode("ascii"))
        else:
            parts.append(char)
    return "".join(parts)


def safe_finding_path(path: str) -> str:
    result = safe_display(path)
    for pattern in _PATH_TOKENS:
        result = pattern.sub("[REDACTED]", result)
    return _PATH_CREDENTIAL_ASSIGNMENT.sub(
        lambda match: match.group(1) + match.group(2) + "[REDACTED]", result)
