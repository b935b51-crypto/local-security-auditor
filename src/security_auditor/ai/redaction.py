"""Second egress boundary for review context and provider output."""

from __future__ import annotations

import re

from security_auditor.core.redaction import safe_display


_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_AUTH = re.compile(r"(?im)\b(Authorization\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s,;\"']+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|credential|client[_-]?secret)"
    r"\s*[:=]\s*['\"]?[^'\"\s,;]{4,}"
)
_PROVIDER_TOKEN = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{36}|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{24,128}|xox[baprs]-[A-Za-z0-9-]{20,128}|"
    r"glpat-[A-Za-z0-9_-]{20,128}"
)
_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>]{1,2048}")
_QUOTED = re.compile(r"(['\"])(?:(?!\1).){8,}?\1")
_OPAQUE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{24,}(?![A-Za-z0-9+/=])")


def redact_text(value: str, *, source: bool = False) -> str:
    """Fail closed on control characters; erase credential shapes and source literals."""
    value = safe_display(value)
    value = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
    value = _URL.sub("[REDACTED URL]", value)
    value = _AUTH.sub(lambda m: m.group(1) + "[REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _PROVIDER_TOKEN.sub("[REDACTED TOKEN]", value)
    value = _ASSIGNMENT.sub(lambda m: m.group(1) + "=[REDACTED]", value)
    if source:
        # Literal contents and comments are unnecessary for v1 review.
        value = value.split("#", 1)[0]
        value = _QUOTED.sub("[REDACTED LITERAL]", value)
        value = _OPAQUE.sub("[REDACTED OPAQUE VALUE]", value)
    return value


def safe_output(value: str, *, limit: int) -> str:
    return redact_text(value[:limit])[:limit]
