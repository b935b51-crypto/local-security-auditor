"""Conservative exact placeholder and nonliteral-reference checks."""

from __future__ import annotations

import math
import re


_PLACEHOLDER = re.compile(
    r"^(?:your(?:[_-](?:api[_-]?key|token|secret|password))?(?:[_-]here)?|"
    r"change[_-]?me|replace[_-]?me|insert[_-]?(?:key|token|secret)[_-]?here|"
    r"(?:example|sample|dummy|fake|test|placeholder)(?:[_-](?:api[_-]?key|token|secret|password|only))?|"
    r"not[_-]?a[_-]?real[_-]?(?:key|token|secret)|password|secret|token|abc123|"
    r"x{6,}|0{6,}|\*{4,}|<[^>]{1,64}>)$",
    re.IGNORECASE,
)
_REFERENCE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%(?:[A-Za-z_][A-Za-z0-9_]*)%|"
    r"(?:os\.(?:getenv|environ)|process\.env|import\.meta\.env|env\.)\b.*|"
    r"(?:vault|aws-secretsmanager|secret)://[^\s]+)$",
    re.IGNORECASE,
)
_UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.I)
_HASH_LABEL = re.compile(r"\b(?:sha\d*|checksum|digest|integrity|commit|etag|hash)\b", re.I)


def is_placeholder(value: str) -> bool:
    value = value.strip().strip("\"'` ")
    return not value or value.lower() in {"none", "null", "nil", "undefined", "false"} or bool(_PLACEHOLDER.fullmatch(value)) or bool(_REFERENCE.fullmatch(value))


def is_hash_context(line: str) -> bool:
    return bool(_HASH_LABEL.search(line))


def is_uuid(value: str) -> bool:
    return bool(_UUID.fullmatch(value))


def shannon_entropy(value: str) -> float:
    """Only call on bounded candidate values; this is a signal, not a detector."""
    if not value or len(value) > 1024:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
