"""Stable finding identity without a public password hash."""

from __future__ import annotations

import hashlib


def finding_fingerprint(rule_id: str, path: str, line: int, column: int,
                        family: str, label: str) -> str:
    fields = ("secret-finding-v1", rule_id, path, str(line), str(column), family, label)
    canonical = b"".join(len(field.encode("utf-8")).to_bytes(4, "big") + field.encode("utf-8")
                         for field in fields)
    return hashlib.sha256(canonical).hexdigest()
