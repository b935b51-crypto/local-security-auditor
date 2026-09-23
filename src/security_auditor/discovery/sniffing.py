"""Small, bounded prefix inspection. This module never parses or executes code."""

from __future__ import annotations

import codecs
from dataclasses import dataclass

from security_auditor.core.models import Confidence, ContentKind


MAGIC: tuple[tuple[bytes, str, ContentKind], ...] = (
    (b"MZ", "pe", ContentKind.BINARY),
    (b"\x7fELF", "elf", ContentKind.BINARY),
    (b"\xfe\xed\xfa\xce", "mach_o", ContentKind.BINARY),
    (b"\xce\xfa\xed\xfe", "mach_o", ContentKind.BINARY),
    (b"\xfe\xed\xfa\xcf", "mach_o", ContentKind.BINARY),
    (b"\xcf\xfa\xed\xfe", "mach_o", ContentKind.BINARY),
    (b"PK\x03\x04", "zip", ContentKind.BINARY),
    (b"\x1f\x8b", "gzip", ContentKind.BINARY),
    (b"%PDF-", "pdf", ContentKind.BINARY),
    (b"\x89PNG\r\n\x1a\n", "png", ContentKind.BINARY),
    (b"\xff\xd8\xff", "jpeg", ContentKind.BINARY),
)


@dataclass(frozen=True, slots=True)
class SniffResult:
    content_kind: ContentKind
    encoding: str | None
    magic: str | None
    first_line: str | None
    confidence: Confidence
    decode_failed: bool = False
    long_line: bool = False


def _decode_prefix(data: bytes, encoding: str) -> str:
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    return decoder.decode(data, final=False)


def sniff_prefix(data: bytes, *, max_line_length: int) -> SniffResult:
    """Classify only supplied bytes; callers enforce the read and total-byte caps."""
    for signature, name, kind in MAGIC:
        if data.startswith(signature):
            return SniffResult(kind, None, name, None, Confidence.HIGH)
    if not data:
        return SniffResult(ContentKind.TEXT, "utf-8", None, "", Confidence.MEDIUM)

    encoding: str | None = None
    payload = data
    confidence = Confidence.HIGH
    if data.startswith(codecs.BOM_UTF8):
        encoding, payload = "utf-8-sig", data
    elif data.startswith(codecs.BOM_UTF16_LE):
        encoding, payload = "utf-16-le", data[2:]
    elif data.startswith(codecs.BOM_UTF16_BE):
        encoding, payload = "utf-16-be", data[2:]
    elif b"\x00" in data:
        # Only a regular NUL pattern is accepted as BOM-less UTF-16.
        even = data[0::2].count(0)
        odd = data[1::2].count(0)
        if max(even, odd) >= len(data) // 4 and min(even, odd) <= len(data) // 16:
            encoding = "utf-16-le" if odd > even else "utf-16-be"
            confidence = Confidence.MEDIUM
        else:
            return SniffResult(ContentKind.BINARY, None, None, None, Confidence.HIGH)
    else:
        encoding = "utf-8"

    try:
        text = _decode_prefix(payload, encoding)
    except UnicodeError:
        return SniffResult(ContentKind.UNKNOWN, None, None, None, Confidence.LOW, decode_failed=True)

    if text:
        controls = sum(1 for c in text if ord(c) < 32 and c not in "\t\r\n\f")
        if controls / len(text) > 0.05:
            return SniffResult(ContentKind.BINARY, None, None, None, Confidence.MEDIUM)
    first_line = text.split("\n", 1)[0].rstrip("\r")
    too_long = len(first_line) > max_line_length
    return SniffResult(
        ContentKind.TEXT, encoding, None,
        first_line[:max_line_length] if not too_long else None,
        confidence, long_line=too_long,
    )
