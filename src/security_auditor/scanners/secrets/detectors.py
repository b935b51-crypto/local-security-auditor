"""Bounded, deterministic native detectors. Each returns raw-free candidates."""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import PurePosixPath

from security_auditor.core.models import Confidence, Severity
from .models import SecretCandidate
from .placeholders import is_hash_context, is_placeholder, is_uuid, shannon_entropy
from .redaction import redacted_preview


PRIVATE_BEGIN = re.compile(r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----")
PRIVATE_END = re.compile(r"-----END (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----")
PROVIDERS: tuple[tuple[str, str, re.Pattern[str], Severity, Confidence], ...] = (
    ("SECRET.GITHUB.TOKEN", "github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), Severity.HIGH, Confidence.HIGH),
    ("SECRET.AWS.ACCESS_KEY", "aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), Severity.LOW, Confidence.MEDIUM),
    ("SECRET.STRIPE.SECRET_KEY", "stripe", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,128}\b"), Severity.HIGH, Confidence.HIGH),
    ("SECRET.SLACK.TOKEN", "slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,128}\b"), Severity.HIGH, Confidence.HIGH),
    ("SECRET.GITLAB.TOKEN", "gitlab", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,128}\b"), Severity.HIGH, Confidence.HIGH),
)
CONNECTION = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
    r"(?P<user>[^\s:@/]{1,128}):(?P<password>[^\s@/]{1,256})@",
    re.I,
)
ASSIGNMENT = re.compile(
    r"(?<![\w-])(?P<key>aws_secret_access_key|api[_-]?key|api[_-]?token|"
    r"client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|"
    r"private[_-]?key|connection[_-]?string|secret|token)"
    r"[\"']?\s*(?::|=)\s*(?P<value>\"[^\"\r\n]{0,256}\"|'[^'\r\n]{0,256}'|[^\s,;#]{0,256})",
    re.I,
)
JWT = re.compile(r"\b[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}\b")
ENTROPY_VALUE = re.compile(r"(?<![\w])(?P<value>[A-Za-z0-9_-]{20,128})(?![\w])")
SECRET_CONTEXT = re.compile(r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret|token|bearer)\b", re.I)
_SECURE_GENERATOR = re.compile(r"secrets\.(?:token_urlsafe|token_hex|token_bytes)\((?:[0-9]{1,3})?\)")
_SYNTHETIC_TEST_VALUE = re.compile(
    r"(?:fake|dummy|synthetic|invalid|sample|example|test)[_-][A-Za-z0-9_-]{1,63}|"
    r"not[_-]a[_-][A-Za-z0-9_-]{1,63}|do[_-]not[_-]echo", re.I,
)


def test_context_path(path: str) -> bool:
    parts = PurePosixPath(path.replace("\\", "/")).parts
    name = parts[-1].casefold() if parts else ""
    return any(part.casefold() in {"test", "tests"} for part in parts[:-1]) or (
        name.startswith("test_") or name.endswith("_test.py")
    )


def private_key(line: str) -> tuple[list[SecretCandidate], bool]:
    match = PRIVATE_BEGIN.search(line)
    if match is None:
        return [], False
    candidate = SecretCandidate(
        "SECRET.PRIVATE_KEY.PEM", "private_key", match.start(), match.end(),
        Severity.HIGH, Confidence.HIGH, 0, redacted_preview("private_key"), 0,
        "private_key_block",
    )
    return [candidate], not bool(PRIVATE_END.search(line, match.end()))


def provider(line: str) -> tuple[list[SecretCandidate], int]:
    result: list[SecretCandidate] = []
    suppressed = 0
    for rule_id, family, pattern, severity, confidence in PROVIDERS:
        for match in pattern.finditer(line):
            value = match.group()
            if is_placeholder(value):
                suppressed += 1
                continue
            result.append(SecretCandidate(rule_id, family, match.start(), match.end(),
                                          severity, confidence, 1, redacted_preview(family), len(value)))
    return result, suppressed


def connection_string(line: str) -> tuple[list[SecretCandidate], int]:
    result: list[SecretCandidate] = []
    suppressed = 0
    for match in CONNECTION.finditer(line):
        password = match.group("password")
        if is_placeholder(password):
            suppressed += 1
            continue
        result.append(SecretCandidate(
            "SECRET.CONNECTION_STRING", "connection_string", *match.span("password"),
            Severity.HIGH, Confidence.HIGH, 2, redacted_preview("password"), len(password),
            match.group("scheme").lower(),
        ))
    return result, suppressed


def _literal(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def assignment(line: str, *, trusted_generated: bool = False,
               test_context: bool = False) -> tuple[list[SecretCandidate], int]:
    result: list[SecretCandidate] = []
    suppressed = 0
    if is_hash_context(line):
        return result, suppressed
    for match in ASSIGNMENT.finditer(line):
        raw_value = match.group("value")
        value = _literal(raw_value)
        key = match.group("key").lower().replace("-", "_")
        if trusted_generated and raw_value == value and _SECURE_GENERATOR.fullmatch(value):
            suppressed += 1
            continue
        if (test_context and value.islower() and not any(char.isdigit() for char in value)
                and _SYNTHETIC_TEST_VALUE.fullmatch(value)):
            suppressed += 1
            continue
        if is_placeholder(value) or is_uuid(value) or value.startswith(("os.getenv(", "os.environ[", "process.env.", "env.")):
            suppressed += 1
            continue
        if not value or len(value) > 256:
            continue
        entropy = shannon_entropy(value)
        classes = sum((any(c.islower() for c in value), any(c.isupper() for c in value),
                       any(c.isdigit() for c in value), any(c in "_-+/=" for c in value)))
        if len(value) < 8 or classes < 2:
            continue
        strong = len(value) >= 16 and entropy >= 3.2 and classes >= 3
        if not strong and key not in {"password", "passwd", "aws_secret_access_key", "client_secret"}:
            continue
        confidence = Confidence.HIGH if strong and key == "aws_secret_access_key" else Confidence.MEDIUM if strong else Confidence.LOW
        severity = Severity.HIGH if key == "aws_secret_access_key" and strong else Severity.MEDIUM
        if re.search(r"\b(?:example|sample|placeholder|documentation)\b", line, re.I):
            confidence = Confidence.LOW
        span_start, span_end = match.span("value")
        if len(match.group("value")) >= 2 and match.group("value")[0] in "\"'":
            span_start += 1
            span_end -= 1
        result.append(SecretCandidate(
            "SECRET.GENERIC.ASSIGNMENT", "password" if key in {"password", "passwd"} else "assignment",
            span_start, span_end, severity, confidence, 4,
            redacted_preview("password" if key in {"password", "passwd"} else "assignment"), len(value), key,
        ))
    return result, suppressed


def _json_segment(segment: str) -> bool:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return len(raw) <= 1024 and isinstance(json.loads(raw), dict)
    except (binascii.Error, UnicodeError, ValueError):
        return False


def jwt(line: str) -> tuple[list[SecretCandidate], int]:
    result: list[SecretCandidate] = []
    suppressed = 0
    for match in JWT.finditer(line):
        value = match.group()
        header, payload, _signature = value.split(".")
        if not _json_segment(header) or not _json_segment(payload):
            continue
        if is_placeholder(value):
            suppressed += 1
            continue
        result.append(SecretCandidate(
            "SECRET.JWT", "jwt", match.start(), match.end(), Severity.MEDIUM,
            Confidence.MEDIUM, 3, redacted_preview("jwt"), len(value),
        ))
    return result, suppressed


def entropy_context(line: str) -> tuple[list[SecretCandidate], int]:
    if not SECRET_CONTEXT.search(line) or is_hash_context(line):
        return [], 0
    result: list[SecretCandidate] = []
    suppressed = 0
    for match in ENTROPY_VALUE.finditer(line):
        value = match.group("value")
        if not SECRET_CONTEXT.search(line[max(0, match.start() - 40):match.start()]):
            continue
        if is_placeholder(value) or is_uuid(value):
            suppressed += 1
            continue
        if shannon_entropy(value) < 3.5:
            continue
        result.append(SecretCandidate(
            "SECRET.GENERIC.ENTROPY", "entropy", match.start(), match.end(),
            Severity.LOW, Confidence.LOW, 5, redacted_preview("entropy"), len(value),
        ))
    return result, suppressed
