"""Shared bounded-result helpers. Never accept source snippets as evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re

from security_auditor import __version__
from security_auditor.core.models import (
    Confidence, Evidence, Finding, Location, Remediation, RuleReference,
    ScannerDiagnostic, Severity,
)
from security_auditor.discovery.path_safety import safe_display


_PATH_TOKENS = tuple(re.compile(pattern) for pattern in (
    r"gh[pousr]_[A-Za-z0-9]{36}", r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    r"sk_(?:live|test)_[A-Za-z0-9]{24,128}",
    r"xox[baprs]-[A-Za-z0-9-]{20,128}", r"glpat-[A-Za-z0-9_-]{20,128}",
))
_PATH_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(password|token|secret|api[_-]?key|credential)([=_:-])[^/\\]{4,}"
)


@dataclass(frozen=True, slots=True)
class StaticRule:
    id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    rationale: str
    remediation: str
    cwe: str | None = None
    tags: tuple[str, ...] = ()

    def reference(self) -> RuleReference:
        return RuleReference(self.id, self.title,
                             f"https://cwe.mitre.org/data/definitions/{self.cwe.removeprefix('CWE-')}.html"
                             if self.cwe else None)


def safe_finding_path(path: str) -> str:
    result = safe_display(path)
    for pattern in _PATH_TOKENS:
        result = pattern.sub("[REDACTED]", result)
    result = _PATH_CREDENTIAL_ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + "[REDACTED]", result)
    return result


def make_finding(rule: StaticRule, scanner_id: str, path: str, line: int, column: int,
                 *, anchor: str, evidence: tuple[tuple[str, str], ...] = (),
                 source: str | None = None, sink: str | None = None,
                 confidence: Confidence | None = None,
                 severity: Severity | None = None) -> Finding:
    """Call with fixed rule labels and safe metadata only, never target text."""
    safe_path = safe_finding_path(path)
    fields = ("static-finding-v1", rule.id, safe_path, str(line), str(column), anchor)
    canonical = b"".join(len(item.encode("utf-8")).to_bytes(4, "big") + item.encode("utf-8")
                         for item in fields)
    fingerprint = hashlib.sha256(canonical).hexdigest()
    return Finding(
        id=fingerprint[:16], rule_id=rule.id, scanner_id=scanner_id,
        category=rule.category, title=rule.title, description=rule.description,
        severity=severity or rule.severity, confidence=confidence or rule.confidence,
        location=Location(safe_path, line, column),
        evidence=Evidence("static_structure", "[REDACTED SOURCE CONTEXT]", evidence),
        rationale=rule.rationale, remediation=Remediation(rule.remediation),
        fingerprint=fingerprint, created_at=datetime.now(timezone.utc),
        tool_version=__version__, cwe=(rule.cwe,) if rule.cwe else (),
        source=source, sink=sink, tags=rule.tags, rule=rule.reference(),
    )


def diagnostic(code: str, message: str) -> ScannerDiagnostic:
    return ScannerDiagnostic(code, message)
