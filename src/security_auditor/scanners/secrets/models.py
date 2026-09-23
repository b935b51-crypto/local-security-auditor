"""Raw-free internal secret candidates."""

from __future__ import annotations

from dataclasses import dataclass

from security_auditor.core.models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class SecretCandidate:
    rule_id: str
    family: str
    start: int  # zero-based character offset in the current line
    end: int
    severity: Severity
    confidence: Confidence
    priority: int
    preview: str
    value_length: int
    label: str = ""

    def overlaps(self, other: SecretCandidate) -> bool:
        return self.start < other.end and other.start < self.end
