"""Safe behavior signals; transient correlation targets are repr-hidden."""

from __future__ import annotations

from dataclasses import dataclass, field
from security_auditor.core.models import Confidence


@dataclass(frozen=True, slots=True)
class BehaviorHit:
    rule_id: str
    line: int
    column: int
    detail: str  # fixed vocabulary only
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class LocalCorrelation:
    downloaded_names: set[str] = field(default_factory=set, repr=False)
    written_paths: set[str] = field(default_factory=set, repr=False)
