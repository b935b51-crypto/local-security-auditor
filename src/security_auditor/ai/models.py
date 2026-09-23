"""Immutable AI annotations; no field changes a deterministic Finding."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from security_auditor.core.models import Confidence


class AIVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY_VALID = "LIKELY_VALID"
    UNCERTAIN = "UNCERTAIN"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


class SubjectType(StrEnum):
    FINDING = "finding"
    FINDING_GROUP = "finding_group"
    ATTACK_PATH = "attack_path_candidate"
    RISK_ASSESSMENT = "risk_assessment"


class ContextStatus(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class AIReviewStatus(StrEnum):
    DISABLED = "disabled"
    COMPLETE = "complete"
    PARTIAL = "partial"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ReviewSubject:
    kind: SubjectType
    id: str
    priority_rank: int


@dataclass(frozen=True, slots=True)
class ReviewContext:
    subject: ReviewSubject
    serialized: str  # bounded, redacted JSON; never log or persist by default
    status: ContextStatus
    fingerprint: str  # hash of already redacted serialized context
    estimated_tokens: int


@dataclass(frozen=True, slots=True)
class AIUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class AIReviewResult:
    review_id: str
    provider: str
    model: str
    subject_type: SubjectType
    subject_id: str
    verdict: AIVerdict
    confidence: Confidence
    summary: str
    rationale: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    contradictory_evidence: tuple[str, ...]
    missing_context: tuple[str, ...]
    remediation: tuple[str, ...]
    limitations: tuple[str, ...]
    prompt_version: str
    response_schema_version: str
    created_at: datetime
    usage: AIUsage
    context_status: ContextStatus
    review_input_fingerprint: str
    provider_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class AIDiagnostic:
    code: str
    count: int = 1


@dataclass(frozen=True, slots=True)
class AIReviewSummary:
    status: AIReviewStatus
    selected: int
    completed: int
    requests: int
    estimated_input_tokens: int
    output_tokens: int
    diagnostics: tuple[AIDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class AIReviewBatch:
    reviews: tuple[AIReviewResult, ...]
    summary: AIReviewSummary
