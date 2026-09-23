"""Public, immutable remediation records. Never store raw source or credentials."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from security_auditor.core.models import Confidence


class RemediationStrategy(StrEnum):
    GUIDANCE_ONLY = "GUIDANCE_ONLY"
    DETERMINISTIC = "DETERMINISTIC"
    AI_ASSISTED = "AI_ASSISTED"


class ProposalStatus(StrEnum):
    GUIDANCE_ONLY = "GUIDANCE_ONLY"
    VALIDATED_STATICALLY = "VALIDATED_STATICALLY"
    PARTIAL_VALIDATION = "PARTIAL_VALIDATION"
    REJECTED = "REJECTED"


class SyntaxStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class PatchValidationResult:
    applies_cleanly: bool
    source_fresh: bool
    scope_valid: bool
    syntax_status: SyntaxStatus
    target_finding_before: bool
    target_finding_after: bool | None
    target_finding_removed: bool
    new_findings: tuple[str, ...] = ()  # rule IDs only
    new_high_findings: tuple[str, ...] = ()
    existing_findings_removed: tuple[str, ...] = ()
    existing_findings_changed: tuple[str, ...] = ()
    static_validation_status: ProposalStatus = ProposalStatus.REJECTED
    runtime_tests_status: str = "NOT_RUN"
    limitations: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PatchCandidate:
    patch_id: str
    finding_id: str
    strategy: RemediationStrategy
    target_relative_path: str
    original_fingerprint: str
    proposed_content_fingerprint: str
    unified_diff: str  # public redacted display only; not an apply artifact
    changed_hunks: int
    changed_line_count: int
    provenance: str
    generated_by: str
    generated_at: str
    human_approval_required: bool = True
    patch_confidence: Confidence = Confidence.LOW
    provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None


@dataclass(frozen=True, slots=True)
class RemediationProposal:
    proposal_id: str
    finding_id: str
    strategy: RemediationStrategy
    status: ProposalStatus
    title: str
    summary: str
    rationale: str
    preconditions: tuple[str, ...]
    remediation_steps: tuple[str, ...]
    external_actions_required: tuple[str, ...]
    patch_candidate: PatchCandidate | None = None
    validation_result: PatchValidationResult | None = None
    limitations: tuple[str, ...] = ()
    human_approval_required: bool = True
    provenance: str = "DETERMINISTIC_RULE"
    assumptions: tuple[str, ...] = ()
    provider_reported_fixed_versions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RemediationBatch:
    proposals: tuple[RemediationProposal, ...] = ()
    diagnostics: tuple[str, ...] = ()
    candidates_considered: int = 0
    ai_requests: int = 0
