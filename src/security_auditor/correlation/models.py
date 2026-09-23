"""Immutable public correlation contracts. No scanner or target I/O."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from security_auditor.core.models import Confidence, Finding, Severity


class Completeness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    ABORTED = "aborted"
    FAILED = "failed"


class NodeType(StrEnum):
    FINDING = "finding"
    FILE = "file"
    FUNCTION = "function"
    DEPENDENCY = "dependency"
    VULNERABILITY = "vulnerability"
    BEHAVIOR = "behavior"
    SECRET = "secret"
    SOURCE = "source"
    SINK = "sink"


class RelationshipType(StrEnum):
    SAME_FILE = "same_file"
    SAME_FUNCTION = "same_function"
    SAME_LOCATION = "same_location"
    SAME_SPAN = "same_span"
    SAME_SINK = "same_sink"
    SAME_SOURCE = "same_source"
    SAME_DEPENDENCY = "same_dependency"
    SAME_VULNERABILITY = "same_vulnerability"
    SUPPORTS = "supports"
    CORROBORATES = "corroborates"
    OVERLAPS = "overlaps"
    DUPLICATE_SIGNAL = "duplicate_signal"
    RELATED_BEHAVIOR = "related_behavior"
    RELATED_VULNERABILITY = "related_vulnerability"
    SOURCE_TO_SINK = "source_to_sink"
    POSSIBLE_SEQUENCE = "possible_sequence"
    POSSIBLE_DEPENDENCY_USE = "possible_dependency_use"
    POSSIBLE_ATTACK_PATH = "possible_attack_path"


class FindingRole(StrEnum):
    PRIMARY = "primary"
    SUPPORTING = "supporting"
    CONTEXTUAL = "contextual"
    DUPLICATE = "duplicate"


class EvidenceStrength(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class ExposureSignal(StrEnum):
    UNKNOWN = "unknown"
    EXTERNAL_INPUT = "external_input"
    NETWORK_CONTEXT = "network_context"


class RiskPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DependencyRelevance(StrEnum):
    UNKNOWN = "unknown"
    PRESENT = "present"
    REFERENCED = "referenced"


@dataclass(frozen=True, slots=True)
class RiskNode:
    id: str
    kind: NodeType
    finding_id: str | None = None


@dataclass(frozen=True, slots=True)
class RiskEdge:
    id: str
    relationship_type: RelationshipType
    source_node: str
    target_node: str
    confidence: Confidence
    evidence: tuple[str, ...]
    rationale: str
    rule_id: str
    structural_metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class RiskGraph:
    nodes: tuple[RiskNode, ...]
    edges: tuple[RiskEdge, ...]


@dataclass(frozen=True, slots=True)
class CorrelationRuleOutput:
    relationships: tuple[RiskEdge, ...] = ()
    candidates: tuple[AttackPathCandidate, ...] = ()


class CorrelationRule(Protocol):
    """Future rule adapter contract; built-in v1 rules remain engine-owned."""

    rule_id: str
    title: str
    required_categories: tuple[str, ...]
    confidence_policy: str
    priority: int
    explanation: str

    def evaluate(self, findings: tuple[Finding, ...], graph: RiskGraph) -> CorrelationRuleOutput:
        """Return bounded deterministic annotations without mutating inputs."""
        ...


@dataclass(frozen=True, slots=True)
class FindingGroup:
    id: str
    primary: str
    members: tuple[tuple[str, FindingRole], ...]
    relationship_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttackPathCandidate:
    id: str
    title: str
    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    confidence: Confidence
    severity_basis: Severity
    rationale: str
    assumptions: tuple[str, ...]
    limitations: tuple[str, ...]
    contributing_findings: tuple[str, ...]
    evidence_summary: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    id: str
    subject: str
    base_severity: Severity
    confidence: Confidence
    evidence_strength: EvidenceStrength
    correlation_strength: EvidenceStrength
    exposure_signal: ExposureSignal
    priority: RiskPriority
    rationale: str
    contributing_findings: tuple[str, ...]
    supporting_relationships: tuple[str, ...]
    limitations: tuple[str, ...]
    dependency_relevance: DependencyRelevance = DependencyRelevance.UNKNOWN


@dataclass(frozen=True, slots=True)
class CorrelationDiagnostic:
    code: str
    count: int = 1


@dataclass(frozen=True, slots=True)
class CorrelationSummary:
    completeness: Completeness
    input_findings: int
    admitted_findings: int
    nodes: int
    edges: int
    groups: int
    attack_paths: int
    scanner_coverage: tuple[tuple[str, str], ...]
    diagnostics: tuple[CorrelationDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    graph: RiskGraph
    groups: tuple[FindingGroup, ...]
    attack_paths: tuple[AttackPathCandidate, ...]
    assessments: tuple[RiskAssessment, ...]
    summary: CorrelationSummary
