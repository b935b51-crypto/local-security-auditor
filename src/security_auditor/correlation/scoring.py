"""Explainable priority without changing original severity or CVSS."""

from __future__ import annotations

from collections import defaultdict

from security_auditor.core.models import Confidence, Finding, Severity
from .graph import _SEVERITIES, _State, _id, _metadata, _minimum, _node
from .models import (DependencyRelevance, EvidenceStrength, ExposureSignal, FindingGroup, FindingRole, RelationshipType, RiskAssessment, RiskPriority)


def assess(state: _State, findings: tuple[Finding, ...], coverage):
    by_id = {f.fingerprint: f for f in findings if _node(f) in state.nodes}
    support: dict[str, set[str]] = defaultdict(set)
    rels: dict[str, set[str]] = defaultdict(set)
    for edge in state.edges.values():
        if edge.relationship_type is RelationshipType.SUPPORTS:
            supporter = edge.source_node.removeprefix("f:")
            primary = edge.target_node.removeprefix("f:")
            support[primary].add(supporter)
            rels[primary].add(edge.id)
    assigned = set().union(*support.values()) if support else set()
    groups = []
    assessments = []
    incomplete = not coverage or any(status != "completed" for _, status in coverage) or state.aborted
    related_network = set()
    dependency_referenced = set()
    for edge in state.edges.values():
        if edge.relationship_type is RelationshipType.RELATED_BEHAVIOR:
            related_network.update((edge.source_node, edge.target_node))
        elif edge.relationship_type is RelationshipType.POSSIBLE_DEPENDENCY_USE:
            dependency_referenced.update((edge.source_node, edge.target_node))
    for primary in sorted(by_id.values(), key=lambda f: f.fingerprint):
        if primary.fingerprint in assigned:
            continue
        supporting = tuple(sorted(s for s in support.get(primary.fingerprint, ()) if s in by_id))
        members = ((primary.fingerprint, FindingRole.PRIMARY),) + tuple(
            (key, FindingRole.SUPPORTING) for key in supporting)
        group_id = _id("group-v1", primary.fingerprint)
        groups.append(FindingGroup(group_id, primary.fingerprint, members,
                                   tuple(sorted(rels.get(primary.fingerprint, ())))))
        evidence = (EvidenceStrength.STRONG if supporting and primary.scanner_id == "sast"
                    else EvidenceStrength.MODERATE if primary.scanner_id in {"sast", "dependencies"}
                    else EvidenceStrength.WEAK)
        correlated = EvidenceStrength.STRONG if supporting else EvidenceStrength.WEAK
        confidence = _minimum(primary.confidence, *(by_id[key].confidence for key in supporting))
        if incomplete and confidence is Confidence.HIGH:
            confidence = Confidence.MEDIUM
        source = _metadata(primary, "source_category")
        exposure = (ExposureSignal.EXTERNAL_INPUT if source == "HTTP_INPUT" else
                    ExposureSignal.NETWORK_CONTEXT if _node(primary) in related_network
                    else ExposureSignal.UNKNOWN)
        base = _SEVERITIES.index(primary.severity)
        bonus = int(bool(supporting) and confidence is Confidence.HIGH and
                    exposure is ExposureSignal.EXTERNAL_INPUT and
                    primary.severity in {Severity.LOW, Severity.MEDIUM})
        priority = RiskPriority(_SEVERITIES[min(base + bonus, len(_SEVERITIES) - 1)].value.lower())
        relevance = DependencyRelevance.PRESENT if primary.dependency else DependencyRelevance.UNKNOWN
        if primary.dependency and _node(primary) in dependency_referenced:
            relevance = DependencyRelevance.REFERENCED
        limitations = ("Scanner or correlation coverage is incomplete.",) if incomplete else ()
        if primary.dependency:
            limitations += ("Import presence does not prove affected API reachability.",)
        assessments.append(RiskAssessment(
            _id("assessment-v1", group_id), group_id, primary.severity, confidence,
            evidence, correlated, exposure, priority,
            "Priority starts from primary severity; a capped one-step bonus requires direct support and structured external-input evidence.",
            tuple(key for key, _ in members), tuple(sorted(rels.get(primary.fingerprint, ()))),
            limitations, relevance))
    return tuple(groups), tuple(assessments)
