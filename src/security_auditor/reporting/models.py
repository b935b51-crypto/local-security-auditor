"""Immutable, bounded report assembled once from normalized results."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import platform
import sys

from security_auditor import __version__
from security_auditor.ai.models import AIReviewBatch, AIReviewResult
from security_auditor.core.models import Finding, RuleReference, ScanSession, ScannerResult, Severity
from security_auditor.correlation.models import CorrelationResult, FindingGroup, AttackPathCandidate, RiskAssessment, FindingRole
from security_auditor.discovery.models import DiscoveryResult
from security_auditor.scanners.dependencies.models import LookupStatus
from security_auditor.scanners.dependencies.scanner import DependencyScanOutcome
from security_auditor.remediation.models import RemediationProposal

SCHEMA_VERSION = "1.1"
MAX_FINDINGS = 1000
MAX_DIAGNOSTICS = 300
MAX_ATTACK_PATHS = 100
MAX_AI_REVIEWS = 100
MAX_GROUPS = 1000


class CoverageStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABORTED = "ABORTED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


@dataclass(frozen=True, slots=True)
class CoverageItem:
    component: str
    status: CoverageStatus
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Coverage:
    overall: CoverageStatus
    components: tuple[CoverageItem, ...]
    reasons: tuple[str, ...]
    skipped_files: int
    unsupported_files: int
    budget_limits_hit: int
    ai_eligible: int
    ai_reviewed: int


@dataclass(frozen=True, slots=True)
class ReportDiagnostic:
    source: str
    code: str
    message: str
    path: str | None = None
    count: int = 1


@dataclass(frozen=True, slots=True)
class ReportCounts:
    total_findings: int
    rendered_findings: int
    severity: tuple[tuple[str, int], ...]
    category: tuple[tuple[str, int], ...]
    risk_priority: tuple[tuple[str, int], ...]
    ai_verdict: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class DependencySummary:
    packages: int = 0
    exact_versions: int = 0
    queries: int = 0
    cache_hits: int = 0
    no_data: int = 0
    matches: int = 0
    first_party_roots: int = 0
    unresolved_third_party: int = 0
    batch_requests_used: int = 0
    batch_requests_limit: int = 0
    detail_requests_used: int = 0
    detail_requests_limit: int = 0
    total_requests_used: int = 0
    total_requests_limit: int = 0
    deduplicated_advisories: int = 0
    provider_budget_reached: bool = False


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: str
    tool_name: str
    tool_version: str
    scan_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    target_display: str
    profile: str
    offline: bool
    ai_requested: bool
    environment_platform: str
    environment_python: str
    coverage: Coverage
    discovery: DiscoveryResult
    scanner_results: tuple[ScannerResult, ...]
    diagnostics: tuple[ReportDiagnostic, ...]
    findings: tuple[Finding, ...]
    finding_groups: tuple[FindingGroup, ...]
    attack_paths: tuple[AttackPathCandidate, ...]
    risk_assessments: tuple[RiskAssessment, ...]
    ai_reviews: tuple[AIReviewResult, ...]
    ai_status: str
    dependency: DependencySummary
    counts: ReportCounts
    roles: tuple[tuple[str, str], ...]
    rules: tuple[RuleReference, ...]
    report_truncated: bool
    limitations: tuple[str, ...]
    external_services: tuple[tuple[str, bool], ...]
    remediation_proposals: tuple[RemediationProposal, ...] = ()
    remediation_diagnostics: tuple[str, ...] = ()
    remediation_requested: bool = False
    remediation_ai_requests: int = 0


def _status(value: str) -> CoverageStatus:
    return {"complete": CoverageStatus.COMPLETE, "completed": CoverageStatus.COMPLETE,
            "partial": CoverageStatus.PARTIAL, "skipped": CoverageStatus.PARTIAL,
            "aborted": CoverageStatus.ABORTED, "failed": CoverageStatus.FAILED,
            "disabled": CoverageStatus.DISABLED}.get(value, CoverageStatus.PARTIAL)


def assemble_report(session: ScanSession, discovery: DiscoveryResult,
                    results: tuple[ScannerResult, ...], correlation: CorrelationResult | None,
                    ai: AIReviewBatch | None, dependency: DependencyScanOutcome | None, *,
                    ai_requested: bool, started_at: datetime, completed_at: datetime,
                    duration_seconds: float) -> ScanReport:
    raw_findings = sorted((f for r in results for f in r.findings),
                          key=lambda f: (f.fingerprint, f.rule_id, f.location.path))
    findings_all: list[Finding] = []
    seen: dict[str, Finding] = {}
    collisions = 0
    for finding in raw_findings:
        prior = seen.get(finding.fingerprint)
        if prior is not None:
            if (prior.rule_id, prior.scanner_id, prior.location) == (
                    finding.rule_id, finding.scanner_id, finding.location):
                continue
            collisions += 1
        else:
            seen[finding.fingerprint] = finding
        findings_all.append(finding)
    findings = tuple(findings_all[:MAX_FINDINGS])
    groups = tuple(sorted(correlation.groups, key=lambda g: g.id)[:MAX_GROUPS]) if correlation else ()
    paths = tuple(sorted(correlation.attack_paths, key=lambda p: p.id)[:MAX_ATTACK_PATHS]) if correlation else ()
    assessments = tuple(sorted(correlation.assessments, key=lambda a: a.id)[:MAX_FINDINGS]) if correlation else ()
    reviews = tuple(sorted(ai.reviews, key=lambda r: r.review_id)[:MAX_AI_REVIEWS]) if ai else ()
    diagnostics = [ReportDiagnostic("discovery", str(d.code), d.message, d.path) for d in discovery.diagnostics]
    for result in results:
        diagnostics.extend(ReportDiagnostic(result.scanner.id, d.code, d.message, d.path)
                           for d in result.diagnostics)
    if correlation:
        diagnostics.extend(ReportDiagnostic("correlation", d.code, d.code.replace("_", " ").lower(), count=d.count)
                           for d in correlation.summary.diagnostics)
    if ai:
        diagnostics.extend(ReportDiagnostic("ai", d.code, d.code.replace("_", " ").lower(), count=d.count)
                           for d in ai.summary.diagnostics)
    if ai_requested and session.offline:
        diagnostics.append(ReportDiagnostic("ai", "AI_OFFLINE", "AI review disabled by offline mode"))
    elif ai_requested and ai is None and not session.offline:
        diagnostics.append(ReportDiagnostic("ai", "AI_UNAVAILABLE", "AI review unavailable"))
    if collisions:
        diagnostics.append(ReportDiagnostic("report", "REPORT_FINGERPRINT_COLLISION",
                                            "distinct findings share a fingerprint", count=collisions))
    catalog: dict[str, RuleReference] = {}
    for finding in findings_all:
        if finding.rule:
            prior = catalog.setdefault(finding.rule_id, finding.rule)
            if prior != finding.rule:
                diagnostics.append(ReportDiagnostic("report", "RULE_CATALOG_CONFLICT", "conflicting rule metadata"))
    diagnostics = sorted(diagnostics, key=lambda d: (d.source, d.code, d.path or "", d.message))
    items = [CoverageItem("discovery", _status(discovery.completeness.value),
                          tuple(sorted({d.code.value for d in discovery.diagnostics if d.affects_completeness})))]
    for result in results:
        state = result.summary.completeness if result.summary else result.status
        items.append(CoverageItem(result.scanner.id, _status(state),
                                  tuple(sorted({d.code for d in result.diagnostics}))))
    if session.profile.value == "quick":
        items.append(CoverageItem("sast.python", CoverageStatus.DISABLED, ("PROFILE_QUICK",)))
    items.append(CoverageItem("correlation", _status(correlation.summary.completeness.value)
                              if correlation else CoverageStatus.DISABLED if session.profile.value == "quick" else
                              CoverageStatus.PARTIAL if results else CoverageStatus.DISABLED,
                              tuple(d.code for d in correlation.summary.diagnostics) if correlation else ()))
    ai_status = ai.summary.status.value if ai else "disabled" if not ai_requested or session.offline else "failed"
    items.append(CoverageItem("ai", _status(ai_status),
                              tuple(d.code for d in ai.summary.diagnostics) if ai else ()))
    deterministic = [item for item in items if item.component != "ai" and item.status is not CoverageStatus.DISABLED]
    if discovery.completeness.value == "failed":
        overall = CoverageStatus.FAILED
    elif any(item.status is CoverageStatus.ABORTED for item in deterministic):
        overall = CoverageStatus.ABORTED
    elif any(item.status is not CoverageStatus.COMPLETE for item in deterministic):
        overall = CoverageStatus.PARTIAL
    else:
        overall = CoverageStatus.COMPLETE
    truncated = (len(findings_all) > MAX_FINDINGS or len(diagnostics) > MAX_DIAGNOSTICS or
                 bool(correlation and (len(correlation.groups) > MAX_GROUPS or
                                       len(correlation.attack_paths) > MAX_ATTACK_PATHS or
                                       len(correlation.assessments) > MAX_FINDINGS)) or
                 bool(ai and len(ai.reviews) > MAX_AI_REVIEWS))
    if (truncated or collisions or any(d.code == "RULE_CATALOG_CONFLICT" for d in diagnostics)) and overall is CoverageStatus.COMPLETE:
        overall = CoverageStatus.PARTIAL
    reasons = tuple(sorted({reason for item in deterministic for reason in item.reasons} |
                           ({"REPORT_TRUNCATED"} if truncated else set()) |
                           ({"REPORT_FINGERPRINT_COLLISION"} if collisions else set()) |
                           ({"RULE_CATALOG_CONFLICT"} if any(d.code == "RULE_CATALOG_CONFLICT" for d in diagnostics) else set())))
    coverage = Coverage(overall, tuple(items), reasons, discovery.summary.stats.files_skipped,
                        sum(s.reason.value == "unsupported_type" for s in discovery.skipped),
                        sum((r.summary.limits_hit if r.summary else 0) for r in results),
                        ai.summary.eligible if ai else 0, ai.summary.completed if ai else 0)
    severity = Counter(f.severity.value.lower() for f in findings_all)
    category = Counter(f.category for f in findings_all)
    priority = Counter(a.priority.value for a in assessments)
    verdict = Counter(r.verdict.value.lower() for r in reviews)
    counts = ReportCounts(len(findings_all), len(findings),
                          tuple((s.value.lower(), severity[s.value.lower()]) for s in Severity),
                          tuple(sorted(category.items())), tuple(sorted(priority.items())),
                          tuple(sorted(verdict.items())))
    roles: dict[str, str] = {}
    for group in groups:
        for fingerprint, role in group.members:
            roles[fingerprint] = role.value
    lookups = dependency.lookups if dependency else ()
    metrics = dict(dependency.result.summary.details) if dependency and dependency.result.summary else {}
    dep_summary = DependencySummary(metrics.get("dependencies_discovered", 0),
                                    metrics.get("exact_dependencies", 0),
                                    metrics.get("provider_queries", 0), metrics.get("cache_hits", 0),
                                    sum(l.status in {LookupStatus.NO_DATA, LookupStatus.OFFLINE_NO_CACHE,
                                                     LookupStatus.QUERY_FAILED} for l in lookups),
                                    metrics.get("vulnerability_matches", 0),
                                    metrics.get("first_party_roots", 0),
                                    metrics.get("unresolved_dependencies", 0),
                                    metrics.get("batch_requests_used", 0),
                                    metrics.get("batch_requests_limit", 0),
                                    metrics.get("detail_requests_used", 0),
                                    metrics.get("detail_requests_limit", 0),
                                    metrics.get("total_requests_used", 0),
                                    metrics.get("total_requests_limit", 0),
                                    metrics.get("deduplicated_advisories", 0),
                                    bool(metrics.get("provider_budget_reached", 0)))
    return ScanReport(SCHEMA_VERSION, "Local Security Auditor", __version__, session.id,
                      started_at, completed_at, max(0.0, duration_seconds),
                      session.target.display_name, session.profile.value, session.offline,
                      ai_requested, platform.system(), sys.version.split()[0], coverage,
                      discovery, results, tuple(diagnostics[:MAX_DIAGNOSTICS]), findings,
                      groups, paths, assessments, reviews, ai_status, dep_summary, counts,
                      tuple(sorted(roles.items())), tuple(catalog[k] for k in sorted(catalog)),
                      truncated, ("Results describe analyzed coverage only.",),
                      (("osv", dep_summary.queries > 0),
                       ("gemini", bool(ai and ai.summary.requests > 0))))
