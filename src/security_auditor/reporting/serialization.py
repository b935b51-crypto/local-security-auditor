"""Explicit public-field whitelist; never serialize dataclasses wholesale."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

from security_auditor.ai.redaction import redact_text
from security_auditor.core.redaction import safe_finding_path
from security_auditor.core.models import Finding
from .models import ScanReport

_DRIVE = re.compile(r"^[A-Za-z]:")


def safe_text(value: object, *, limit: int = 2000) -> str:
    return redact_text(str(value)[:limit])[:limit]


def safe_diff(value: str, *, limit: int = 32768) -> str:
    if len(value) > limit:
        return "[PATCH DIFF OMITTED]"
    lines = value.splitlines(keepends=True)
    safe = "".join(redact_text(line.removesuffix("\n").removesuffix("\r")) +
                   ("\n" if line.endswith("\n") else "") for line in lines)
    return safe if safe == value.replace("\r\n", "\n") else "[PATCH DIFF OMITTED]"


def safe_path(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.replace("\\", "/")
    if (candidate.startswith("/") or _DRIVE.match(candidate) or
            any(part in {"", ".", ".."} for part in candidate.split("/"))):
        return "[UNSAFE PATH]"
    return safe_text(safe_finding_path(candidate), limit=500)


def safe_uri(value: str | None) -> str | None:
    if value is None or len(value) > 2048:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"https", "http"} or not parts.netloc or parts.username or parts.password:
            return None
    except ValueError:
        return None
    # Credential-like URL query strings and fragments do not belong in reports.
    if parts.query or parts.fragment:
        return None
    return safe_finding_path(value)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def finding_view(f: Finding, roles: dict[str, str], priorities: dict[str, str],
                 reviews: dict[str, tuple[str, str]], proposal_refs: dict[str, str]) -> dict:
    location = f.location
    dependency = f.dependency
    vulnerability = f.vulnerability
    return {
        "id": safe_text(f.id, limit=128), "fingerprint": safe_text(f.fingerprint, limit=128),
        "rule_id": safe_text(f.rule_id, limit=128), "scanner_id": safe_text(f.scanner_id, limit=128),
        "category": safe_text(f.category, limit=64), "title": safe_text(f.title, limit=500),
        "description": safe_text(f.description), "severity": f.severity.value,
        "confidence": f.confidence.value,
        "role": roles.get(f.fingerprint, "primary"),
        "remediation_proposal_id": proposal_refs.get(f.fingerprint),
        "risk_priority": priorities.get(f.fingerprint),
        "location": {"path": safe_path(location.path), "start_line": location.start_line,
                     "start_column": location.start_column, "end_line": location.end_line,
                     "end_column": location.end_column},
        "evidence": {"kind": safe_text(f.evidence.kind, limit=100),
                     # The summary is deliberately source-free. A scanner preview is not a report authority.
                     "summary": safe_text(f.evidence.kind.replace("_", " "), limit=100)},
        "rationale": safe_text(f.rationale),
        "attack_scenario": safe_text(f.attack_scenario) if f.attack_scenario else None,
        "source": safe_text(f.source, limit=200) if f.source else None,
        "sink": safe_text(f.sink, limit=200) if f.sink else None,
        "cwe": [safe_text(x, limit=80) for x in f.cwe],
        "cve": [safe_text(x, limit=80) for x in f.cve],
        "cvss": safe_text(f.cvss, limit=100) if f.cvss else None,
        "owasp": [safe_text(x, limit=80) for x in f.owasp],
        "tags": [safe_text(x, limit=100) for x in f.tags],
        "remediation": {"recommendation": safe_text(f.remediation.recommendation),
                        "references": [url for x in f.remediation.references if (url := safe_uri(x))]},
        "dependency": ({"ecosystem": safe_text(dependency.ecosystem, limit=100),
                        "name": safe_text(dependency.name, limit=200),
                        "version": safe_text(dependency.version, limit=100) if dependency.version else None,
                        "direct": dependency.direct} if dependency else None),
        "vulnerability": ({"id": safe_text(vulnerability.advisory_id, limit=100),
                           "source": safe_text(vulnerability.source, limit=100),
                           "reference": safe_uri(vulnerability.reference_uri),
                           "fixed_versions": [safe_text(x, limit=100) for x in vulnerability.fixed_versions]}
                          if vulnerability else None),
        "ai_review": ({"verdict": reviews[f.fingerprint][0], "confidence": reviews[f.fingerprint][1]}
                      if f.fingerprint in reviews else None),
    }


def report_view(report: ScanReport) -> dict:
    roles = dict(report.roles)
    priorities = {a.subject: a.priority.value for a in report.risk_assessments}
    for group in report.finding_groups:
        if group.id in priorities:
            priorities[group.primary] = priorities[group.id]
    reviews = {r.subject_id: (r.verdict.value, r.confidence.value) for r in report.ai_reviews
               if r.subject_type.value == "finding"}
    proposal_by_finding = {p.finding_id: p.proposal_id for p in report.remediation_proposals}
    proposal_refs = {f.fingerprint: proposal_by_finding[f.id] for f in report.findings
                     if f.id in proposal_by_finding}
    for group in report.finding_groups:
        primary_proposal = proposal_refs.get(group.primary)
        if primary_proposal:
            for fingerprint, role in group.members:
                if role.value == "supporting":
                    proposal_refs[fingerprint] = primary_proposal
    return {
        "schema_version": report.schema_version,
        "tool": {"name": report.tool_name, "version": report.tool_version},
        "scan": {"scan_id": report.scan_id, "started_at": iso(report.started_at),
                 "completed_at": iso(report.completed_at),
                 "duration_seconds": round(report.duration_seconds, 3),
                 "target": safe_text(report.target_display, limit=200),
                 "profile": report.profile, "offline": report.offline,
                 "ai_requested": report.ai_requested,
                 "remediation_requested": report.remediation_requested},
        "environment": {"platform": report.environment_platform,
                        "python": report.environment_python},
        "coverage": {"overall": report.coverage.overall.value,
                     "components": [{"component": x.component, "status": x.status.value,
                                     "reasons": list(x.reasons)} for x in report.coverage.components],
                     "reasons": list(report.coverage.reasons),
                     "skipped_files": report.coverage.skipped_files,
                     "unsupported_files": report.coverage.unsupported_files,
                     "budget_limits_hit": report.coverage.budget_limits_hit,
                     "ai_eligible": report.coverage.ai_eligible,
                     "ai_reviewed": report.coverage.ai_reviewed},
        "discovery": {"admitted_files": report.discovery.summary.stats.files_admitted,
                      "skipped_files": report.discovery.summary.stats.files_skipped,
                      "directories_visited": report.discovery.summary.stats.directories_visited,
                      "completeness": report.discovery.completeness.value},
        "scanners": [{"id": r.scanner.id, "version": r.scanner.version,
                      "status": r.status,
                      "completeness": r.summary.completeness if r.summary else r.status,
                      "artifacts_scanned": r.summary.artifacts_scanned if r.summary else 0,
                      "artifacts_skipped": r.summary.artifacts_skipped if r.summary else 0,
                      **({"artifacts_considered": r.summary.artifacts_considered,
                          "artifacts_applicable": r.summary.artifacts_applicable,
                          "artifacts_not_applicable": r.summary.artifacts_not_applicable}
                         if r.summary and r.scanner.id in {"sast.python", "behavior.static"} else {}),
                      "findings": len(r.findings)} for r in report.scanner_results],
        "summary": {"counts": {"total_findings": report.counts.total_findings,
                                "rendered_findings": report.counts.rendered_findings,
                                "severity": dict(report.counts.severity),
                                "category": dict(report.counts.category),
                                "risk_priority": dict(report.counts.risk_priority),
                                "ai_verdict": dict(report.counts.ai_verdict)},
                    "dependency": {"packages": report.dependency.packages,
                                   "exact_versions": report.dependency.exact_versions,
                                   "queries": report.dependency.queries,
                                   "cache_hits": report.dependency.cache_hits,
                                   "no_data": report.dependency.no_data,
                                   "matches": report.dependency.matches},
                    "ai_status": report.ai_status,
                    "external_services": dict(report.external_services),
                    "remediation": {"proposals": len(report.remediation_proposals),
                                    "patches": sum(p.patch_candidate is not None for p in report.remediation_proposals),
                                    "ai_requests": report.remediation_ai_requests,
                                    "diagnostics": list(report.remediation_diagnostics)}},
        "diagnostics": [{"source": d.source, "code": safe_text(d.code, limit=100),
                         "message": safe_text(d.message, limit=500), "path": safe_path(d.path),
                         "count": d.count} for d in report.diagnostics],
        "rules": [{"id": safe_text(r.id, limit=128), "title": safe_text(r.title, limit=500),
                   "help_uri": safe_uri(r.help_uri)} for r in report.rules],
        "findings": [finding_view(f, roles, priorities, reviews, proposal_refs) for f in report.findings],
        "finding_groups": [{"id": g.id, "primary": g.primary,
                            "members": [{"fingerprint": fp, "role": role.value} for fp, role in g.members]}
                           for g in report.finding_groups],
        "attack_paths": [{"id": p.id, "title": safe_text(p.title, limit=500),
                          "confidence": p.confidence.value, "severity_basis": p.severity_basis.value,
                          "rationale": safe_text(p.rationale),
                          "assumptions": [safe_text(x, limit=500) for x in p.assumptions],
                          "limitations": [safe_text(x, limit=500) for x in p.limitations],
                          "contributing_findings": list(p.contributing_findings)} for p in report.attack_paths],
        "risk_assessments": [{"id": a.id, "subject": a.subject,
                              "base_severity": a.base_severity.value, "confidence": a.confidence.value,
                              "priority": a.priority.value, "rationale": safe_text(a.rationale),
                              "contributing_findings": list(a.contributing_findings),
                              "limitations": [safe_text(x, limit=500) for x in a.limitations]}
                             for a in report.risk_assessments],
        "ai_reviews": [{"id": r.review_id, "provider": r.provider, "model": r.model,
                        "subject_type": r.subject_type.value, "subject_id": r.subject_id,
                        "verdict": r.verdict.value, "confidence": r.confidence.value,
                        "summary": safe_text(r.summary, limit=500),
                        "rationale": [safe_text(x, limit=500) for x in r.rationale],
                        "supporting_evidence": [safe_text(x, limit=500) for x in r.supporting_evidence],
                        "contradictory_evidence": [safe_text(x, limit=500) for x in r.contradictory_evidence],
                        "missing_context": [safe_text(x, limit=500) for x in r.missing_context],
                        "remediation": [safe_text(x, limit=500) for x in r.remediation],
                        "limitations": [safe_text(x, limit=500) for x in r.limitations],
                        "prompt_version": r.prompt_version,
                        "response_schema_version": r.response_schema_version,
                        "usage": {"input_tokens": r.usage.input_tokens,
                                  "output_tokens": r.usage.output_tokens,
                                  "total_tokens": r.usage.total_tokens}}
                       for r in report.ai_reviews],
        "remediation_proposals": [{
            "proposal_id": safe_text(p.proposal_id, limit=64),
            "finding_id": safe_text(p.finding_id, limit=128),
            "strategy": p.strategy.value, "status": p.status.value,
            "title": safe_text(p.title, limit=500),
            "summary": safe_text(p.summary, limit=500),
            "rationale": safe_text(p.rationale, limit=500),
            "preconditions": [safe_text(x, limit=500) for x in p.preconditions],
            "remediation_steps": [safe_text(x, limit=500) for x in p.remediation_steps],
            "external_actions_required": [safe_text(x, limit=100) for x in p.external_actions_required],
            "provider_reported_fixed_versions": [safe_text(x, limit=100) for x in p.provider_reported_fixed_versions],
            "assumptions": [safe_text(x, limit=500) for x in p.assumptions],
            "limitations": [safe_text(x, limit=500) for x in p.limitations],
            "human_approval_required": True,
            "runtime_tests_status": "NOT_RUN",
            "provenance": safe_text(p.provenance, limit=100),
            "patch_candidate": ({"patch_id": safe_text(p.patch_candidate.patch_id, limit=64),
                                 "target_relative_path": safe_path(p.patch_candidate.target_relative_path),
                                 "original_fingerprint": p.patch_candidate.original_fingerprint,
                                 "proposed_content_fingerprint": p.patch_candidate.proposed_content_fingerprint,
                                 "unified_diff": safe_diff(p.patch_candidate.unified_diff),
                                 "changed_hunks": p.patch_candidate.changed_hunks,
                                 "changed_line_count": p.patch_candidate.changed_line_count,
                                 "provenance": safe_text(p.patch_candidate.provenance, limit=100),
                                 "generated_by": safe_text(p.patch_candidate.generated_by, limit=100),
                                 "generated_at": p.patch_candidate.generated_at,
                                 "patch_confidence": p.patch_candidate.patch_confidence.value,
                                 "provider": p.patch_candidate.provider,
                                 "model": p.patch_candidate.model,
                                 "prompt_version": p.patch_candidate.prompt_version,
                                 "human_approval_required": True}
                                if p.patch_candidate else None),
            "validation": ({"applies_cleanly": v.applies_cleanly,
                            "source_fresh": v.source_fresh, "scope_valid": v.scope_valid,
                            "syntax_status": v.syntax_status.value,
                            "target_finding_before": v.target_finding_before,
                            "target_finding_after": v.target_finding_after,
                            "target_finding_removed": v.target_finding_removed,
                            "new_findings": list(v.new_findings),
                            "new_high_findings": list(v.new_high_findings),
                            "existing_findings_removed": list(v.existing_findings_removed),
                            "existing_findings_changed": list(v.existing_findings_changed),
                            "static_validation_status": v.static_validation_status.value,
                            "runtime_tests_status": "NOT_RUN",
                            "limitations": [safe_text(x, limit=500) for x in v.limitations],
                            "diagnostics": list(v.diagnostics)} if (v := p.validation_result) else None),
        } for p in report.remediation_proposals],
        "report_truncated": report.report_truncated,
        "limitations": [safe_text(x, limit=500) for x in report.limitations],
    }
