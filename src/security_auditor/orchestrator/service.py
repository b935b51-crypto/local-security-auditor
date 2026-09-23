"""One bounded pass through discovery, scanners, correlation and optional AI."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from uuid import uuid4

from security_auditor.core.config import AuditConfig
from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget, ScannerDiagnostic, ScannerResult, ScannerSummary
from security_auditor.discovery import discover
from security_auditor.discovery.policy import DiscoveryPolicy
from security_auditor.discovery.models import ScanCompleteness
from security_auditor.scanners.secrets.scanner import SecretScanner
from security_auditor.scanners.sast.scanner import SASTScanner
from security_auditor.scanners.behavior.scanner import BehaviorScanner
from security_auditor.scanners.dependencies.scanner import DependencyScanner
from security_auditor.correlation.engine import CorrelationEngine
from security_auditor.ai.reviewer import AIReviewer
from security_auditor.reporting.models import (CoverageStatus, ReportDiagnostic,
                                                ScanReport, assemble_report)
from security_auditor.remediation.planner import RemediationPlanner
from .models import ScanRequest


class ScanOrchestrator:
    """Only discovery and admitted-artifact scanners touch target files."""

    def __init__(self, *, dependency_provider=None, dependency_cache=None, ai_provider=None,
                 tool_config_dir: Path | None = None):
        self.dependency_provider = dependency_provider
        self.dependency_cache = dependency_cache
        self.ai_provider = ai_provider
        self.tool_config_dir = tool_config_dir

    def run_scan(self, request: ScanRequest) -> ScanReport:
        started = datetime.now(timezone.utc)
        clock = monotonic()
        config = request.config
        profile = request.profile or config.profile
        # --ai alone grants Gemini egress, not an implicit OSV lookup.
        ai_only_online = ((request.ai_requested or request.ai_remediation_requested)
                          and request.offline is None and config.offline)
        offline = (False if ai_only_online else
                   config.offline if request.offline is None else request.offline)
        # Explicit --ai is necessary even when a trusted config enables AI.
        ai_enabled = request.ai_requested and not request.ai_disabled and not offline
        session = ScanSession(uuid4().hex, ScanTarget(request.target, request.target.name or "."),
                              profile, started, offline)
        def cancelled() -> bool:
            return request.cancel_event is not None and request.cancel_event.is_set()

        def stage(name: str) -> None:
            if request.progress is not None:
                try:
                    request.progress(name)
                except Exception:
                    pass

        stage("Discovering")
        discovery = discover(session.target, DiscoveryPolicy.from_config(config), cancelled)
        results: list[ScannerResult] = []
        correlation = None
        ai = None
        dependency_outcome = None
        if discovery.root is not None and discovery.completeness is not ScanCompleteness.FAILED:
            scanners = [SecretScanner(config.secrets)]
            if profile is not ScanProfile.QUICK:
                scanners.append(SASTScanner(config.sast))
            scanners.append(BehaviorScanner(config.behavior))
            vulnerability = (replace(config.vulnerability, enabled=False)
                             if ai_only_online else config.vulnerability)
            dependency = DependencyScanner(config.dependencies, vulnerability,
                                           self.dependency_provider, self.dependency_cache)
            for scanner in scanners:
                if cancelled():
                    break
                stage({"secrets": "Secrets", "sast.python": "SAST",
                       "behavior": "Behavior"}.get(scanner.metadata.id, "Scanning"))
                try:
                    results.append(scanner.scan_discovery(session, discovery))
                except Exception:
                    results.append(ScannerResult(scanner.metadata, status="failed",
                        diagnostics=(ScannerDiagnostic("SCANNER_INTERNAL_ERROR", "scanner failed without exposing target content"),),
                        summary=ScannerSummary(completeness="failed")))
            if not cancelled():
                stage("Dependencies")
                try:
                    dependency_outcome = dependency.scan_with_inventory(session, discovery)
                    results.append(dependency_outcome.result)
                except Exception:
                    results.append(ScannerResult(dependency.metadata, status="failed",
                        diagnostics=(ScannerDiagnostic("SCANNER_INTERNAL_ERROR", "scanner failed without exposing target content"),),
                        summary=ScannerSummary(completeness="failed")))
            if not cancelled() and profile is not ScanProfile.QUICK:
                stage("Correlation")
                try:
                    correlation = CorrelationEngine(config.correlation).correlate(results)
                except Exception:
                    correlation = None
            if not cancelled() and ai_enabled:
                stage("AI Review")
                try:
                    ai = AIReviewer(replace(config.ai, enabled=True), self.ai_provider).review(
                        session, results, correlation, discovery, allow_online_ai=True,
                        tool_config_dir=self.tool_config_dir)
                except Exception:
                    ai = None
        report = assemble_report(session, discovery, tuple(results), correlation, ai,
                                 dependency_outcome, ai_requested=request.ai_requested,
                                 started_at=started, completed_at=datetime.now(timezone.utc),
                                 duration_seconds=monotonic() - clock)
        if not cancelled() and request.propose_fixes and discovery.root is not None:
            stage("Remediation")
            try:
                planner = RemediationPlanner(replace(config.remediation, enabled=True),
                                             config.sast, ai_provider=self.ai_provider,
                                             tool_config_dir=self.tool_config_dir)
                batch = planner.plan(report, ai_remediation=request.ai_remediation_requested)
                report = replace(report, remediation_proposals=batch.proposals,
                    remediation_diagnostics=batch.diagnostics,
                    remediation_requested=True,
                    remediation_ai_requests=batch.ai_requests,
                    external_services=tuple((name, used or name == "gemini" and batch.ai_requests > 0)
                                            for name, used in report.external_services),
                    completed_at=datetime.now(timezone.utc),
                    duration_seconds=monotonic() - clock)
            except Exception:
                report = replace(report, remediation_requested=True,
                                 remediation_diagnostics=("PATCH_VALIDATION_PARTIAL",))
        if cancelled():
            report = replace(report,
                coverage=replace(report.coverage, overall=CoverageStatus.ABORTED,
                                 reasons=tuple(sorted(set(report.coverage.reasons) | {"SCAN_CANCELLED"}))),
                diagnostics=report.diagnostics +
                            (ReportDiagnostic("orchestrator", "SCAN_CANCELLED", "scan cancelled by operator"),))
        stage("Reporting")
        return report
