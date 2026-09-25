"""Golden identity, context, provenance, and no-work AI cases; never use live services."""

from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.ai.models import AIReviewStatus
from security_auditor.ai.reviewer import AIReviewer
from security_auditor.core.config import AISettings, AuditConfig
from security_auditor.core.models import (Confidence, Evidence, ScanProfile, ScanSession,
                                          ScanTarget, ScannerMetadata, ScannerResult, Severity)
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.gate.service import GateStatus, evaluate_gate
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.remediation.planner import RemediationPlanner
from security_auditor.reporting import html, json_report, sarif
from security_auditor.reporting.models import assemble_report
from security_auditor.scanners._common import StaticRule, make_finding
from security_auditor.scanners.behavior.python_rules import scan_python_behavior
from security_auditor.scanners.dependencies.cache import VulnerabilityCache
from security_auditor.scanners.dependencies.models import LookupResult, LookupStatus


RULE = StaticRule("BEHAVIOR.DYNAMIC_CODE", "Synthetic dynamic code", "Static signal.",
                  "behavior", Severity.MEDIUM, Confidence.HIGH, "Static evidence.",
                  "Review source boundary.")


class NoNetworkProvider:
    def __init__(self):
        self.calls = []

    def lookup_batch(self, keys, limits):
        self.calls.append(tuple(keys))
        return tuple(LookupResult(key, LookupStatus.NO_MATCH) for key in keys)


class NoGeminiProvider:
    provider_id = "gemini"
    model = "gemini-3.8-flash"

    def review(self, *args, **kwargs):
        raise AssertionError("No eligible work may call Gemini")


class FindingIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-identity-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.target = self.base / "target"
        self.target.mkdir()
        self.session = ScanSession("synthetic", ScanTarget(self.target, "synthetic"),
                                   ScanProfile.DEEP, datetime.now(timezone.utc), offline=True)

    def _report(self, *findings):
        scanner = ScannerResult(ScannerMetadata("behavior.static", "test", "behavior", True),
                                tuple(findings))
        discovery = discover(self.session.target, DiscoveryPolicy())
        now = datetime.now(timezone.utc)
        return assemble_report(self.session, discovery, (scanner,), None, None, None,
                               ai_requested=False, started_at=now, completed_at=now,
                               duration_seconds=0)

    def test_exact_duplicate_has_one_finding_and_one_remediation(self):
        finding = make_finding(RULE, "behavior.static", "app.py", 2, 5,
                               anchor="exec", sink="python_ast",
                               evidence=(("detection", "python_ast"),))
        report = self._report(finding, finding)
        self.assertEqual(report.counts.total_findings, 1)
        self.assertEqual(report.findings[0].fingerprint, finding.fingerprint)
        settings = replace(AuditConfig().remediation, enabled=True)
        proposals = RemediationPlanner(settings, AuditConfig().sast).plan(report)
        self.assertEqual(len(proposals.proposals), 1)

    def test_different_semantic_evidence_is_not_silently_deduplicated(self):
        first = make_finding(RULE, "behavior.static", "app.py", 2, 5,
                             anchor="exec", sink="python_ast",
                             evidence=(("detection", "python_ast"),))
        second = replace(first, evidence=Evidence("static_structure", "[REDACTED]",
                                                   (("detection", "other_operation"),)))
        report = self._report(first, second, second)
        self.assertEqual(report.counts.total_findings, 2)
        self.assertIn("REPORT_FINGERPRINT_COLLISION", {d.code for d in report.diagnostics})

    def test_test_context_is_additive_and_production_remains_unmarked(self):
        test = make_finding(RULE, "behavior.static", "tests/unit/example.py", 2, 5,
                            anchor="exec")
        spec = make_finding(RULE, "behavior.static", "apps/ui/example.spec.ts", 3, 1,
                            anchor="exec")
        production = make_finding(RULE, "behavior.static", "src/example.py", 4, 1,
                                  anchor="exec")
        report = self._report(test, spec, production)
        by_path = {finding.location.path: finding for finding in report.findings}
        self.assertIn("context:test_code", by_path["tests/unit/example.py"].tags)
        self.assertIn("context:test_code", by_path["apps/ui/example.spec.ts"].tags)
        self.assertNotIn("context:test_code", by_path["src/example.py"].tags)
        self.assertIn("此訊號位於測試程式碼", html.render(report))

    def test_end_to_end_same_sink_group_has_one_proposal_and_stable_sarif_roles(self):
        tests = self.target / "tests"
        tests.mkdir()
        (tests / "test_runtime.py").write_text(
            "import subprocess\nsubprocess.run(['cmd', '/c', 'echo'])\n", encoding="utf-8")
        report = ScanOrchestrator(dependency_cache=VulnerabilityCache(self.base / "cache")).run_scan(
            ScanRequest(self.target, AuditConfig(), ScanProfile.DEEP, True, False,
                        propose_fixes=True))
        signals = [f for f in report.findings if f.rule_id in {
            "BEHAVIOR.PROCESS_EXEC", "BEHAVIOR.CMD_EXEC"}]
        self.assertEqual(len(signals), 2)
        roles = dict(report.roles)
        command = next(f for f in signals if f.rule_id == "BEHAVIOR.CMD_EXEC")
        process = next(f for f in signals if f.rule_id == "BEHAVIOR.PROCESS_EXEC")
        self.assertEqual((roles[command.fingerprint], roles[process.fingerprint]),
                         ("primary", "supporting"))
        self.assertEqual(len(report.remediation_proposals), 1)
        view = json.loads(json_report.render(report))
        self.assertEqual(view["summary"]["counts"]["total_findings"], 2)
        self.assertEqual(len(view["finding_groups"]), 1)
        self.assertIn("<details><summary>", html.render(report))
        sarif_results = json.loads(sarif.render(report))["runs"][0]["results"]
        self.assertEqual({item["properties"]["role"] for item in sarif_results},
                         {"primary", "supporting"})
        self.assertEqual(len({item["properties"]["findingGroupId"]
                              for item in sarif_results}), 1)

    def test_nested_compile_is_one_dynamic_operation_with_bounded_context(self):
        source = ("class Snapshot:\n"
                  "  def evaluate(self):\n"
                  "    sources = dict(self.sources)\n"
                  "    def load(name):\n"
                  "      exec(compile(sources[name], '<synthetic>', 'exec'))\n"
                  "    return load\n")
        hits = [hit for hit in scan_python_behavior(ast.parse(source))
                if hit.rule_id == "BEHAVIOR.DYNAMIC_CODE"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].context, "stored_source_lookup")
        standalone = scan_python_behavior(ast.parse("compile('x = 1', '<synthetic>', 'exec')"))
        self.assertEqual(sum(hit.rule_id == "BEHAVIOR.DYNAMIC_CODE" for hit in standalone), 1)

    def test_remote_dynamic_input_has_no_stored_source_context(self):
        source = "def handler(request):\n  exec(request.json)\n"
        hits = [hit for hit in scan_python_behavior(ast.parse(source))
                if hit.rule_id == "BEHAVIOR.DYNAMIC_CODE"]
        self.assertEqual(len(hits), 1)
        self.assertIsNone(hits[0].context)
        shadowed = ("class Snapshot:\n"
                    "  def evaluate(self):\n"
                    "    sources = dict(self.sources)\n"
                    "    def load(sources):\n"
                    "      exec(compile(sources['x'], '<synthetic>', 'exec'))\n")
        shadowed_hits = [hit for hit in scan_python_behavior(ast.parse(shadowed))
                         if hit.rule_id == "BEHAVIOR.DYNAMIC_CODE"]
        self.assertEqual(len(shadowed_hits), 1)
        self.assertIsNone(shadowed_hits[0].context)

    def test_cache_provenance_and_partial_stale_semantics(self):
        (self.target / "requirements.txt").write_text("requests==2.0.0\nurllib3==1.0.0\n",
                                                         encoding="utf-8")
        cache = VulnerabilityCache(self.base / "cache")
        cache.write(LookupResult(("PyPI", "requests", "2.0.0"), LookupStatus.NO_MATCH))
        cache.write(LookupResult(("PyPI", "urllib3", "1.0.0"), LookupStatus.NO_MATCH))
        provider = NoNetworkProvider()
        report = ScanOrchestrator(dependency_provider=provider, dependency_cache=cache).run_scan(
            ScanRequest(self.target, AuditConfig(), ScanProfile.DEEP, True, False))
        dep = json.loads(json_report.render(report))["summary"]["dependency"]
        self.assertEqual((dep["provider"], dep["exact_versions"],
                          dep["assessed_exact_versions"], dep["unassessed_exact_versions"]),
                         ("OSV", 2, 2, 0))
        self.assertEqual((dep["cache_hits"], dep["fresh_cache_hits"], dep["queries"]), (2, 2, 0))
        self.assertEqual(provider.calls, [])
        self.assertIn("在已取得情報的依賴範圍中", html.render(report))
        with patch("security_auditor.scanners.dependencies.cache.time.time", return_value=10**10):
            stale = ScanOrchestrator(dependency_provider=provider, dependency_cache=cache).run_scan(
                ScanRequest(self.target, AuditConfig(), ScanProfile.DEEP, True, False))
        self.assertEqual(stale.dependency.stale_cache_hits, 2)
        self.assertEqual(stale.dependency.assessed_exact_versions, 0)
        self.assertEqual(stale.dependency.unassessed_exact_versions, 2)
        self.assertEqual(stale.coverage.overall.value, "PARTIAL")
        self.assertEqual(evaluate_gate(json.loads(json_report.render(stale))).status, GateStatus.BLOCK)

    def test_mixed_cache_and_fake_provider_preserves_provenance(self):
        (self.target / "requirements.txt").write_text("requests==2.0.0\nurllib3==1.0.0\n",
                                                         encoding="utf-8")
        cache = VulnerabilityCache(self.base / "cache")
        cache.write(LookupResult(("PyPI", "requests", "2.0.0"), LookupStatus.NO_MATCH))
        provider = NoNetworkProvider()
        report = ScanOrchestrator(dependency_provider=provider, dependency_cache=cache).run_scan(
            ScanRequest(self.target, AuditConfig(), ScanProfile.DEEP, False, False))
        self.assertEqual((report.dependency.assessed_exact_versions,
                          report.dependency.unassessed_exact_versions,
                          report.dependency.cache_hits, report.dependency.queries),
                         (2, 0, 1, 1))
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(len(provider.calls[0]), 1)
        self.assertEqual(report.coverage.overall.value, "COMPLETE")

    def test_offline_no_cache_is_unassessed_and_gate_blocked(self):
        (self.target / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
        provider = NoNetworkProvider()
        report = ScanOrchestrator(dependency_provider=provider,
                                  dependency_cache=VulnerabilityCache(self.base / "empty-cache")).run_scan(
            ScanRequest(self.target, AuditConfig(), ScanProfile.DEEP, True, False))
        self.assertEqual((report.dependency.assessed_exact_versions,
                          report.dependency.unassessed_exact_versions), (0, 1))
        self.assertEqual(report.dependency.no_data, 1)
        self.assertEqual(provider.calls, [])
        self.assertEqual(evaluate_gate(json.loads(json_report.render(report))).status, GateStatus.BLOCK)

    def test_ai_no_eligible_is_distinct_from_disabled(self):
        low = make_finding(RULE, "behavior.static", "app.py", 2, 5,
                           anchor="exec", severity=Severity.INFO)
        scanner = ScannerResult(ScannerMetadata("behavior.static", "test", "behavior", True), (low,))
        online = replace(self.session, offline=False)
        provider = NoGeminiProvider()
        outcome = AIReviewer(AISettings(enabled=True), provider).review(
            online, (scanner,), allow_online_ai=True)
        self.assertEqual(outcome.summary.status, AIReviewStatus.NO_ELIGIBLE_ITEMS)
        self.assertEqual((outcome.summary.eligible, outcome.summary.completed, outcome.summary.requests),
                         (0, 0, 0))
        discovery = discover(online.target, DiscoveryPolicy())
        now = datetime.now(timezone.utc)
        report = assemble_report(online, discovery, (scanner,), None, outcome, None,
                                 ai_requested=True, started_at=now, completed_at=now,
                                 duration_seconds=0)
        self.assertEqual(json.loads(json_report.render(report))["summary"]["ai_status"],
                         "no_eligible_items")
        self.assertIn("無符合 AI 審查條件的項目", html.render(report))
        disabled = AIReviewer(AISettings(enabled=True), provider).review(
            self.session, (scanner,), allow_online_ai=True)
        self.assertEqual(disabled.summary.status, AIReviewStatus.DISABLED)

    def test_patch_ai_unavailable_does_not_change_review_status(self):
        finding = make_finding(RULE, "behavior.static", "app.py", 2, 5, anchor="exec")
        report = self._report(finding)
        settings = replace(AuditConfig().remediation, enabled=True)
        batch = RemediationPlanner(settings, AuditConfig().sast).plan(
            report, ai_remediation=True)
        self.assertIn("PATCH_AI_UNAVAILABLE", batch.diagnostics)
        self.assertEqual(report.ai_status, "disabled")


if __name__ == "__main__":
    unittest.main()
