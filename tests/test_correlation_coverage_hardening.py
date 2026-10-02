"""Synthetic data only: upstream path contract, invalid attribution, coverage layers."""

from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from test_correlation import finding, result
from security_auditor.core.config import AuditConfig
from security_auditor.core.models import Evidence, Location, ScanProfile, ScanSession, ScanTarget
from security_auditor.core.redaction import safe_finding_path
from security_auditor.correlation import CorrelationEngine, Completeness
from security_auditor.correlation.graph import _valid
from security_auditor.gate.service import evaluate_gate, GateStatus
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import console, html, json_report, sarif
from security_auditor.reporting.coverage_layers import coverage_layers
from security_auditor.reporting.models import assemble_report, CoverageStatus
from security_auditor.reporting.serialization import report_view


class CorrelationCoverageHardeningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-correlation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.network = patch("socket.create_connection", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.connect = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        self.connect.start()
        self.addCleanup(self.connect.stop)

    def scan(self):
        return ScanOrchestrator().run_scan(ScanRequest(self.root, AuditConfig(), ScanProfile.DEEP, True, False))

    def test_three_real_path_patterns_are_redacted_before_finding_and_admitted(self):
        path = self.root / "tests/unit/test_account_credential_storage.py"
        path.parent.mkdir(parents=True)
        lines = ["# inert\n"] * 445
        lines[56] = 'password = "Q7m2R9p4L1v6B8x3"\n'
        lines[440] = 'secret = "Z9x8C7v6B5n4M3a2"\n'
        lines[443] = '# bearer A1b2C3d4E5f6G7h8I9j0K1l2\n'
        path.write_text("".join(lines), encoding="utf-8")
        report = self.scan()
        secrets = next(r for r in report.scanner_results if r.scanner.id == "secrets")
        self.assertEqual([(f.rule_id, f.location.start_line) for f in secrets.findings], [
            ("SECRET.GENERIC.ASSIGNMENT", 57), ("SECRET.GENERIC.ASSIGNMENT", 441),
            ("SECRET.GENERIC.ENTROPY", 444)])
        for f in secrets.findings:
            self.assertEqual(f.location.path, "tests/unit/test_account_credential_[REDACTED]")
            self.assertEqual(safe_finding_path(f.location.path), f.location.path)
            self.assertTrue(_valid(f))
        self.assertNotIn("CORRELATION_INVALID_FINDING", {d.code for d in report.diagnostics})
        self.assertEqual(report.coverage.overall, CoverageStatus.COMPLETE)
        self.assertEqual({f.fingerprint for f in secrets.findings},
                         {g.primary for g in report.finding_groups if g.primary in {f.fingerprint for f in secrets.findings}})

    def test_large_text_path_uses_the_same_public_contract(self):
        path = self.root / "credential_storage.log"
        path.write_text('password = "Q7m2R9p4L1v6B8x3"\n' + '# inert\n' * 160000, encoding="utf-8")
        report = self.scan()
        secret = next(f for f in report.findings if f.scanner_id == "secrets")
        self.assertEqual(secret.location.path, "credential_[REDACTED]")
        self.assertTrue(_valid(secret))
        self.assertNotIn("CORRELATION_INVALID_FINDING", {d.code for d in report.diagnostics})

    def test_validator_keeps_rejecting_unredacted_path_and_malformed_evidence(self):
        raw = finding("SECRET.GENERIC.ASSIGNMENT", "secrets", "tests/credential_material.py", 3)
        bad_evidence = replace(raw, location=Location("tests/other.py", 8), evidence=Evidence("test", "", (None,)))
        invalid_fp = replace(raw, fingerprint="not-a-fingerprint", location=Location("src/third.py", 9))
        output = CorrelationEngine().correlate((result("secrets", raw, bad_evidence, invalid_fp),))
        self.assertEqual(output.summary.completeness, Completeness.PARTIAL)
        self.assertEqual(output.summary.admitted_findings, 0)
        notes = output.summary.diagnostics
        self.assertEqual(len(notes), 3)
        self.assertTrue(all(d.code == "CORRELATION_INVALID_FINDING" and d.count == 1 for d in notes))
        self.assertEqual({d.path for d in notes}, {"tests/credential_[REDACTED]", "tests/other.py", "src/third.py"})
        messages = " ".join(d.message for d in notes)
        for token in (raw.fingerprint, "input-3", "line=3", "line=8", "line=9", "rule=SECRET.GENERIC.ASSIGNMENT",
                      "reason=UNREDACTED_OR_UNSAFE_PATH", "reason=INVALID_STRUCTURED_EVIDENCE", "reason=INVALID_FINGERPRINT"):
            self.assertIn(token, messages)

    def test_diagnostic_privacy_and_bounded_overflow(self):
        secret = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        unsafe = finding("BEHAVIOR.PROCESS_EXEC", "behavior.static", "D:/private/source.py", 2)
        unsafe = replace(unsafe, title=secret, description=secret, evidence=Evidence("test", secret), rule_id=secret)
        output = CorrelationEngine().correlate((result("behavior.static", *([unsafe] * 103)),))
        notes = output.summary.diagnostics
        self.assertEqual(sum(d.count for d in notes), 103)
        self.assertEqual(len(notes), 101)
        self.assertTrue(all(d.path is None for d in notes))
        self.assertIn("reason=DETAILS_OMITTED", str(notes))
        serialized = json.dumps(asdict(output))
        self.assertNotIn(secret, serialized)
        self.assertNotIn("D:/private", serialized)
        aws = "AKIA" + "A1B2C3D4E5F6G7H8"
        contaminated_rule = replace(unsafe, rule_id=aws)
        guarded = CorrelationEngine().correlate((result("behavior.static", contaminated_rule),))
        self.assertNotIn(aws, json.dumps(asdict(guarded)))

    def test_invalid_attribution_survives_json_html_console_without_dropping_inventory(self):
        baseline = self.scan()
        bad = tuple(replace(finding("BEHAVIOR.PROCESS_EXEC", "behavior.static", f"src/file{n}.py", n),
                            evidence=Evidence("test", "", (None,))) for n in range(1, 4))
        inputs = (result("behavior.static", *bad),)
        correlated = CorrelationEngine().correlate(inputs)
        now = datetime.now(timezone.utc)
        session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"), ScanProfile.DEEP, now)
        # Public assembly receives a safe original inventory; correlation is tested with malformed copies.
        originals = (result("behavior.static", *(replace(f, evidence=Evidence("test", "[REDACTED]")) for f in bad)),)
        report = assemble_report(session, baseline.discovery, originals, correlated, None, None,
                                 ai_requested=False, started_at=now, completed_at=now, duration_seconds=0)
        self.assertEqual(len(report.findings), 3)
        view = report_view(report)
        self.assertEqual(view["schema_version"], "1.1")
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)
        for rendered in (json_report.render(report), html.render(report), console.render(report)):
            for n, f in enumerate(bad, 1):
                self.assertIn(f"src/file{n}.py", rendered)
                self.assertIn(f.fingerprint, rendered)
                self.assertIn("reason=INVALID_STRUCTURED_EVIDENCE", rendered)
            self.assertNotIn(str(self.root), rendered)

    def presentation_report(self, incomplete):
        report = self.scan()
        components = tuple(replace(c, status=CoverageStatus.PARTIAL,
                                   reasons=("DEPENDENCY_CACHE_STALE",) if c.component == "dependencies" else ())
                           if c.component in incomplete else c for c in report.coverage.components)
        return replace(report, coverage=replace(report.coverage, components=components, overall=CoverageStatus.PARTIAL))

    def assert_layers(self, incomplete, expected):
        report = self.presentation_report(incomplete)
        view = report_view(report)
        before = json_report.render(report)
        layers = coverage_layers(view["coverage"])
        self.assertEqual(tuple(layer.status for layer in layers), expected)
        terminal, page = console.render(report), html.render(report)
        for layer in layers:
            self.assertIn(f"{layer.key} {layer.status}", terminal)
            self.assertIn(f"{layer.key} {layer.status}", page)
        qualified = "Source-code finding inventory from enabled and supported deterministic analyzers is complete."
        self.assertEqual(qualified in terminal, expected[0] == "COMPLETE")
        self.assertEqual("目前已啟用且受支援的原始碼確定性分析器，其 Finding 清單已完整產生。" in page,
                         expected[0] == "COMPLETE")
        self.assertEqual(before, json_report.render(report))
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)
        self.assertEqual(json.loads(sarif.render(report))["version"], "2.1.0")

    def test_dependency_partial_only_presentation(self):
        self.assert_layers({"dependencies"}, ("COMPLETE", "PARTIAL", "COMPLETE"))

    def test_correlation_partial_only_presentation(self):
        self.assert_layers({"correlation"}, ("COMPLETE", "COMPLETE", "PARTIAL"))

    def test_source_partial_presentation(self):
        self.assert_layers({"sast.python"}, ("PARTIAL", "COMPLETE", "COMPLETE"))

    def test_dependency_and_correlation_partial_presentation(self):
        self.assert_layers({"dependencies", "correlation"}, ("COMPLETE", "PARTIAL", "PARTIAL"))

    def test_disabled_missing_or_truncated_never_claims_complete_inventory(self):
        report = self.scan()
        view = report_view(report)
        qualified = "Source-code finding inventory from enabled and supported deterministic analyzers is complete."
        for components in ([], [c for c in view["coverage"]["components"] if c["component"] != "sast.python"],
                           [dict(c, status="DISABLED") if c["component"] == "sast.python" else c
                            for c in view["coverage"]["components"]]):
            self.assertNotEqual(coverage_layers(dict(view["coverage"], components=components))[0].status, "COMPLETE")
        self.assertNotIn(qualified, console.render(replace(report, report_truncated=True)))
        for reason in ("REPORT_FINGERPRINT_COLLISION", "RULE_CATALOG_CONFLICT"):
            conflicted = replace(report, coverage=replace(report.coverage, reasons=(reason,), overall=CoverageStatus.PARTIAL))
            self.assertNotIn(qualified, console.render(conflicted))

    def test_upstream_incomplete_propagation_unchanged(self):
        output = CorrelationEngine().correlate((result("dependencies", completeness="partial"),))
        self.assertEqual(output.summary.completeness, Completeness.PARTIAL)
        self.assertEqual(output.summary.diagnostics, ())

    def test_cmd_process_group_and_sarif_reference_integrity(self):
        (self.root / "run.py").write_text("import subprocess\nsubprocess.run(['cmd.exe', '/c', 'echo', 'inert'])\n", encoding="utf-8")
        report = self.scan()
        self.assertNotIn("CORRELATION_INVALID_FINDING", {d.code for d in report.diagnostics})
        command = next(f for f in report.findings if f.rule_id == "BEHAVIOR.CMD_EXEC")
        process = next(f for f in report.findings if f.rule_id == "BEHAVIOR.PROCESS_EXEC")
        group = next(g for g in report.finding_groups if g.primary == command.fingerprint)
        self.assertIn((process.fingerprint, "supporting"), group.members)
        findings = {f.fingerprint for f in report.findings}
        self.assertTrue(all(g.primary in findings and all(fp in findings for fp, _ in g.members) for g in report.finding_groups))
        data = json.loads(sarif.render(report))
        relevant = [r for r in data["runs"][0]["results"] if r["ruleId"] in {command.rule_id, process.rule_id}]
        self.assertEqual(len(relevant), 2)
        self.assertTrue(all(r["properties"]["findingGroupId"] == group.id for r in relevant))


if __name__ == "__main__":
    unittest.main()
