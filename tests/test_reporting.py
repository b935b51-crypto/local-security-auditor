"""Phase 7 synthetic end-to-end and report security regressions."""

from __future__ import annotations

from dataclasses import replace
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.ai.models import AIUsage
from security_auditor.ai.providers import ProviderResponse
from security_auditor.cli.main import main
from security_auditor.core.config import AuditConfig, DiscoveryLimits, VulnerabilityLimits
from security_auditor.core.models import Location, ScanProfile
from security_auditor.gate.service import GateStatus, evaluate_gate
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import console, html, json_report, sarif
from security_auditor.reporting.models import CoverageStatus, ReportDiagnostic
from security_auditor.reporting.models import assemble_report
from security_auditor.reporting.output import ReportOutputError, write_text
from security_auditor.scanners.dependencies.models import LookupResult, LookupStatus, Vulnerability


class FakeOSV:
    def __init__(self):
        self.calls = []

    def lookup_batch(self, keys, limits):
        self.calls.append(tuple(keys))
        return tuple(LookupResult(key, LookupStatus.MATCHED,
                                  (Vulnerability("OSV-FAKE-1", summary="Synthetic advisory"),))
                     for key in keys)


class FakeGemini:
    provider_id = "gemini"
    model = "gemini-3.8-flash"

    def __init__(self):
        self.calls = []

    def review(self, context, **kwargs):
        self.calls.append(context)
        payload = {"verdict": "LIKELY_FALSE_POSITIVE", "confidence": "MEDIUM",
                   "summary": "<script>alert(1)</script>", "rationale": ["synthetic"],
                   "supporting_evidence": [], "contradictory_evidence": [],
                   "missing_context": [], "remediation": [], "limitations": []}
        return ProviderResponse(json.dumps(payload), AIUsage(20, 10, 30))


class ReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-report-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "synthetic"
        self.root.mkdir()
        # Text is inert data. No target file is imported or executed.
        self.fake_secret = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        self.fake_key = "AIza" + "A" * 35
        (self.root / "app.py").write_text(
            "import os\nimport subprocess\ncredential = '" + self.fake_secret +
            "'\ncommand = input()\nos.system(command)\nsubprocess.run(['tool.exe'])\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
        (self.root / "safe.py").write_text("import subprocess\nsubprocess.run(['echo','ok'],shell=False)\n", encoding="utf-8")

    def report(self, *, profile=ScanProfile.STANDARD, offline=True, ai=False, osv=None, gemini=None,
               config=None):
        return ScanOrchestrator(dependency_provider=osv, ai_provider=gemini).run_scan(
            ScanRequest(self.root, config or AuditConfig(), profile, offline, ai))

    def test_end_to_end_and_formats_are_safe(self):
        osv = FakeOSV()
        gemini = FakeGemini()
        with patch.dict(os.environ, {"GEMINI_API_KEY": self.fake_key}):
            report = self.report(profile=ScanProfile.DEEP, offline=False, ai=True,
                                 osv=osv, gemini=gemini,
                                 config=replace(AuditConfig(), vulnerability=VulnerabilityLimits(cache_enabled=False)))
        self.assertTrue(osv.calls)
        self.assertTrue(gemini.calls)
        self.assertTrue(any(f.category == "secret" for f in report.findings))
        self.assertTrue(any(f.scanner_id.startswith("sast") for f in report.findings),
                        [(r.scanner.id, r.status, r.summary.artifacts_scanned if r.summary else None,
                          [d.code for d in r.diagnostics]) for r in report.scanner_results])
        self.assertTrue(any(f.scanner_id.startswith("behavior") for f in report.findings))
        self.assertTrue(any(f.scanner_id == "dependencies" for f in report.findings))
        self.assertTrue(report.risk_assessments)
        self.assertEqual(report.ai_status, "complete")
        rendered = [console.render(report), json_report.render(report), sarif.render(report), html.render(report)]
        for item in rendered:
            self.assertFalse(self.fake_secret in item)
            self.assertFalse(self.fake_key in item)
        canonical = json.loads(rendered[1])
        self.assertEqual(canonical["schema_version"], "1.1")
        self.assertEqual(canonical["summary"]["counts"]["total_findings"], len(report.findings))
        self.assertEqual(rendered[1], json_report.render(report))
        sarif_data = json.loads(rendered[2])
        self.assertEqual(sarif_data["version"], "2.1.0")
        rules = {r["id"] for r in sarif_data["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue(all(r["ruleId"] in rules for r in sarif_data["runs"][0]["results"]))
        for item in sarif_data["runs"][0]["results"]:
            for location in item.get("locations", []):
                self.assertFalse(location["physicalLocation"]["artifactLocation"]["uri"].startswith(("/", "C:")))
        self.assertNotIn("<script>", rendered[3])
        self.assertIn("&lt;script&gt;", rendered[3])

    def test_offline_and_profile_semantics(self):
        gemini = FakeGemini()
        quick = self.report(profile=ScanProfile.QUICK, offline=True, ai=True, gemini=gemini,
                            config=replace(AuditConfig(), limits=DiscoveryLimits(max_file_size_bytes=1)))
        self.assertEqual(gemini.calls, [])
        self.assertEqual(quick.ai_status, "disabled")
        self.assertFalse(any(r.scanner.id == "sast" for r in quick.scanner_results))
        self.assertEqual(quick.coverage.overall, CoverageStatus.PARTIAL)
        self.assertIn("SCAN COVERAGE: PARTIAL", console.render(quick))
        self.assertIn("掃描覆蓋率：部分完成", html.render(quick))
        self.assertEqual(json.loads(sarif.render(quick))["runs"][0]["properties"]["scanCoverage"]["overall"], "PARTIAL")

    def test_report_injection_and_unicode(self):
        report = self.report()
        target = replace(report, target_display="<svg onload=alert(1)>\x1b[31m中文😀")
        diagnostic = ReportDiagnostic("test", "INJECT", "<svg onload=alert(1)>\rINJECT")
        target = replace(target, diagnostics=(diagnostic,))
        outputs = [console.render(target), json_report.render(target), sarif.render(target), html.render(target)]
        self.assertNotIn("\x1b", outputs[0])
        self.assertNotIn("\r", outputs[0])
        self.assertNotIn("<svg", outputs[3])
        self.assertIn("&lt;svg", outputs[3])
        self.assertIn("中文😀", outputs[3])
        json.loads(outputs[1]); json.loads(outputs[2])

    def test_html_zh_tw_safe_wording_and_machine_formats(self):
        report = self.report()
        rendered = html.render(report)
        self.assertIn('<html lang="zh-TW">', rendered)
        for label in ("本機安全掃描器", "掃描目標", "掃描覆蓋率", "掃描摘要",
                      "確定性掃描結果", "問題群組", "潛在攻擊路徑", "依賴套件漏洞",
                      "AI 輔助審查", "修復建議", "掃描覆蓋率與診斷", "隱私與外部服務"):
            self.assertIn(label, rendered)
        self.assertIn("離線模式：是", rendered)
        self.assertIn("使用 Gemini AI：否", rendered)
        self.assertNotIn("True", rendered)
        self.assertNotIn("False", rendered)
        for unsafe in ("此專案安全", "沒有漏洞", "掃描通過"):
            self.assertNotIn(unsafe, rendered)
        self.assertIn("Content-Security-Policy", rendered)
        self.assertNotIn("<script", rendered)
        self.assertEqual(json.loads(json_report.render(report))["schema_version"], "1.1")

    def test_html_partial_zero_finding_warning(self):
        quick = self.report(profile=ScanProfile.QUICK,
                            config=replace(AuditConfig(), limits=DiscoveryLimits(max_file_size_bytes=1)))
        rendered = html.render(quick)
        self.assertIn("警告：本次掃描覆蓋範圍不完整", rendered)
        self.assertIn("在已完成分析的範圍內未偵測到安全問題。", rendered)

    def test_html_ast_diagnostic_preserves_code_and_relative_path(self):
        report = self.report()
        report = replace(report, diagnostics=(ReportDiagnostic(
            "sast.python", "SAST_AST_DEPTH_LIMIT_REACHED", "Python AST depth limit reached",
            "src/synthetic.py"),))
        rendered = html.render(report)
        self.assertIn("src/synthetic.py</code>：<code>SAST_AST_DEPTH_LIMIT_REACHED", rendered)
        self.assertIn("Python AST 深度已達安全分析上限。", rendered)
        self.assertNotIn(str(self.root), rendered)

    def test_root_identity_and_oversize_path_survive_public_reports(self):
        (self.root / "pyproject.toml").write_text('[project]\nname="demo"\n', encoding="utf-8")
        (self.root / "uv.lock").write_text(
            '[[package]]\nname="demo"\nversion="0.1.0"\nsource={editable="."}\n', encoding="utf-8")
        (self.root / "logs").mkdir()
        (self.root / "logs" / "big.log").write_bytes(b"SYNTHETIC DATA\n" * 75000)
        report = self.report(config=replace(AuditConfig(), vulnerability=VulnerabilityLimits(cache_enabled=False)))
        view = json.loads(json_report.render(report))
        dependency = view["summary"]["dependency"]
        self.assertEqual(dependency["first_party_roots"], 1)
        self.assertEqual(dependency["unresolved_third_party"], 0)
        self.assertGreater(dependency["no_data"], 0)
        self.assertNotIn("DEPENDENCY_UNRESOLVED_VERSION", view["coverage"]["reasons"])
        oversized = next(d for d in view["diagnostics"] if d["code"] == "SECRET_FILE_TOO_LARGE")
        self.assertEqual(oversized["path"], "logs/big.log")
        self.assertNotIn(str(self.root), json.dumps(oversized))
        rendered = html.render(report)
        self.assertIn("logs/big.log", rendered)
        self.assertIn("第一方專案根套件：1", rendered)
        self.assertIn("未解析的第三方依賴：0", rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)

    def test_oversize_secret_shaped_filename_is_redacted_in_public_reports(self):
        fake_token = "ghp_" + ("A1b2C3d4" * 5)[:36]
        (self.root / f"0-{fake_token}.log").write_bytes(b"SYNTHETIC DATA\n" * 75000)
        report = self.report()
        json_text = json_report.render(report)
        html_text = html.render(report)
        self.assertNotIn(fake_token, json_text)
        self.assertNotIn(fake_token, html_text)
        diagnostic = next(d for d in json.loads(json_text)["diagnostics"]
                          if d["code"] == "SECRET_FILE_TOO_LARGE")
        self.assertIn("[REDACTED]", diagnostic["path"])

    def test_last_output_boundary_drops_raw_snippet_and_redacts_key(self):
        report = self.report()
        first = report.findings[0]
        contaminated = replace(first, title=self.fake_key,
                               location=Location(self.fake_key + ".py", 1),
                               evidence=replace(first.evidence, redacted_snippet=self.fake_secret))
        report = replace(report, target_display=self.fake_key,
                         findings=(contaminated,),
                         diagnostics=(ReportDiagnostic("test", "SYNTHETIC", self.fake_key),))
        for rendered in (console.render(report), json_report.render(report),
                         sarif.render(report), html.render(report)):
            self.assertFalse(self.fake_key in rendered)
            self.assertFalse(self.fake_secret in rendered)

    def test_cli_stdout_purity_and_errors(self):
        for format_name in ("json", "sarif"):
            out, err = StringIO(), StringIO()
            with patch("sys.stdout", out), patch("sys.stderr", err):
                code = main(["scan", str(self.root), "--format", format_name, "--offline"])
            self.assertEqual(code, 0)
            self.assertEqual(err.getvalue(), "")
            json.loads(out.getvalue())
        out, err = StringIO(), StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(main(["scan", str(self.root), "--format", "json",
                                   "--offline", "--verbose"]), 0)
        json.loads(out.getvalue())
        self.assertNotIn(self.fake_secret, err.getvalue())
        with patch("sys.stdout", StringIO()), patch("sys.stderr", StringIO()):
            self.assertEqual(main(["scan", str(self.root / "missing")]), 3)
            self.assertEqual(main(["scan", str(self.root / "app.py")]), 3)

    def test_output_atomic_overwrite_and_unsafe_path(self):
        destination = self.root.parent / "report.json"
        write_text(destination, "first")
        self.assertEqual(destination.read_text(), "first")
        with self.assertRaises(ReportOutputError) as error:
            write_text(destination, "second")
        self.assertEqual(error.exception.code, "REPORT_OUTPUT_EXISTS")
        self.assertEqual(destination.read_text(), "first")
        write_text(destination, "second", force=True)
        self.assertEqual(destination.read_text(), "second")
        link = self.root.parent / "link.json"
        try:
            link.symlink_to(destination)
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(ReportOutputError):
            write_text(link, "unsafe", force=True)
        self.assertEqual(destination.read_text(), "second")

    def test_atomic_write_failure_leaves_no_final_file(self):
        destination = self.root.parent / "unwritten.json"
        with patch("security_auditor.reporting.output.os.link", side_effect=OSError()):
            with self.assertRaises(ReportOutputError):
                write_text(destination, "new")
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.root.parent.glob(".security-auditor-*.tmp")))

    def test_scanner_failure_isolated_and_partial(self):
        with patch("security_auditor.orchestrator.service.SASTScanner.scan_discovery",
                   side_effect=RuntimeError("FAKE_SECRET_MUST_NOT_APPEAR")):
            report = self.report()
        self.assertTrue(any(f.category == "secret" for f in report.findings))
        self.assertEqual(report.coverage.overall, CoverageStatus.PARTIAL)
        self.assertIn("SCANNER_INTERNAL_ERROR", {d.code for d in report.diagnostics})
        self.assertNotIn("FAKE_SECRET_MUST_NOT_APPEAR", json_report.render(report))

    def test_report_truncation_is_explicit(self):
        from datetime import datetime, timezone
        from security_auditor.core.models import ScanSession, ScanTarget
        report = self.report()
        first = report.findings[0]
        original = report.scanner_results[0]
        result = replace(original, findings=tuple(replace(first, id=f"{i:016x}",
                                                         fingerprint=f"{i:064x}")
                                                  for i in range(1001)))
        now = datetime.now(timezone.utc)
        session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"), ScanProfile.STANDARD, now)
        limited = assemble_report(session, report.discovery, (result,), None, None, None,
                                  ai_requested=False, started_at=now, completed_at=now,
                                  duration_seconds=0)
        self.assertTrue(limited.report_truncated)
        view = json.loads(json_report.render(limited))
        self.assertEqual(view["summary"]["counts"]["total_findings"], 1001)
        self.assertEqual(view["summary"]["counts"]["rendered_findings"], 1000)
        self.assertEqual(view["coverage"]["overall"], "PARTIAL")

    def test_cli_html_and_threshold(self):
        destination = self.root.parent / "audit.html"
        with patch("sys.stdout", StringIO()), patch("sys.stderr", StringIO()):
            self.assertEqual(main(["scan", str(self.root), "--format", "html",
                                   "--output", str(destination), "--offline"]), 0)
        self.assertIn("<!doctype html>", destination.read_text(encoding="utf-8"))
        with patch("sys.stdout", StringIO()), patch("sys.stderr", StringIO()):
            self.assertEqual(main(["scan", str(self.root), "--fail-on", "high"]), 10)

    def test_ai_only_opt_in_does_not_enable_osv(self):
        osv, gemini = FakeOSV(), FakeGemini()
        with patch.dict(os.environ, {"GEMINI_API_KEY": self.fake_key}):
            report = self.report(offline=None, ai=True, osv=osv, gemini=gemini)
        self.assertFalse(osv.calls)
        self.assertTrue(gemini.calls)
        self.assertFalse(report.offline)


if __name__ == "__main__":
    unittest.main()
