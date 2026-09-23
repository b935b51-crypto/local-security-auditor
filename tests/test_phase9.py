"""Phase 9 synthetic gate and GUI controller regressions; no target code runs."""

from __future__ import annotations

from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.cli.main import main
from security_auditor.ai.models import AIUsage
from security_auditor.ai.providers.base import ProviderResponse
from security_auditor.core.config import AuditConfig, VulnerabilityLimits
from security_auditor.gate import (GateReportError, SecurityGatePolicy, evaluate_gate,
                                   load_report)
from security_auditor.gate.service import GateStatus
from security_auditor.gate.service import MAX_REPORT_BYTES
from security_auditor.gui.controller import ApplicationController, ControllerEvent, ScanOptions
from security_auditor.gui.view_models import (coverage_message, display_text,
                                               public_patch_text, visible_findings)
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting.serialization import report_view


class Phase9Tests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="auditor-phase9-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "synthetic"
        self.root.mkdir()
        self.path = self.root / "app.py"
        self.config = replace(AuditConfig(), vulnerability=VulnerabilityLimits(enabled=False))

    def scan(self, source: str = "value = 1\n") -> dict:
        self.path.write_text(source, encoding="utf-8")
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, self.config, offline=True))
        return report_view(report)

    def test_complete_clean_passes_and_partial_empty_blocks(self) -> None:
        view = self.scan()
        self.assertEqual(evaluate_gate(view).status, GateStatus.PASS)
        partial = json.loads(json.dumps(view))
        partial["coverage"]["overall"] = "PARTIAL"
        self.assertEqual(evaluate_gate(partial).status, GateStatus.BLOCK)
        self.assertIn("Coverage is incomplete", coverage_message(partial))
        self.assertEqual(evaluate_gate(partial, SecurityGatePolicy(partial_coverage=GateStatus.WARN)).status,
                         GateStatus.WARN)

    def test_high_sast_blocks_and_ai_cannot_override(self) -> None:
        view = self.scan("import os\nvalue = input()\nos.system(value)\n")
        high = [f for f in view["findings"] if f["scanner_id"].startswith("sast") and f["severity"] == "HIGH"]
        self.assertTrue(high)
        result = evaluate_gate(view)
        self.assertEqual(result.status, GateStatus.BLOCK)
        self.assertIn(high[0]["fingerprint"], result.blocking_findings)
        view["ai_reviews"].append({"subject_id": high[0]["fingerprint"],
                                   "verdict": "LIKELY_FALSE_POSITIVE", "confidence": "HIGH",
                                   "summary": "synthetic advisory", "rationale": [],
                                   "supporting_evidence": [], "contradictory_evidence": [],
                                   "missing_context": [], "remediation": [], "limitations": []})
        self.assertEqual(evaluate_gate(view).blocking_findings, result.blocking_findings)

    def test_secret_blocks_and_behavior_does_not(self) -> None:
        view = self.scan("import os\nos.system('echo hello')\n")
        self.assertEqual(evaluate_gate(view).status, GateStatus.WARN)
        self.assertFalse(evaluate_gate(view).blocking_findings)
        key = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        view = self.scan("credential = '" + key + "'\n")
        self.assertTrue(any(f["category"] == "secret" for f in view["findings"]))
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)

    def test_dependency_no_data_warns_and_policy_can_block(self) -> None:
        view = self.scan()
        view["summary"]["dependency"]["no_data"] = 1
        self.assertEqual(evaluate_gate(view).status, GateStatus.WARN)
        self.assertEqual(evaluate_gate(view, SecurityGatePolicy(dependency_no_data=GateStatus.BLOCK)).status,
                         GateStatus.BLOCK)

    def test_medium_sast_warns_and_high_exact_dependency_blocks(self) -> None:
        view = self.scan("import os\nvalue = input()\nos.system(value)\n")
        sast = next(f for f in view["findings"] if f["scanner_id"].startswith("sast"))
        sast["severity"] = "MEDIUM"
        sast["risk_priority"] = None
        self.assertEqual(evaluate_gate(view).status, GateStatus.WARN)
        sast["severity"] = "HIGH"
        sast["scanner_id"] = "dependencies"
        sast["category"] = "dependency"
        sast["confidence"] = "HIGH"
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)

    def test_supporting_not_double_counted(self) -> None:
        view = self.scan("import os\nvalue = input()\nos.system(value)\n")
        behavior = next(f for f in view["findings"] if f["scanner_id"].startswith("behavior"))
        behavior["role"] = "supporting"
        result = evaluate_gate(view)
        self.assertEqual(len(result.blocking_findings), 1)
        self.assertTrue(any(f["role"] == "supporting" for f in view["findings"]))

    def test_invalid_report_rejected(self) -> None:
        view = self.scan()
        for mutate in (lambda x: x.pop("coverage"),
                       lambda x: x.update(schema_version="2.0"),
                       lambda x: x["summary"]["counts"].update(rendered_findings=999),
                       lambda x: x["coverage"].update(overall="SAFE"),
                       lambda x: x["coverage"]["components"][0].update(status="PARTIAL")):
            damaged = json.loads(json.dumps(view))
            mutate(damaged)
            with self.assertRaises(GateReportError):
                evaluate_gate(damaged)
        contaminated = self.scan("import os\nvalue = input()\nos.system(value)\n")
        contaminated["findings"][0]["fingerprint"] = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        with self.assertRaises(GateReportError):
            evaluate_gate(contaminated)

    def test_bounded_loader_duplicate_keys_and_cli_json(self) -> None:
        view = self.scan()
        path = self.root.parent / "report.json"
        path.write_text(json.dumps(view), encoding="utf-8")
        self.assertEqual(load_report(path)["schema_version"], "1.1")
        stdout, stderr = StringIO(), StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = main(["gate", str(path), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "PASS")
        path.write_text('{"schema_version":"1.1","schema_version":"1.1"}', encoding="utf-8")
        with self.assertRaises(GateReportError):
            load_report(path)
        with path.open("wb") as stream:
            stream.truncate(MAX_REPORT_BYTES + 1)
        with self.assertRaises(GateReportError):
            load_report(path)

    def test_gate_cli_block_exit_and_no_rescan(self) -> None:
        view = self.scan()
        view["coverage"]["overall"] = "PARTIAL"
        path = self.root.parent / "report.json"
        path.write_text(json.dumps(view), encoding="utf-8")
        with patch("sys.stdout", StringIO()) as stdout:
            code = main(["gate", str(path), "--format", "json"])
        self.assertEqual(code, 20)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "BLOCK")

    def test_gate_cli_warn_exit(self) -> None:
        view = self.scan()
        view["summary"]["dependency"]["no_data"] = 1
        path = self.root.parent / "warn.json"
        path.write_text(json.dumps(view), encoding="utf-8")
        with patch("sys.stdout", StringIO()) as stdout:
            code = main(["gate", str(path), "--format", "json"])
        self.assertEqual(code, 10)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "WARN")

    def test_gui_view_models_plain_text_and_public_diff(self) -> None:
        view = self.scan()
        self.assertEqual(visible_findings(view), [])
        self.assertNotIn("\x1b", display_text("<script>\x1b[31m\u202e"))
        self.assertNotIn("\u202e", display_text("\u202e"))
        self.assertIn("測試", display_text("測試🔒"))
        fake = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        proposal = {"patch_candidate": {"unified_diff": "@@ -1 +1 @@\n-" + fake + "\n+safe\n"}}
        self.assertNotIn(fake, public_patch_text(proposal))

    def test_controller_scans_synthetic_and_can_cancel(self) -> None:
        self.path.write_text("value = 1\n", encoding="utf-8")
        original = self.path.read_bytes()
        controller = ApplicationController()
        controller.start_scan(self.root, ScanOptions())
        controller.worker.join(timeout=10)
        self.assertFalse(controller.running)
        self.assertIsNotNone(controller.public_report)
        self.assertIsNotNone(controller.gate)
        self.assertEqual(controller.gate.status, GateStatus.PASS)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(any(controller.public_report["summary"]["external_services"].values()))
        self.assertTrue(any(e.kind == "complete" for e in controller.poll()))
        event = Event(); event.set()
        aborted = ScanOrchestrator().run_scan(ScanRequest(self.root, self.config, offline=True,
                                                         cancel_event=event))
        self.assertEqual(aborted.coverage.overall.value, "ABORTED")
        self.assertEqual(evaluate_gate(report_view(aborted)).status, GateStatus.BLOCK)

    def test_open_existing_report_is_read_only(self) -> None:
        view = self.scan()
        path = self.root.parent / "existing.json"
        path.write_text(json.dumps(view), encoding="utf-8")
        controller = ApplicationController()
        controller.open_report(path)
        self.assertIsNone(controller.report)
        self.assertEqual(controller.gate.status, GateStatus.PASS)
        self.assertEqual(controller.public_report["schema_version"], "1.1")
        path.write_text("{bad json", encoding="utf-8")
        with self.assertRaises(GateReportError):
            controller.open_report(path)

    def test_no_apply_option_and_gui_import_is_lazy(self) -> None:
        with patch.dict(sys.modules, {"tkinter": None}):
            from security_auditor.core.config import AuditConfig as ImportedConfig
            self.assertIsNotNone(ImportedConfig())
            from security_auditor.cli.main import parser
            self.assertIn("scan", parser().format_help())
        with self.assertRaises(ValueError):
            ScanOptions(ai_remediation=True)

    def test_gemini_only_gui_grant_does_not_enable_osv(self) -> None:
        class FakeGemini:
            provider_id = "gemini"
            model = "gemini-3.8-flash"

            def __init__(self) -> None:
                self.calls = 0

            def review(self, _context, **_kwargs):
                self.calls += 1
                return ProviderResponse(json.dumps({"verdict": "LIKELY_FALSE_POSITIVE",
                    "confidence": "MEDIUM", "summary": "synthetic advisory", "rationale": [],
                    "supporting_evidence": [], "contradictory_evidence": [],
                    "missing_context": [], "remediation": [], "limitations": []}), AIUsage(1, 1, 2))

        class FakeOSV:
            def __init__(self) -> None:
                self.calls = 0

            def lookup_batch(self, *_args):
                self.calls += 1
                return ()

        self.path.write_text("import os\nvalue = input()\nos.system(value)\n", encoding="utf-8")
        gemini, osv = FakeGemini(), FakeOSV()
        controller = ApplicationController(ScanOrchestrator(ai_provider=gemini, dependency_provider=osv))
        fake_key = "AIza" + "A" * 35
        with patch.dict("os.environ", {"GEMINI_API_KEY": fake_key}):
            controller.start_scan(self.root, ScanOptions(offline=False, ai_review=True))
            controller.worker.join(timeout=10)
        self.assertFalse(controller.running)
        self.assertEqual(osv.calls, 0)
        self.assertGreater(gemini.calls, 0)
        self.assertTrue(controller.public_report["ai_reviews"])
        self.assertEqual(controller.gate.status, GateStatus.BLOCK)

    def test_all_tk_views_render_and_no_apply_action(self) -> None:
        try:
            import tkinter as tk
            from tkinter import ttk
        except ImportError:
            self.skipTest("Tk desktop unavailable")
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Tk desktop unavailable")
        self.addCleanup(root.destroy)
        root.withdraw()
        from security_auditor.gui.app import AuditorApp, _VIEWS
        self.path.write_text("import requests\nrequests.get(url, verify=False)\n", encoding="utf-8")
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, self.config, offline=True,
                                                         propose_fixes=True))
        controller = ApplicationController()
        controller.report = report
        controller.public_report = report_view(report)
        controller.gate = evaluate_gate(controller.public_report)
        app = AuditorApp(root, controller)

        def widget_texts(widget):
            values = [widget.get("1.0", "end") for _ in (0,) if isinstance(widget, tk.Text)]
            for child in widget.winfo_children():
                values.extend(widget_texts(child))
            return values

        for view in _VIEWS:
            app.current_view = view
            app._render()
            root.update_idletasks()
        app.current_view = "Dashboard"
        app._render()
        self.assertIn("OFFLINE MODE", " ".join(widget_texts(app.main)))
        app.current_view = "Remediation"
        app._render()
        self.assertIn("Patch provenance", " ".join(widget_texts(app.main)))

        def button_texts(widget):
            texts = [widget.cget("text") for _ in (0,) if isinstance(widget, ttk.Button)]
            for child in widget.winfo_children():
                texts.extend(button_texts(child))
            return texts

        labels = button_texts(root)
        self.assertFalse(any(label.lower().startswith(("apply", "fix", "save to source"))
                             for label in labels))
        self.assertIn("Copy public proposal", labels)
        proposal = next(p for p in controller.public_report["remediation_proposals"]
                        if p["patch_candidate"])
        app._copy_proposal(proposal)
        public_copy = root.clipboard_get()
        self.assertIn("verify=True", public_copy)
        fake = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        with patch("security_auditor.gui.app.messagebox.showwarning") as warning:
            app._copy_proposal({"patch_candidate": {"unified_diff": "-" + fake + "\n+safe\n"}})
        self.assertTrue(warning.called)
        self.assertEqual(root.clipboard_get(), public_copy)
        dependency_view = json.loads(json.dumps(controller.public_report))
        finding = dependency_view["findings"][0]
        finding["scanner_id"] = "dependencies"
        finding["category"] = "dependency"
        finding["role"] = "primary"
        finding["dependency"] = {"ecosystem": "PyPI", "name": "demo-package",
                                  "version": "1.0.0", "direct": True}
        finding["vulnerability"] = {"id": "OSV-SYNTHETIC", "source": "OSV",
                                    "fixed_versions": ["1.0.1"]}
        controller.public_report = dependency_view
        app.current_view = "Dependencies"
        app._render()
        app.table.selection_set("0")
        app._show_finding()
        self.assertIn("demo-package", app.detail.get("1.0", "end"))
        self.assertIn("1.0.1", app.detail.get("1.0", "end"))
        partial = json.loads(json.dumps(controller.public_report))
        partial["coverage"]["overall"] = "PARTIAL"
        controller.public_report = partial
        controller.gate = evaluate_gate(partial)
        controller.events.put(ControllerEvent("complete", "PARTIAL"))
        app._poll()
        self.assertIn("COVERAGE PARTIAL", app.banner.cget("text"))
        self.assertIn("SECURITY GATE BLOCK", app.banner.cget("text"))


if __name__ == "__main__":
    unittest.main()
