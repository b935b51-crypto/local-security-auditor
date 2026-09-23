"""Phase 8 inert synthetic proposals; no target content is executed or modified."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.ai.providers.base import ProviderResponse
from security_auditor.core.config import AuditConfig, RemediationSettings, SASTLimits, VulnerabilityLimits, load_config
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.remediation.models import ProposalStatus, RemediationStrategy
from security_auditor.remediation.patching import LineEdit, validate_patch
from security_auditor.reporting import console, html, json_report, sarif


class FakePatchProvider:
    provider_id = "gemini"
    model = "gemini-3.8-flash"

    def __init__(self, replacement="result = yaml.safe_load(data)\n", target="app.py"):
        self.calls = []
        self.replacement = replacement
        self.target = target

    def propose_patch(self, context, **kwargs):
        self.calls.append(context)
        return ProviderResponse(json.dumps({"can_propose_patch": True,
            "target_file": self.target, "assumptions": [], "rationale": ["synthetic"],
            "limitations": [], "replacements": [{"start_line": 3, "end_line": 3,
                                                    "replacement": self.replacement}]}))


class RemediationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="auditor-phase8-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "synthetic"
        self.root.mkdir()
        self.path = self.root / "app.py"
        self.config = replace(AuditConfig(), vulnerability=VulnerabilityLimits(enabled=False))

    def scan(self, *, ai=False, offline=True, provider=None):
        return ScanOrchestrator(ai_provider=provider).run_scan(ScanRequest(
            self.root, self.config, offline=offline, propose_fixes=True,
            ai_remediation_requested=ai))

    def test_tls_patch_is_static_and_never_writes_target(self):
        source = b"import requests\nrequests.get(url, verify=False)\n"
        self.path.write_bytes(source)
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        report = self.scan()
        proposal = next(p for p in report.remediation_proposals
                        if p.strategy is RemediationStrategy.DETERMINISTIC)
        self.assertEqual(proposal.status, ProposalStatus.VALIDATED_STATICALLY)
        self.assertTrue(proposal.human_approval_required)
        self.assertTrue(proposal.validation_result.target_finding_removed)
        self.assertEqual(proposal.validation_result.runtime_tests_status, "NOT_RUN")
        self.assertIn("+requests.get(url, verify=True)", proposal.patch_candidate.unified_diff)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), before)
        data = json.loads(json_report.render(report))
        self.assertEqual(data["schema_version"], "1.1")
        self.assertTrue(data["remediation_proposals"][0]["human_approval_required"])
        self.assertTrue(all(p["runtime_tests_status"] == "NOT_RUN" for p in data["remediation_proposals"]))
        self.assertIn("Remediation proposals", console.render(report))
        self.assertIn("Remediation proposals", html.render(report))
        self.assertNotIn("fixes", json.loads(sarif.render(report))["runs"][0]["results"][0])

    def test_crlf_and_unicode_preserved(self):
        source = "import requests\r\nlabel = '測試'\r\nrequests.get(url, verify=False)\r\n".encode("utf-8")
        self.path.write_bytes(source)
        report = self.scan()
        proposal = next(p for p in report.remediation_proposals if p.patch_candidate)
        self.assertEqual(proposal.status, ProposalStatus.VALIDATED_STATICALLY)
        self.assertEqual(self.path.read_bytes(), source)

    def test_ai_patch_requires_separate_opt_in_and_uses_fake_provider(self):
        source = b"import yaml\ndata = input()\nresult = yaml.load(data)\n"
        self.path.write_bytes(source)
        fake = FakePatchProvider()
        key = "AIza" + "F" * 35  # clearly fake fixture, never a real credential
        with patch.dict(os.environ, {"GEMINI_API_KEY": key}):
            offline = self.scan(ai=True, offline=True, provider=fake)
            self.assertFalse(fake.calls)
            online = self.scan(ai=True, offline=False, provider=fake)
        self.assertEqual(len(fake.calls), 1)
        self.assertNotIn(key, fake.calls[0])
        self.assertTrue(any(p.strategy is RemediationStrategy.AI_ASSISTED and p.patch_candidate
                            for p in online.remediation_proposals))
        ai_patch = next(p.patch_candidate for p in online.remediation_proposals if p.patch_candidate)
        self.assertEqual((ai_patch.provider, ai_patch.model, ai_patch.prompt_version),
                         ("gemini", "gemini-3.8-flash", "patch-v1"))
        self.assertEqual(self.path.read_bytes(), source)
        self.assertFalse(any(p.patch_candidate for p in offline.remediation_proposals))
        for rendered in (json_report.render(online), html.render(online), console.render(online)):
            self.assertNotIn(key, rendered)

    def test_ai_scope_suppression_and_destructive_are_rejected(self):
        self.path.write_text("import yaml\ndata = input()\nresult = yaml.load(data)\n", encoding="utf-8")
        key = "AIza" + "F" * 35
        for replacement, target, expected in (
            ("result = yaml.safe_load(data)\n", "../other.py", "PATCH_SCOPE_VIOLATION"),
            ("# nosec\nresult = yaml.safe_load(data)\n", "app.py", "PATCH_SECURITY_SUPPRESSION_DETECTED"),
            ("pass\n", "app.py", "PATCH_DESTRUCTIVE_CHANGE"),
            ("result = yaml.safe_load(\n", "app.py", "PATCH_SYNTAX_INVALID"),
            ("eval(data)\n", "app.py", "PATCH_NEW_HIGH_FINDING"),
            ("result = yaml.safe_load(data); import pickle; pickle.loads(data)\n", "app.py", "PATCH_NEW_HIGH_FINDING"),
        ):
            with self.subTest(expected=expected):
                fake = FakePatchProvider(replacement, target)
                with patch.dict(os.environ, {"GEMINI_API_KEY": key}):
                    report = self.scan(ai=True, offline=False, provider=fake)
                self.assertIn(expected, report.remediation_diagnostics)
                self.assertFalse(any(p.patch_candidate for p in report.remediation_proposals))

    def test_ai_secret_echo_is_rejected_without_report_leak(self):
        fake_secret = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        self.path.write_text("import yaml\ndata = input()\nresult = yaml.load(data)\n", encoding="utf-8")
        key = "AIza" + "F" * 35
        fake = FakePatchProvider("result = yaml.safe_load(data); token='" + fake_secret + "'\n")
        with patch.dict(os.environ, {"GEMINI_API_KEY": key}):
            report = self.scan(ai=True, offline=False, provider=fake)
        self.assertIn("PATCH_SECRET_EXPOSURE", report.remediation_diagnostics)
        for rendered in (json_report.render(report), html.render(report), console.render(report), sarif.render(report)):
            self.assertNotIn(fake_secret, rendered)
            self.assertNotIn(key, rendered)

    def test_ai_response_cannot_echo_api_key(self):
        self.path.write_text("import yaml\ndata = input()\nresult = yaml.load(data)\n", encoding="utf-8")
        key = "AIza" + "F" * 35
        class EchoProvider(FakePatchProvider):
            def propose_patch(self, context, **kwargs):
                self.calls.append(context)
                return ProviderResponse(kwargs["api_key"])
        with patch.dict(os.environ, {"GEMINI_API_KEY": key}):
            report = self.scan(ai=True, offline=False, provider=EchoProvider())
        self.assertIn("PATCH_AI_RESPONSE_INVALID", report.remediation_diagnostics)
        self.assertNotIn(key, json_report.render(report))

    def test_public_patch_diff_is_escaped_in_html(self):
        self.path.write_text("import requests\nrequests.get(url, verify=False)\n", encoding="utf-8")
        report = self.scan()
        proposals = list(report.remediation_proposals)
        index = next(i for i, p in enumerate(proposals) if p.patch_candidate)
        candidate = replace(proposals[index].patch_candidate,
                            unified_diff="--- a/app.py\n+++ b/app.py\n+<script>alert(1)</script>\n")
        proposals[index] = replace(proposals[index], patch_candidate=candidate)
        rendered = html.render(replace(report, remediation_proposals=tuple(proposals)))
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_new_medium_finding_keeps_validation_partial(self):
        self.path.write_text("import yaml\ndata = input()\nresult = yaml.load(data)\n", encoding="utf-8")
        key = "AIza" + "F" * 35
        fake = FakePatchProvider("result = yaml.safe_load(data); import tempfile; tempfile.mktemp()\n")
        with patch.dict(os.environ, {"GEMINI_API_KEY": key}):
            report = self.scan(ai=True, offline=False, provider=fake)
        proposal = next(p for p in report.remediation_proposals if p.strategy is RemediationStrategy.AI_ASSISTED)
        self.assertEqual(proposal.status, ProposalStatus.PARTIAL_VALIDATION)
        self.assertIn("SAST.PYTHON.INSECURE_TEMP_FILE", proposal.validation_result.new_findings)

    def test_stale_source_and_forbidden_target(self):
        self.path.write_text("import requests\nrequests.get(url, verify=False)\n", encoding="utf-8")
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, self.config))
        finding = next(f for f in report.findings if f.rule_id == "SAST.PYTHON.TLS_VERIFY_DISABLED")
        artifact = next(a for a in report.discovery.artifacts if a.path == "app.py")
        self.path.write_text("import requests\nrequests.get(url, verify=True)\n", encoding="utf-8")
        candidate, validation = validate_patch(self.root, artifact, finding,
            (LineEdit(2, 2, "requests.get(url, verify=True)\n"),),
            RemediationStrategy.DETERMINISTIC, RemediationSettings(), SASTLimits(),
            provenance="DETERMINISTIC_RULE", generated_by="test", confidence=finding.confidence)
        self.assertIsNone(candidate)
        self.assertIn("PATCH_SOURCE_STALE", validation.diagnostics)
        forbidden = replace(artifact, path=".env")
        candidate, validation = validate_patch(self.root, forbidden, replace(finding,
            location=replace(finding.location, path=".env")),
            (LineEdit(2, 2, "x"),), RemediationStrategy.DETERMINISTIC,
            RemediationSettings(), SASTLimits(), provenance="DETERMINISTIC_RULE",
            generated_by="test", confidence=finding.confidence)
        self.assertIsNone(candidate)
        self.assertIn("PATCH_FORBIDDEN_TARGET", validation.diagnostics)

    def test_config_is_bounded_and_no_apply_option(self):
        config = load_config(Path(__file__).resolve().parents[1] / "security-auditor.example.toml")
        self.assertFalse(config.remediation.enabled)
        with self.assertRaises(ValueError):
            RemediationSettings(max_changed_lines=1000)
        from security_auditor.cli.main import parser
        help_text = parser().format_help() + parser()._subparsers._group_actions[0].choices["scan"].format_help()
        self.assertIn("--propose-fixes", help_text)
        self.assertNotIn("--apply", help_text)
