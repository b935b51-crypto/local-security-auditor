"""Synthetic project scope regressions; fixtures are never imported or executed."""

from __future__ import annotations

import json
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import AuditConfig, DiscoveryLimits
from security_auditor.core.models import ScanProfile, ScanTarget
from security_auditor.discovery.models import ScanCompleteness
from security_auditor.discovery.policy import DiscoveryPolicy
from security_auditor.discovery.service import discover
from security_auditor.correlation.models import FindingGroup, FindingRole
from security_auditor.gate import evaluate_gate
from security_auditor.gate.service import GateStatus
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import html, json_report


class ScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-scope-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name: str, contents: str = "synthetic data\n") -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def scan(self, policy: DiscoveryPolicy | None = None):
        return discover(ScanTarget(self.root, "synthetic"), policy or DiscoveryPolicy())

    def test_default_scope_prunes_generated_trees_but_keeps_security_inputs(self):
        for directory in (".uv-cache", ".mypy_cache", ".pytest_cache", ".ruff_cache",
                          ".venv", "node_modules", "dist", "build", "coverage"):
            self.write(f"{directory}/nested/noise.py", "import os\nos.system(input())\n")
        self.write(".coverage")
        self.write("coverage.xml")
        self.write(".env", "SYNTHETIC_PUBLIC=1\n")
        self.write("requirements.txt", "example==1.0.0\n")
        self.write("uv.lock", "version = 1\n")
        self.write("tests/integration/test_portfolio_phase4.py", "def test_synthetic(): pass\n")
        for number in range(40):
            self.write(f".uv-cache/archive-v0/dependency/noise_{number}.py",
                       "import os\nos.system(input())\n")
        result = self.scan(DiscoveryPolicy(limits=DiscoveryLimits(max_file_count=4)))
        admitted = {artifact.path for artifact in result.artifacts}
        self.assertEqual(result.completeness, ScanCompleteness.COMPLETE)
        self.assertEqual(admitted, {".env", "requirements.txt", "uv.lock",
                                    "tests/integration/test_portfolio_phase4.py"})
        self.assertEqual(result.summary.stats.directories_excluded, 9)
        self.assertEqual(result.summary.stats.files_excluded, 2)
        self.assertEqual(result.summary.stats.files_skipped, 0)
        self.assertEqual(result.summary.stats.files_discovered, 4)
        self.assertEqual(len(result.exclusions), 11)
        self.assertTrue(all(not item.path.startswith(("/", "C:")) for item in result.exclusions))
        self.assertIn("EXCLUDED_DEFAULT_CACHE", {item.reason.value for item in result.exclusions})

    @unittest.skipUnless(os.name == "nt", "Windows path matching")
    def test_windows_casefold_without_substring_overmatch(self):
        self.write(".UV-CACHE/noise.py", "pass\n")
        self.write("src/my.uv-cache-helper.py", "pass\n")
        result = self.scan()
        self.assertIn(".UV-CACHE", {x.path for x in result.exclusions})
        self.assertIn("src/my.uv-cache-helper.py", {x.path for x in result.artifacts})

    def test_unrelated_include_does_not_reopen_cache_and_explicit_include_can(self):
        self.write("src/app.py", "pass\n")
        self.write(".uv-cache/buried.py", "pass\n")
        unrelated = self.scan(DiscoveryPolicy(include=("src/app.py",)))
        self.assertEqual({x.path for x in unrelated.artifacts}, {"src/app.py"})
        self.assertIn(".uv-cache", {x.path for x in unrelated.exclusions})
        explicit = self.scan(DiscoveryPolicy(include=(".uv-cache/buried.py",)))
        self.assertIn(".uv-cache/buried.py", {x.path for x in explicit.artifacts})
        self.assertEqual(explicit.summary.stats.directories_excluded, 0)

    def test_user_policy_and_trusted_default_override(self):
        self.write("custom/omit.py", "pass\n")
        self.write(".uv-cache/keep.py", "pass\n")
        user_excluded = self.scan(DiscoveryPolicy(exclude=("custom/",)))
        self.assertEqual(user_excluded.summary.stats.user_exclusions, 1)
        self.assertIn("EXCLUDED_USER_POLICY", {x.reason.value for x in user_excluded.exclusions})
        restored = self.scan(DiscoveryPolicy(default_exclude=()))
        self.assertIn(".uv-cache/keep.py", {x.path for x in restored.artifacts})

    def test_report_scope_is_additive_and_html_safe(self):
        self.write("src/app.py", "pass\n")
        self.write(".uv-cache/noise.py", "import os\nos.system(input())\n")
        self.write("dist/ignored.txt", "synthetic\n")
        self.write("custom&name.txt", "synthetic\n")
        report = ScanOrchestrator().run_scan(
            ScanRequest(self.root, replace(AuditConfig(), exclude=("custom&name.txt",)),
                        ScanProfile.STANDARD, True, False))
        view = json.loads(json_report.render(report))
        scope = view["discovery"]["scope"]
        self.assertEqual(view["schema_version"], "1.1")
        self.assertEqual(view["coverage"]["overall"], "COMPLETE")
        self.assertEqual(evaluate_gate(view).status, GateStatus.PASS)
        self.assertEqual(scope["excluded_directories"], 2)
        self.assertEqual(scope["excluded_files"], 1)
        self.assertTrue(scope["default_exclusions_applied"])
        self.assertFalse(any((f["location"]["path"] or "").startswith(".uv-cache/")
                             for f in view["findings"]))
        rendered = html.render(report)
        self.assertIn("掃描範圍與排除項目", rendered)
        self.assertIn(".uv-cache", rendered)
        self.assertIn("custom&amp;name.txt", rendered)
        self.assertNotIn("custom&name.txt", rendered)
        self.assertNotIn("<script", rendered)
        self.assertNotIn("noise.py", rendered)

    def test_gitignored_env_is_still_secret_scanned_and_redacted(self):
        fake_secret = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        self.write(".gitignore", ".env\n")
        self.write(".env", "SYNTHETIC_TOKEN=" + fake_secret + "\n")
        report = ScanOrchestrator().run_scan(
            ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        self.assertIn(".env", {a.path for a in report.discovery.artifacts})
        self.assertTrue(any(f.location.path == ".env" and f.scanner_id == "secrets"
                            for f in report.findings))
        self.assertNotIn(fake_secret, json_report.render(report))
        self.assertNotIn(fake_secret, html.render(report))

    def test_html_hides_singleton_group_noise(self):
        self.write("src/app.py", "import os\nvalue = input()\nos.system(value)\n")
        report = ScanOrchestrator().run_scan(
            ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        self.assertTrue(report.findings)
        self.assertTrue(any(f.location.path == "src/app.py" for f in report.findings))
        first = report.findings[0]
        singleton = FindingGroup("synthetic-singleton", first.fingerprint,
                                 ((first.fingerprint, FindingRole.PRIMARY),), ())
        isolated = replace(report, finding_groups=(singleton,), attack_paths=())
        rendered = html.render(isolated)
        self.assertNotIn("synthetic-singleton", rendered)
        self.assertNotIn(first.fingerprint, rendered)


if __name__ == "__main__":
    unittest.main()
