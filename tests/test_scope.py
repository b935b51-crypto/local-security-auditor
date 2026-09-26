"""Synthetic project scope regressions; fixtures are never imported or executed."""

from __future__ import annotations

import json
from contextlib import redirect_stderr
from dataclasses import replace
from io import StringIO
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import AuditConfig, DiscoveryLimits
from security_auditor.cli.main import main
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

    def test_typescript_build_metadata_is_file_level_generated_scope(self):
        for name in ("foo.tsbuildinfo", "nested/path/tsconfig.tsbuildinfo",
                     "apps/dashboard/.tsbuildinfo"):
            self.write(name, "generated metadata\n")
        for name in ("foo.ts", "foo.tsx", "foo.js", "foo.jsx",
                     "directory.tsbuildinfo/real.ts"):
            self.write(name, "export const value = 1;\n")
        result = self.scan()
        excluded = {entry.path: entry for entry in result.exclusions}
        for name in ("foo.tsbuildinfo", "nested/path/tsconfig.tsbuildinfo",
                     "apps/dashboard/.tsbuildinfo"):
            with self.subTest(name=name):
                self.assertEqual((excluded[name].scope_class.value, excluded[name].reason.value,
                                  excluded[name].is_directory),
                                 ("GENERATED", "EXCLUDED_DEFAULT_GENERATED", False))
        self.assertEqual({a.path for a in result.artifacts},
                         {"foo.ts", "foo.tsx", "foo.js", "foo.jsx",
                          "directory.tsbuildinfo/real.ts"})
        self.assertEqual(result.completeness, ScanCompleteness.COMPLETE)
        self.assertEqual(result.summary.stats.files_excluded, 3)

    @unittest.skipUnless(os.name == "nt", "Windows case-insensitive scope policy")
    def test_typescript_build_metadata_windows_casefold(self):
        self.write("FOO.TSBUILDINFO")
        result = self.scan()
        self.assertEqual([(x.path, x.reason.value) for x in result.exclusions],
                         [("FOO.TSBUILDINFO", "EXCLUDED_DEFAULT_GENERATED")])
        self.assertEqual(result.artifacts, ())

    def test_tsbuildinfo_gitignore_cannot_define_or_negate_default_scope(self):
        self.write("foo.tsbuildinfo")
        for contents in (None, "*.tsbuildinfo\n", "!foo.tsbuildinfo\n"):
            with self.subTest(gitignore=contents):
                if contents is not None:
                    self.write(".gitignore", contents)
                for respect_gitignore in (False, True):
                    result = self.scan(DiscoveryPolicy(respect_gitignore=respect_gitignore))
                    entry = next(x for x in result.exclusions if x.path == "foo.tsbuildinfo")
                    self.assertEqual((entry.scope_class.value, entry.reason.value),
                                     ("GENERATED", "EXCLUDED_DEFAULT_GENERATED"))
                    self.assertNotIn("foo.tsbuildinfo", {x.path for x in result.artifacts})
                    self.assertEqual(result.completeness, ScanCompleteness.COMPLETE)

    def test_tsbuildinfo_trusted_include_reopens_only_named_file(self):
        self.write("foo.tsbuildinfo")
        self.write("other.tsbuildinfo")
        result = self.scan(DiscoveryPolicy(include=("foo.tsbuildinfo",)))
        self.assertEqual({x.path for x in result.artifacts}, {"foo.tsbuildinfo"})
        self.assertEqual({x.path for x in result.exclusions}, {"other.tsbuildinfo"})

    def test_existing_default_directory_classes_remain(self):
        expected = {
            ".git": "GENERATED", ".venv": "ENVIRONMENT", "venv": "ENVIRONMENT",
            "env": "ENVIRONMENT", "__pycache__": "CACHE", ".pytest_cache": "CACHE",
            ".mypy_cache": "CACHE", ".ruff_cache": "CACHE", ".uv-cache": "CACHE",
            "node_modules": "DEPENDENCY_VENDOR", "dist": "BUILD_OUTPUT",
            "build": "BUILD_OUTPUT", "out": "BUILD_OUTPUT",
        }
        policy = DiscoveryPolicy()
        for directory, scope_class in expected.items():
            with self.subTest(directory=directory):
                classification = policy.exclusion(f"nested/{directory}", is_directory=True)
                self.assertIsNotNone(classification)
                self.assertEqual(classification[0].value, scope_class)

    def test_long_tsbuildinfo_never_consumes_secret_budget_or_partial_coverage(self):
        self.write("foo.tsbuildinfo", "x" * (1024 * 1024 + 256) + "\n")
        report = ScanOrchestrator().run_scan(
            ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        view = json.loads(json_report.render(report))
        entry = next(x for x in view["discovery"]["scope"]["entries"]
                     if x["path"] == "foo.tsbuildinfo")
        self.assertEqual(entry, {"path": "foo.tsbuildinfo", "class": "GENERATED",
                                 "reason": "EXCLUDED_DEFAULT_GENERATED", "is_directory": False})
        self.assertEqual(view["discovery"]["admitted_files"], 0)
        self.assertEqual(view["discovery"]["skipped_files"], 0)
        for scanner in view["scanners"]:
            if scanner["id"] in {"secrets", "sast.python", "behavior.static"}:
                self.assertEqual(scanner["artifacts_scanned"], 0)
                if scanner["id"] == "secrets":
                    self.assertEqual(scanner["large_text"]["large_text_files_scanned"], 0)
                    self.assertEqual(scanner["large_text"]["large_text_bytes_scanned"], 0)
        self.assertEqual(view["coverage"]["overall"], "COMPLETE")
        self.assertEqual(evaluate_gate(view).status, GateStatus.PASS)

    def test_force_changes_output_overwrite_not_tsbuildinfo_scope(self):
        self.write("foo.tsbuildinfo")
        output_directory = tempfile.TemporaryDirectory(prefix="auditor-scope-output-")
        self.addCleanup(output_directory.cleanup)
        destination = Path(output_directory.name) / "scope-report.json"
        args = ["scan", str(self.root), "--offline", "--no-ai", "--format", "json",
                "--output", str(destination)]
        self.assertEqual(main(args), 0)
        with redirect_stderr(StringIO()):
            self.assertEqual(main(args), 4)
        self.assertEqual(main([*args, "--force"]), 0)
        view = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(view["discovery"]["admitted_files"], 0)
        self.assertEqual(view["discovery"]["scope"]["entries"][0]["reason"],
                         "EXCLUDED_DEFAULT_GENERATED")

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
