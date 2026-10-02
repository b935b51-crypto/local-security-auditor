"""Scope and diagnostic regressions; synthetic target contents are never run."""

from contextlib import redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.cli.main import main
from security_auditor.core.config import AuditConfig
from security_auditor.core.models import ScanProfile, ScanTarget
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.discovery.path_safety import is_reparse_point
from security_auditor.gate import evaluate_gate
from security_auditor.gate.service import GateStatus
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import html, json_report, sarif
from test_windows_filesystem import make_junction, synthetic_sandbox


class PytestTempParsePathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-pytest-scope-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, contents="pass\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def report(self, root=None):
        return ScanOrchestrator().run_scan(
            ScanRequest(root or self.root, AuditConfig(), ScanProfile.STANDARD, True, False))

    def test_temp_tree_is_pruned_before_enumeration_or_parsing(self):
        self.write(".pytest-tmp/fixture/broken.py", "def invalid(:\n")
        self.write("nested/.pytest-tmp/broken.py", "def invalid(:\n")
        self.write("tests/test_valid.py")
        original_scandir = os.scandir

        def checked_scandir(path):
            self.assertNotIn(".pytest-tmp", Path(path).parts)
            return original_scandir(path)

        with patch("security_auditor.discovery.service.os.scandir", side_effect=checked_scandir):
            report = self.report()
        view = json.loads(json_report.render(report))
        self.assertEqual(view["coverage"]["overall"], "COMPLETE")
        self.assertEqual(view["diagnostics"], [])
        self.assertEqual(evaluate_gate(view).status, GateStatus.PASS)
        entries = view["discovery"]["scope"]["entries"]
        for name in (".pytest-tmp", "nested/.pytest-tmp"):
            self.assertIn({"path": name, "class": "GENERATED",
                           "reason": "EXCLUDED_DEFAULT_GENERATED", "is_directory": True}, entries)
        for scanner in view["scanners"]:
            if scanner["id"] in {"sast.python", "behavior.static", "secrets"}:
                self.assertEqual(scanner["artifacts_scanned"], 1)
        rendered = html.render(report)
        self.assertIn(".pytest-tmp", rendered)
        self.assertIn("EXCLUDED_DEFAULT_GENERATED", rendered)
        self.assertEqual(json.loads(sarif.render(report))["version"], "2.1.0")

    def test_multiple_parse_failures_have_private_relative_paths_in_reports(self):
        marker = "SYNTHETIC_PARSER_CONTENT_MUST_NOT_LEAK"
        fake_secret = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        for name in ("src/broken_a.py", "tests/broken_b.py"):
            self.write(name, 'def broken("' + marker + '", "' + fake_secret + '":\n')
        report = self.report()
        view = json.loads(json_report.render(report))
        for code in ("SAST_PARSE_FAILED", "BEHAVIOR_PARSE_FAILED"):
            entries = [d for d in view["diagnostics"] if d["code"] == code]
            self.assertEqual([(d["path"], d["count"]) for d in entries],
                             [("src/broken_a.py", 1), ("tests/broken_b.py", 1)])
        for result in report.scanner_results:
            if result.scanner.id in {"sast.python", "behavior.static"}:
                self.assertEqual(result.summary.completeness, "partial")
                self.assertEqual({d.path for d in result.diagnostics},
                                 {"src/broken_a.py", "tests/broken_b.py"})
        for rendered in (json_report.render(report), html.render(report)):
            self.assertNotIn(marker, rendered)
            self.assertNotIn(fake_secret, rendered)
            self.assertNotIn(str(self.root), rendered)
            self.assertNotIn(self.root.as_posix(), rendered)
            self.assertNotIn("SyntaxError", rendered)
            for name in ("src/broken_a.py", "tests/broken_b.py"):
                self.assertIn(name, rendered)
        self.assertEqual(view["schema_version"], "1.1")
        self.assertEqual(view["coverage"]["overall"], "PARTIAL")
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)

    def test_gitignore_cannot_define_or_reopen_pytest_temp_scope(self):
        self.write(".pytest-tmp/broken.py", "def invalid(:\n")
        self.write("src/valid.py")
        for content in (None, ".pytest-tmp/\n", "!.pytest-tmp/\nsrc/valid.py\n"):
            with self.subTest(content=content):
                if content is not None:
                    self.write(".gitignore", content)
                result = discover(ScanTarget(self.root, "synthetic"), DiscoveryPolicy())
                self.assertIn("src/valid.py", {a.path for a in result.artifacts})
                self.assertEqual([(x.path, x.reason.value) for x in result.exclusions],
                                 [(".pytest-tmp", "EXCLUDED_DEFAULT_GENERATED")])
                self.assertEqual(result.completeness.value, "complete")

    def test_trusted_include_can_reopen_named_temp_artifact(self):
        self.write(".pytest-tmp/keep.py")
        self.write(".pytest-tmp/omit.py")
        result = discover(ScanTarget(self.root, "synthetic"),
                          DiscoveryPolicy(include=(".pytest-tmp/keep.py",)))
        self.assertEqual([a.path for a in result.artifacts], [".pytest-tmp/keep.py"])
        self.assertEqual(result.completeness.value, "complete")

    def test_force_only_overwrites_report(self):
        self.write(".pytest-tmp/broken.py", "def invalid(:\n")
        with tempfile.TemporaryDirectory(prefix="auditor-pytest-report-") as output:
            destination = Path(output) / "report.json"
            args = ["scan", str(self.root), "--offline", "--no-ai", "--format", "json",
                    "--output", str(destination)]
            self.assertEqual(main(args), 0)
            with redirect_stderr(StringIO()):
                self.assertEqual(main(args), 4)
            self.assertEqual(main([*args, "--force"]), 0)
            view = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(view["discovery"]["admitted_files"], 0)
            self.assertEqual(view["coverage"]["overall"], "COMPLETE")
            self.assertEqual(view["discovery"]["scope"]["entries"][0]["path"], ".pytest-tmp")

    def test_normal_reparse_partial_propagation_unchanged(self):
        self.write("src/linked/not_admitted.py")
        blocked = os.stat(self.root / "src/linked", follow_symlinks=False).st_ino
        with patch("security_auditor.discovery.service.is_reparse_point",
                   side_effect=lambda info: info.st_ino == blocked or is_reparse_point(info)):
            view = json.loads(json_report.render(self.report()))
        self.assertIn(("REPARSE_POINT_SKIPPED", "src/linked"),
                      {(d["code"], d["path"]) for d in view["diagnostics"]})
        for code in ("SAST_DISCOVERY_INCOMPLETE", "BEHAVIOR_DISCOVERY_INCOMPLETE",
                     "SECRET_DISCOVERY_INCOMPLETE", "DEPENDENCY_DISCOVERY_INCOMPLETE"):
            self.assertIn(code, {d["code"] for d in view["diagnostics"]})
        self.assertEqual(view["coverage"]["overall"], "PARTIAL")
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)

    @unittest.skipUnless(os.name == "nt", "Windows case-insensitive scope policy")
    def test_windows_case_and_no_substring_overmatch(self):
        self.write(".PYTEST-TMP/broken.py", "def invalid(:\n")
        self.write("tests/pytest-tmp-helper.py")
        result = discover(ScanTarget(self.root, "synthetic"), DiscoveryPolicy())
        self.assertEqual([a.path for a in result.artifacts], ["tests/pytest-tmp-helper.py"])
        self.assertEqual([e.path for e in result.exclusions], [".PYTEST-TMP"])

    @unittest.skipUnless(os.name == "nt", "Real Windows junction control")
    def test_real_junction_temp_pruned_normal_and_included_still_partial(self):
        with synthetic_sandbox() as (base, links):
            root = base / "root"
            temp = root / ".pytest-tmp" / "fixture"
            temp.mkdir(parents=True)
            destination = base / "inert"
            destination.mkdir()
            (destination / "broken.py").write_text("def invalid(:\n", encoding="utf-8")
            make_junction(base, links, temp / "linked", destination)
            view = json.loads(json_report.render(self.report(root)))
            self.assertEqual(view["diagnostics"], [])
            self.assertEqual(view["coverage"]["overall"], "COMPLETE")
            included = discover(ScanTarget(root, "synthetic"),
                                DiscoveryPolicy(include=(".pytest-tmp/fixture/linked/",)))
            self.assertEqual(included.completeness.value, "partial")
            self.assertIn("REPARSE_POINT_SKIPPED", {d.code.value for d in included.diagnostics})
            (root / "src").mkdir()
            make_junction(base, links, root / "src" / "linked", destination)
            view = json.loads(json_report.render(self.report(root)))
            self.assertEqual(view["coverage"]["overall"], "PARTIAL")
            self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)
            self.assertEqual([d["path"] for d in view["diagnostics"]
                              if d["code"] == "REPARSE_POINT_SKIPPED"], ["src/linked"])
            self.assertFalse(any(d["code"].endswith("PARSE_FAILED") for d in view["diagnostics"]))


if __name__ == "__main__":
    unittest.main()
