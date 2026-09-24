"""Explicit OSV CLI permission is separate from offline defaults and Gemini."""

from __future__ import annotations

from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.cli.main import main, parser
from security_auditor.orchestrator import ScanOrchestrator
from security_auditor.scanners.dependencies.cache import VulnerabilityCache
from security_auditor.scanners.dependencies.models import LookupResult, LookupStatus


class FakeOSV:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, str, str], ...]] = []

    def lookup_batch(self, keys, limits):
        self.calls.append(tuple(keys))
        return tuple(LookupResult(key, LookupStatus.NO_MATCH) for key in keys)


class CliOSVTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="auditor-cli-osv-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.target = self.base / "target"
        self.target.mkdir()
        (self.target / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
        self.run_count = 0

    def run_cli(self, *options: str, config_offline: bool | None = None):
        provider = FakeOSV()
        self.run_count += 1
        cache = VulnerabilityCache(self.base / f"cache-{self.run_count}")
        argv = ["scan", str(self.target), "--format", "json", *options]
        if config_offline is not None:
            config = self.base / "operator.toml"
            config.write_text(f"[scan]\noffline = {str(config_offline).lower()}\n", encoding="utf-8")
            argv.extend(("--config", str(config)))
        stdout, stderr = StringIO(), StringIO()
        orchestrator = ScanOrchestrator(dependency_provider=provider, dependency_cache=cache)
        with patch("security_auditor.cli.main.ScanOrchestrator", return_value=orchestrator), \
             patch.dict(os.environ, {"GEMINI_API_KEY": ""}), \
             patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            exit_code = main(argv)
        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        return json.loads(stdout.getvalue()), provider.calls

    def test_default_and_explicit_offline_never_query(self):
        for options in ((), ("--offline",)):
            with self.subTest(options=options):
                report, calls = self.run_cli(*options)
                self.assertTrue(report["scan"]["offline"])
                self.assertEqual(calls, [])
                self.assertEqual(report["summary"]["dependency"]["no_data"], 1)
                diagnostic = next(d for d in report["diagnostics"]
                                  if d["code"] == "DEPENDENCY_PROVIDER_NO_DATA")
                self.assertIn("--osv", diagnostic["message"])
                self.assertEqual(report["coverage"]["overall"], "PARTIAL")

    def test_osv_permission_is_independent_of_ai(self):
        for options in (("--osv",), ("--osv", "--no-ai"), ("--osv", "--ai")):
            with self.subTest(options=options):
                report, calls = self.run_cli(*options)
                self.assertFalse(report["scan"]["offline"])
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0], (("PyPI", "example", "1.0.0"),))
                self.assertEqual(report["summary"]["dependency"]["queries"], 1)
                self.assertEqual(report["summary"]["dependency"]["no_data"], 0)
                if "--ai" not in options:
                    self.assertFalse(any(d["source"] == "ai" for d in report["diagnostics"]))

    def test_cli_flags_override_trusted_config(self):
        cases = (
            ((), False, False, True),
            (("--offline",), False, True, False),
            (("--osv",), True, False, True),
        )
        for options, config_offline, expected_offline, expected_query in cases:
            with self.subTest(options=options, config_offline=config_offline):
                report, calls = self.run_cli(*options, config_offline=config_offline)
                self.assertEqual(report["scan"]["offline"], expected_offline)
                self.assertEqual(bool(calls), expected_query)

    def test_ai_alone_does_not_enable_osv(self):
        report, calls = self.run_cli("--ai")
        self.assertFalse(report["scan"]["offline"])
        self.assertEqual(calls, [])

    def test_offline_and_osv_are_mutually_exclusive(self):
        with patch("sys.stderr", StringIO()):
            with self.assertRaises(SystemExit) as error:
                parser().parse_args(["scan", str(self.target), "--offline", "--osv"])
        self.assertEqual(error.exception.code, 2)

    def test_help_explains_network_permission(self):
        help_text = parser()._subparsers._group_actions[0].choices["scan"].format_help()
        self.assertIn("--osv", help_text)
        self.assertIn("disabled by default", help_text)


if __name__ == "__main__":
    unittest.main()
