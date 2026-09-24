"""Golden false-positive controls; synthetic target files are never executed."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget, Severity
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.sast import SASTScanner
from security_auditor.scanners.secrets import SecretScanner


class DetectionPrecisionGoldenTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-precision-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"),
                                   ScanProfile.STANDARD, datetime.now(timezone.utc))

    def write(self, path: str, content: str) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")

    def scan(self, scanner):
        return scanner.scan_discovery(self.session, discover(self.session.target, DiscoveryPolicy()))

    def test_a_standard_library_generated_token_is_not_hardcoded(self):
        self.write("app.py", "import secrets\ntoken = secrets.token_urlsafe(32)\n"
                             "other = secrets.token_hex(24)\npassword = secrets.token_bytes(16)\n")
        result = self.scan(SecretScanner())
        self.assertEqual(result.status, "completed")
        self.assertFalse(any(f.rule_id == "SECRET.GENERIC.ASSIGNMENT" for f in result.findings))

    def test_a_literal_and_unknown_helper_still_detected(self):
        self.write("app.py", "import secrets\ntoken = 'A9b8C7d6E5f4G3h2I1j0'\n"
                             "password = make_secure_token()\n")
        result = self.scan(SecretScanner())
        self.assertEqual([f.rule_id for f in result.findings],
                         ["SECRET.GENERIC.ASSIGNMENT", "SECRET.GENERIC.ASSIGNMENT"])
        self.assertTrue(all(f.cwe == ("CWE-798",) for f in result.findings))

    def test_a_shadowed_secrets_name_is_not_trusted(self):
        self.write("app.py", "import secrets\nsecrets = CustomGenerator()\n"
                             "password = secrets.token_urlsafe(32)\n")
        result = self.scan(SecretScanner())
        self.assertIn("SECRET.GENERIC.ASSIGNMENT", {f.rule_id for f in result.findings})

    def test_a_module_monkeypatch_is_not_trusted(self):
        self.write("app.py", "import secrets\n"
                             "secrets.token_urlsafe = unsafe_generator\n"
                             "password = secrets.token_urlsafe(32)\n")
        result = self.scan(SecretScanner())
        self.assertEqual(len([f for f in result.findings
                              if f.rule_id == "SECRET.GENERIC.ASSIGNMENT"]), 1)

    def test_a_quoted_generator_text_is_not_a_generated_value(self):
        self.write("quoted.py", "import secrets\n"
                                "password = secrets.token_urlsafe(32); token = 'secrets.token_urlsafe(32)'\n")
        result = self.scan(SecretScanner())
        self.assertEqual(len([f for f in result.findings
                              if f.rule_id == "SECRET.GENERIC.ASSIGNMENT"]), 1)

    def test_b_synthetic_test_fixture_is_not_cwe_798_medium(self):
        self.write("tests/test_auth.py", "password = 'fake-test-password'\n"
                                         "payload = {'password': 'not-a-token'}\n"
                                         "other = {'password': 'do-not-echo'}\n")
        result = self.scan(SecretScanner())
        self.assertFalse(any(f.rule_id == "SECRET.GENERIC.ASSIGNMENT" for f in result.findings))
        self.assertEqual(result.status, "completed")

    def test_b_tests_are_not_ignored_and_provider_secret_keeps_priority(self):
        provider = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:36]
        self.write("tests/test_api.py", f"api_key = '{provider}'\n"
                                        "password = 'ProductionCredentialA9!'\n")
        result = self.scan(SecretScanner())
        self.assertIn(("SECRET.GITHUB.TOKEN", Severity.HIGH),
                      {(f.rule_id, f.severity) for f in result.findings})
        self.assertIn("SECRET.GENERIC.ASSIGNMENT", {f.rule_id for f in result.findings})
        self.assertNotIn(provider, repr(result))

    def test_b_synthetic_marker_outside_tests_remains_eligible(self):
        self.write("app.py", "password = 'fake-test-password'\n")
        result = self.scan(SecretScanner())
        self.assertIn("SECRET.GENERIC.ASSIGNMENT", {f.rule_id for f in result.findings})

    def test_b_large_text_test_file_keeps_provider_detection(self):
        provider = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:36]
        self.write("tests/test_large.py", "password = 'fake-test-password'\n"
                   + f"api_key = '{provider}'\n" + "# inert fixture line\n" * 60_000)
        result = self.scan(SecretScanner())
        self.assertEqual(result.status, "completed")
        self.assertEqual([f.rule_id for f in result.findings], ["SECRET.GITHUB.TOKEN"])
        self.assertNotIn(provider, repr(result))

    def test_c_local_cli_path_keeps_finding_with_lower_severity(self):
        self.write("scripts/export_openapi.py", "import sys\nfrom pathlib import Path\n"
                     "output = Path(sys.argv[1])\noutput.write_text('inert')\n")
        result = self.scan(SASTScanner())
        matches = [f for f in result.findings if f.rule_id == "SAST.PYTHON.PATH_TRAVERSAL"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.LOW)
        self.assertEqual(matches[0].cwe, ("CWE-22",))
        self.assertIn("depends on who controls", matches[0].description)

    def test_c_remote_path_retains_medium_severity(self):
        self.write("scripts/remote.py", "from pathlib import Path\n"
                     "@app.post('/write')\ndef write_file(user_path):\n"
                     "    Path(user_path).write_text('inert')\n")
        result = self.scan(SASTScanner())
        matches = [f for f in result.findings if f.rule_id == "SAST.PYTHON.PATH_TRAVERSAL"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.MEDIUM)

    def test_c_mixed_cli_and_remote_origin_remains_medium_after_long_trace(self):
        steps = "".join(f"path = str(path)  # bounded synthetic step {index}\n" for index in range(14))
        self.write("scripts/mixed.py", "import sys\nfrom flask import request\nfrom pathlib import Path\n"
                     "path = sys.argv[1] + request.args['file']\n" + steps +
                     "Path(path).write_text('inert')\n")
        result = self.scan(SASTScanner())
        matches = [f for f in result.findings if f.rule_id == "SAST.PYTHON.PATH_TRAVERSAL"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
