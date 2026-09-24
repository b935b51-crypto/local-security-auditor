"""Synthetic hostile-file tests. Fixtures are data and are never executed."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
import ast
import base64
import json
import logging
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import SecretLimits, load_config
from security_auditor.core.models import Confidence, ScanProfile, ScanSession, ScanTarget, Severity
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.discovery.models import ScanCompleteness
from security_auditor.scanners.secrets import SecretScanner
from security_auditor.scanners.secrets.fingerprint import finding_fingerprint
from security_auditor.scanners.secrets.placeholders import is_placeholder, shannon_entropy
from security_auditor.scanners.secrets.redaction import sanitize_url_for_evidence


class SecretScannerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-phase2-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"),
                                   ScanProfile.STANDARD, datetime.now(timezone.utc))

    def write(self, path: str, content: str | bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)

    def scan(self, limits: SecretLimits | None = None):
        discovered = discover(self.session.target, DiscoveryPolicy())
        return SecretScanner(limits).scan_discovery(self.session, discovered)

    def test_mixed_synthetic_repo_and_no_plaintext_propagation(self):
        github = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:36]
        password = "SuperFakePass123"
        assignment = "A9x7KpQ2vR8mZ1wL5n6B4c3D2"
        self.write(".env", f"GITHUB_TOKEN={github}\nDATABASE_URL=postgres://user:{password}@localhost/db\n"
                         f"CLIENT_SECRET={assignment}\nAPI_KEY=YOUR_API_KEY_HERE\nTOKEN=${{TOKEN}}\n")
        self.write("README.md", "Example: PASSWORD=changeme\n")
        result = self.scan()
        self.assertEqual(result.status, "completed")
        self.assertEqual({f.rule_id for f in result.findings},
                         {"SECRET.GITHUB.TOKEN", "SECRET.CONNECTION_STRING", "SECRET.GENERIC.ASSIGNMENT"})
        for raw in (github, password, assignment):
            self.assertFalse(raw in repr(result), "raw synthetic credential reached result repr")
            self.assertFalse(raw in json.dumps(asdict(result), default=str), "raw synthetic credential reached serialized result")
        self.assertGreaterEqual(result.summary.placeholders_suppressed, 2)
        github_finding = next(f for f in result.findings if f.rule_id == "SECRET.GITHUB.TOKEN")
        self.assertEqual((github_finding.severity, github_finding.confidence), (Severity.HIGH, Confidence.HIGH))
        self.assertEqual(github_finding.location.path, ".env")
        self.assertGreater(result.summary.duplicates_suppressed, 0)

    def test_private_key_body_and_public_material(self):
        body = "FAKE_PRIVATE_BODY_ONLY_" + "Q7r8" * 12
        self.write("private.pem", f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
                                  "-----BEGIN CERTIFICATE-----\nPUBLIC_ONLY\n-----END CERTIFICATE-----\n"
                                  "ssh-ed25519 PUBLIC_ONLY user@example\n")
        result = self.scan()
        self.assertEqual([f.rule_id for f in result.findings], ["SECRET.PRIVATE_KEY.PEM"])
        finding = result.findings[0]
        self.assertEqual((finding.severity, finding.confidence), (Severity.HIGH, Confidence.HIGH))
        self.assertFalse(body in repr(result), "synthetic private key body reached result repr")
        self.assertFalse(body in json.dumps(asdict(result), default=str), "synthetic private key body reached serialized result")
        self.assertTrue("[REDACTED PRIVATE KEY]" in repr(finding))

    def test_certificate_named_pem_can_contain_private_key(self):
        self.write("bundle.pem", "-----BEGIN CERTIFICATE-----\nPUBLIC_ONLY\n-----END CERTIFICATE-----\n"
                                 "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_PRIVATE_BODY_ONLY\n"
                                 "-----END OPENSSH PRIVATE KEY-----\n")
        result = self.scan()
        self.assertEqual([f.rule_id for f in result.findings], ["SECRET.PRIVATE_KEY.PEM"])
        self.assertFalse("FAKE_PRIVATE_BODY_ONLY" in repr(result))
        self.write("unterminated.pem", "-----BEGIN PRIVATE KEY-----\nFAKE_BODY_ONLY\n")
        result = self.scan()
        self.assertEqual(result.status, "partial")
        self.assertIn("SECRET_PRIVATE_KEY_UNTERMINATED", {d.code for d in result.diagnostics})

    def test_provider_aws_pair_jwt_and_documentation(self):
        aws_id = "AKIA" + "A1B2C3D4" * 2
        aws_secret = "S7p8Q9r0T1u2V3w4X5y6Z7a8"
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"synthetic"}').rstrip(b"=").decode()
        jwt = f"{header}.{payload}.FAKESIGNATURE12345"
        self.write("tests/config.py", f"AWS_ACCESS_KEY_ID='{aws_id}'\nAWS_SECRET_ACCESS_KEY='{aws_secret}'\n")
        self.write("README.md", f"example jwt: {jwt}\n")
        result = self.scan()
        by_rule = {f.rule_id: f for f in result.findings}
        self.assertIn("SECRET.AWS.ACCESS_KEY", by_rule)
        self.assertIn("SECRET.JWT", by_rule)
        self.assertEqual(by_rule["SECRET.AWS.ACCESS_KEY"].severity, Severity.HIGH)
        self.assertEqual(by_rule["SECRET.AWS.ACCESS_KEY"].confidence, Confidence.HIGH)
        for raw in (aws_id, aws_secret, jwt):
            self.assertFalse(raw in repr(result), "raw synthetic credential reached result repr")

    def test_other_structured_providers_and_aws_id_alone(self):
        stripe = "sk_test_" + ("A1b2C3d4" * 4)
        slack = "xoxb-" + ("A1b2C3d4" * 4)
        gitlab = "glpat-" + ("A1b2C3d4" * 4)
        aws_id = "AKIA" + "A1B2C3D4" * 2
        self.write("tokens.txt", f"{stripe}\n{slack}\n{gitlab}\n{aws_id}\n")
        result = self.scan()
        self.assertEqual({finding.rule_id for finding in result.findings},
                         {"SECRET.STRIPE.SECRET_KEY", "SECRET.SLACK.TOKEN",
                          "SECRET.GITLAB.TOKEN", "SECRET.AWS.ACCESS_KEY"})
        aws = next(f for f in result.findings if f.rule_id == "SECRET.AWS.ACCESS_KEY")
        self.assertEqual((aws.severity, aws.confidence), (Severity.LOW, Confidence.MEDIUM))
        for raw in (stripe, slack, gitlab, aws_id):
            self.assertFalse(raw in repr(result), "raw synthetic credential reached result repr")

    def test_placeholders_references_hash_uuid_and_entropy(self):
        self.write("config.toml", 'api_key = "YOUR_API_KEY_HERE"\npassword = "changeme"\n'
                                  'token = "${TOKEN}"\nclient_secret = "os.getenv(\'CLIENT_SECRET\')"\n'
                                  'sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n'
                                  'secret = "123e4567-e89b-42d3-a456-426614174000"\n')
        result = self.scan()
        self.assertEqual(len(result.findings), 0)
        self.assertTrue(is_placeholder("FAKE_TOKEN"))
        self.assertFalse(is_placeholder("realtestprojectkeyA1b2C3d4"))
        self.assertGreater(shannon_entropy("A1b2C3d4E5f6G7h8"), 3)

    def test_resource_limits_decode_and_safe_diagnostics(self):
        self.write("a.py", "secret='A1b2C3d4E5f6G7h8I9j0'\n")
        self.write("b.py", "token='Q1w2E3r4T5y6U7i8O9p0'\n")
        result = self.scan(replace(SecretLimits(), max_total_bytes=40))
        self.assertEqual(result.status, "aborted")
        self.assertIn("SECRET_SCAN_BYTE_BUDGET_REACHED", {d.code for d in result.diagnostics})
        self.assertFalse("Q1w2E3r4T5y6U7i8O9p0" in repr(result))
        large = self.scan(replace(SecretLimits(), max_file_bytes=8))
        self.assertEqual(large.status, "partial")
        self.assertIn("SECRET_FILE_TOO_LARGE", {d.code for d in large.diagnostics})
        long_line = self.scan(replace(SecretLimits(), max_line_bytes=10))
        self.assertEqual(long_line.status, "partial")
        self.assertIn("SECRET_LINE_TOO_LONG", {d.code for d in long_line.diagnostics})

    def test_oversize_diagnostic_has_redacted_relative_path_without_content(self):
        marker = "SYNTHETIC_OVERSIZED_CONTENT_MARKER"
        self.write("logs/big.log", (marker + "\n") * 4)
        result = self.scan(replace(SecretLimits(), max_file_bytes=8))
        diagnostic = next(d for d in result.diagnostics if d.code == "SECRET_FILE_TOO_LARGE")
        self.assertEqual(diagnostic.path, "logs/big.log")
        self.assertEqual(result.status, "partial")
        self.assertNotIn(str(self.root), repr(result))
        self.assertNotIn(marker, repr(result))

        fake_token = "ghp_" + ("A1b2C3d4" * 5)[:36]
        self.write(f"logs/0-{fake_token}.log", "SAFE SYNTHETIC DATA\n")
        redacted = self.scan(replace(SecretLimits(), max_file_bytes=8))
        serialized = json.dumps(asdict(redacted), default=str)
        self.assertNotIn(fake_token, serialized)
        self.assertTrue(any(d.code == "SECRET_FILE_TOO_LARGE" and "[REDACTED]" in (d.path or "")
                            for d in redacted.diagnostics))

    def test_utf16_and_changed_admitted_file(self):
        raw = "A9x7KpQ2vR8mZ1wL5n6B4c3D2"
        self.write("utf16.env", b"\xff\xfe" + f"CLIENT_SECRET={raw}\n".encode("utf-16-le"))
        discovered = discover(self.session.target, DiscoveryPolicy())
        result = SecretScanner().scan_discovery(self.session, discovered)
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(raw in repr(result), "raw synthetic credential reached result repr")
        self.write("utf16.env", b"\xff\xfe" + "CLIENT_SECRET=changed\n".encode("utf-16-le"))
        changed = SecretScanner().scan_discovery(self.session, discovered)
        self.assertEqual(changed.status, "partial")
        self.assertIn("SECRET_READ_FAILED", {d.code for d in changed.diagnostics})
        self.assertEqual(len(changed.findings), 0)

    def test_many_matches_limit_and_adversarial_line(self):
        token = "ghp_" + ("A1b2C3d4" * 5)[:36]
        self.write("many.env", "\n".join(f"TOKEN_{n}={token}" for n in range(30)))
        result = self.scan(replace(SecretLimits(), max_matches_per_rule_per_file=2,
                                   max_findings_per_file=2))
        self.assertEqual(result.status, "partial")
        self.assertLessEqual(len(result.findings), 2)
        self.assertIn("SECRET_MATCH_LIMIT_REACHED", {d.code for d in result.diagnostics})
        self.write("long.js", "a" * 500_000 + "\n")
        result = self.scan()
        self.assertEqual(result.status, "partial")
        self.assertIn("SECRET_LINE_TOO_LONG", {d.code for d in result.diagnostics})

    def test_global_finding_limit_and_failed_discovery(self):
        token = "ghp_" + ("A1b2C3d4" * 5)[:36]
        self.write("tokens.txt", f"{token}\n{token}\n{token}\n")
        result = self.scan(replace(SecretLimits(), max_findings_total=2))
        self.assertEqual(result.status, "aborted")
        self.assertEqual(result.summary.completeness, "aborted")
        self.assertEqual(len(result.findings), 2)
        self.assertFalse(token in repr(result))
        discovered = discover(self.session.target, DiscoveryPolicy())
        failed = replace(discovered, root=None, completeness=ScanCompleteness.FAILED)
        failed_result = SecretScanner().scan_discovery(self.session, failed)
        self.assertEqual(failed_result.status, "failed")
        self.assertEqual(failed_result.summary.completeness, "failed")

    def test_matched_secret_in_filename_is_redacted_and_collision_is_visible(self):
        first = "ghp_" + ("A1b2C3d4" * 5)[:36]
        second = "ghp_" + ("Z9y8X7w6" * 5)[:36]
        for value in (first, second):
            self.write(f"{value}.env", value + "\n")
        result = self.scan()
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len({f.fingerprint for f in result.findings}), 2)
        self.assertEqual(result.status, "partial")
        self.assertIn("SECRET_FINGERPRINT_COLLISION", {d.code for d in result.diagnostics})
        for value in (first, second):
            self.assertFalse(value in repr(result), "matched filename credential reached result")
            self.assertFalse(value in json.dumps(asdict(result), default=str),
                             "matched filename credential reached serialized result")

    def test_detector_error_and_log_leakage(self):
        raw = "A1b2C3d4E5f6G7h8I9j0K1l2"
        self.write("config.env", f"CLIENT_SECRET={raw}\n")
        with patch("security_auditor.scanners.secrets.detectors.assignment", side_effect=ValueError(raw)):
            with patch.object(logging.Logger, "_log") as logged:
                result = self.scan()
        self.assertEqual(result.status, "partial")
        self.assertIn("SECRET_RULE_ERROR", {d.code for d in result.diagnostics})
        self.assertFalse(raw in repr(result), "raw synthetic credential reached result repr")
        logged.assert_not_called()

    def test_fingerprint_stability_and_url_sanitization(self):
        first = finding_fingerprint("SECRET.GITHUB.TOKEN", "a.py", 3, 10, "github", "")
        self.assertEqual(first, finding_fingerprint("SECRET.GITHUB.TOKEN", "a.py", 3, 10, "github", ""))
        self.assertNotEqual(first, finding_fingerprint("SECRET.GITHUB.TOKEN", "b.py", 3, 10, "github", ""))
        raw = "SuperFakePass123"
        sanitized = sanitize_url_for_evidence(f"postgres://user:{raw}@host/db?token={raw}")
        self.assertFalse(raw in sanitized)
        self.assertFalse("host/db" in sanitized)

    def test_config_and_discovery_completeness(self):
        config = load_config(Path(__file__).resolve().parents[1] / "security-auditor.example.toml")
        self.assertTrue(config.secrets.enabled)
        self.write("large.txt", b"X" * 1000)
        discovered = discover(self.session.target, DiscoveryPolicy.from_config(config))
        partial = replace(discovered, completeness=type(discovered.completeness).PARTIAL)
        result = SecretScanner().scan_discovery(self.session, partial)
        self.assertEqual(result.status, "partial")
        self.assertIn("SECRET_DISCOVERY_INCOMPLETE", {d.code for d in result.diagnostics})
        with self.assertRaises(ValueError):
            SecretLimits(max_file_bytes=1_000_000_000)

    def test_target_config_cannot_disable_redaction_or_raise_limits(self):
        config = self.root.parent / "operator.toml"
        config.write_text("[secrets]\nredact = false\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(config)
        config.write_text("[secrets]\nmax_file_bytes = 999999999\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(config)

    def test_no_target_execution_and_no_complete_token_literals(self):
        package = Path(__file__).resolve().parents[1] / "src" / "security_auditor" / "scanners" / "secrets"
        forbidden_imports = {"subprocess", "runpy", "importlib", "pickle"}
        forbidden_calls = {"eval", "exec", "compile"}
        for path in package.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(forbidden_imports.intersection(alias.name for alias in node.names), path)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, forbidden_imports, path)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_calls, path)
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertFalse(bool(re.search(r"gh[pousr]_[A-Za-z0-9]{36}\b", source)))


if __name__ == "__main__":
    unittest.main()
