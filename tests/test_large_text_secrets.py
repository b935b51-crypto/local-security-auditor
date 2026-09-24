"""Synthetic large-text fixtures only; no target code is executed."""

from __future__ import annotations

import base64
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security_auditor.core.config import AuditConfig, SecretLimits
from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.secrets import SecretScanner
from security_auditor.gate.service import GateStatus, evaluate_gate
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import html, json_report


MIB = 1024 * 1024
TOKEN = "ghp_" + "Ab12" * 9


class LargeTextSecretTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-large-text-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.session = ScanSession(
            "synthetic", ScanTarget(self.root, "synthetic"),
            ScanProfile.STANDARD, datetime.now(timezone.utc),
        )

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, limits: SecretLimits | None = None):
        discovered = discover(self.session.target, DiscoveryPolicy())
        return SecretScanner(limits).scan_discovery(self.session, discovered)

    def test_mode_switch_and_legacy_cap(self):
        self.write("small.txt", ("prefix " + TOKEN + "\n").encode())
        result = self.scan()
        self.assertEqual(dict(result.summary.details)["full_buffer_files"], 1)
        self.assertEqual(dict(result.summary.details)["large_text_files_scanned"], 0)
        self.write("large.txt", b"ordinary\n" * 120_000)
        result = self.scan()
        self.assertEqual(result.status, "completed")
        self.assertEqual(dict(result.summary.details)["full_buffer_files"], 1)
        self.assertEqual(dict(result.summary.details)["large_text_files_scanned"], 1)
        capped = self.scan(replace(SecretLimits(), max_file_bytes=MIB))
        self.assertIn("SECRET_FILE_TOO_LARGE", {d.code for d in capped.diagnostics})
        self.assertEqual(dict(capped.summary.details)["large_text_files_scanned"], 0)

    def test_long_line_cross_chunk_rules_and_redaction(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"synthetic"}').rstrip(b"=").decode()
        jwt = header + "." + payload + "." + "Ab12" * 8
        assignment = 'api_key = "SyntheticOnlyAb12Cd34Ef56"'
        url = "postgres://user:SyntheticOnlyAb12Cd34@localhost/db"
        aws_id = "AKIA" + "A1B2C3D4" * 2
        aws_secret = 'aws_secret_access_key = "S7p8Q9r0T1u2V3w4X5y6Z7a8"'
        # The token begins six bytes before a reader chunk boundary.
        prefix = b"safe\n" * (MIB // 5)
        padding = b"x" * ((65536 - 6 - len(prefix) % 65536) % 65536)
        long_line = padding + b" " + TOKEN.encode() + b" " + jwt.encode() + b" "
        long_line += assignment.encode() + b" " + url.encode() + b" " + aws_id.encode() + b"\n"
        data = prefix + long_line + aws_secret.encode() + b"\n"
        if len(data) <= MIB:
            data += b"safe\n" * 300
        self.write("large.txt", data)
        result = self.scan()
        rules = {finding.rule_id for finding in result.findings}
        self.assertEqual(result.status, "completed")
        self.assertTrue({"SECRET.GITHUB.TOKEN", "SECRET.JWT", "SECRET.CONNECTION_STRING",
                         "SECRET.AWS.ACCESS_KEY", "SECRET.GENERIC.ASSIGNMENT"} <= rules)
        self.assertEqual(next(f for f in result.findings if f.rule_id == "SECRET.AWS.ACCESS_KEY").severity.value,
                         "HIGH")
        self.assertGreater(dict(result.summary.details)["long_lines_segment_scanned"], 0)
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn(url, json.dumps(asdict(result), default=str))

    def test_private_marker_state_and_unterminated_final_line(self):
        body = b"FAKE_PRIVATE_BODY_ONLY_" + b"Q7r8" * 100
        data = b"safe\n" * 210_000
        data += b"x" * 65520 + b" -----BEGIN PRIVATE KEY-----\r\n"
        data += body + b"\r\n-----END PRIVATE KEY-----\r\n"
        data += b"x" * 131072
        self.write("large.pem", data)
        result = self.scan()
        self.assertEqual(result.status, "completed")
        self.assertEqual(sum(f.rule_id == "SECRET.PRIVATE_KEY.PEM" for f in result.findings), 1)
        self.assertNotIn(body.decode(), repr(result))
        self.assertNotIn("SECRET_PRIVATE_KEY_UNTERMINATED", {d.code for d in result.diagnostics})

    def test_invalid_utf8_and_incomplete_rule_context(self):
        self.write("invalid.log", b"safe\n" * 210_000 + b"\xff")
        failed = self.scan()
        self.assertEqual(failed.status, "partial")
        self.assertTrue(any(d.code == "SECRET_DECODE_UNAVAILABLE" and d.path == "invalid.log"
                            for d in failed.diagnostics))
        (self.root / "invalid.log").unlink()
        # More than one overlap of whitespace in a long assignment is not
        # silently asserted to have complete rule coverage.
        self.write("gap.log", b"safe\n" * 210_000 +
                   b"api_key =" + b" " * 20_000 + b"SyntheticOnlyAb12Cd34Ef56\n")
        partial = self.scan()
        self.assertEqual(partial.status, "partial")
        self.assertIn("SECRET_LARGE_TEXT_INCOMPLETE", {d.code for d in partial.diagnostics})

    def test_four_mib_and_discovery_ceiling(self):
        self.write("within.log", b"x" * (4 * MIB))
        result = self.scan()
        self.assertEqual(dict(result.summary.details)["large_text_files_scanned"], 1)
        self.write("outside.log", b"x" * (4 * MIB + 1))
        discovered = discover(self.session.target, DiscoveryPolicy())
        self.assertFalse(any(a.path == "outside.log" for a in discovered.artifacts))

    def test_cross_reader_boundary_utf8_crlf_and_exact_columns(self):
        # A three-byte UTF-8 character straddles the 64 KiB reader boundary.
        prefix = b"safe\n" * (MIB // 5)
        line = b"x" * (65536 - len(prefix) % 65536 - 1)
        line += "中".encode("utf-8") + b" " + TOKEN.encode() + b"\r\n"
        self.write("boundary.log", prefix + line)
        result = self.scan()
        tokens = [f for f in result.findings if f.rule_id == "SECRET.GITHUB.TOKEN"]
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0].location.start_line, len(prefix) // 5 + 1)
        self.assertEqual(tokens[0].location.start_column, line.decode("utf-8").index(TOKEN) + 1)
        self.assertEqual(tokens[0].location.path, "boundary.log")

    def test_fingerprint_and_location_stable_across_modes(self):
        self.write("stable.log", ("prefix " + TOKEN + "\n").encode())
        small = self.scan()
        anchor = next(f for f in small.findings if f.rule_id == "SECRET.GITHUB.TOKEN")
        self.write("stable.log", ("prefix " + TOKEN + "\n").encode() + b"safe\n" * 210_000)
        large = self.scan()
        counterpart = next(f for f in large.findings if f.rule_id == "SECRET.GITHUB.TOKEN")
        self.assertEqual(large.status, "completed")
        self.assertEqual((anchor.rule_id, anchor.location, anchor.fingerprint),
                         (counterpart.rule_id, counterpart.location, counterpart.fingerprint))

    def test_each_detector_crosses_byte_chunk_boundary_without_duplicate(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"synthetic"}').rstrip(b"=").decode()
        jwt = header + "." + payload + "." + "Ab12" * 8
        cases = (
            (TOKEN, "SECRET.GITHUB.TOKEN"),
            (jwt, "SECRET.JWT"),
            ('api_key = "SyntheticOnlyAb12Cd34Ef56"', "SECRET.GENERIC.ASSIGNMENT"),
            ("postgres://user:SyntheticOnlyAb12Cd34@localhost/db", "SECRET.CONNECTION_STRING"),
            ("AKIA" + "A1B2C3D4" * 2, "SECRET.AWS.ACCESS_KEY"),
            ("-----BEGIN PRIVATE KEY-----\nFAKE_BODY\n-----END PRIVATE KEY-----", "SECRET.PRIVATE_KEY.PEM"),
        )
        for sample, rule in cases:
            with self.subTest(rule=rule):
                prefix = b"safe\n" * 210_000
                # The first five bytes of the sample land before a reader boundary.
                padding = b"x" * ((65536 - (len(prefix) + 6) % 65536) % 65536)
                self.write("boundary.log", prefix + padding + b" " + sample.encode() + b"\n")
                result = self.scan()
                self.assertEqual(result.status, "completed")
                self.assertEqual(sum(f.rule_id == rule for f in result.findings), 1)
                self.assertEqual(dict(result.summary.details)["large_text_files_scanned"], 1)

    def test_long_line_sizes_and_match_cap(self):
        for line_size in (64 * 1024, 128 * 1024, 512 * 1024, MIB):
            with self.subTest(line_size=line_size):
                self.write("one.log", b"safe\n" * 210_000 + b"x" * line_size + b" " + TOKEN.encode())
                result = self.scan()
                self.assertEqual(result.status, "completed")
                self.assertEqual(sum(f.rule_id == "SECRET.GITHUB.TOKEN" for f in result.findings), 1)
        self.write("one.log", b"safe\n" * 210_000 + (TOKEN.encode() + b" ") * 8)
        limited = self.scan(replace(SecretLimits(), max_matches_per_rule_per_file=2))
        self.assertEqual(limited.status, "partial")
        self.assertEqual(sum(f.rule_id == "SECRET.GITHUB.TOKEN" for f in limited.findings), 2)

    def test_total_byte_and_elapsed_budgets(self):
        self.write("large.log", b"safe\n" * 210_000)
        byte_limited = self.scan(replace(SecretLimits(), max_total_bytes=MIB))
        self.assertEqual(byte_limited.status, "aborted")
        self.assertIn("SECRET_SCAN_BYTE_BUDGET_REACHED", {d.code for d in byte_limited.diagnostics})
        with patch("security_auditor.scanners.secrets.large_text.monotonic", return_value=10**20):
            time_limited = self.scan(replace(SecretLimits(), max_elapsed_seconds=1))
        self.assertEqual(time_limited.status, "aborted")
        self.assertIn("SECRET_SCAN_ABORTED", {d.code for d in time_limited.diagnostics})

    def test_unterminated_private_key_and_finding_cap_are_incomplete(self):
        self.write("large.log", b"safe\n" * 210_000 + b"-----BEGIN PRIVATE KEY-----\nFAKE_BODY")
        missing_end = self.scan()
        self.assertEqual(missing_end.status, "partial")
        self.assertIn("SECRET_PRIVATE_KEY_UNTERMINATED", {d.code for d in missing_end.diagnostics})
        self.assertEqual(dict(missing_end.summary.details)["large_text_files_partial"], 1)
        self.write("large.log", b"safe\n" * 210_000 + (TOKEN.encode() + b" ") * 6)
        limited = self.scan(replace(SecretLimits(), max_findings_per_file=2))
        self.assertEqual(limited.status, "partial")
        self.assertEqual(len(limited.findings), 2)
        self.assertEqual(dict(limited.summary.details)["large_text_files_partial"], 1)

    def test_public_reporting_and_gate_modes(self):
        self.write("large.log", b"safe\n" * 210_000)
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        view = json.loads(json_report.render(report))
        large = next(s["large_text"] for s in view["scanners"] if s["id"] == "secrets")
        self.assertEqual(large["large_text_files_scanned"], 1)
        self.assertEqual(large["large_text_files_partial"], 0)
        self.assertIn("LARGE_TEXT_BOUNDED", large["modes"])
        self.assertIn("大型文字檔已使用有界分塊模式完成分析", html.render(report))
        self.assertEqual(evaluate_gate(view).status, GateStatus.PASS)
        self.write("large.log", b"safe\n" * 210_000 + b"api_key =" + b" " * 20_000 + b"SyntheticOnlyAb12Cd34Ef56\n")
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        view = json.loads(json_report.render(report))
        large = next(s["large_text"] for s in view["scanners"] if s["id"] == "secrets")
        self.assertEqual(large["large_text_files_partial"], 1)
        self.assertEqual(evaluate_gate(view).status, GateStatus.BLOCK)
        self.write("large.log", b"safe\n" * 210_000 + TOKEN.encode() + b"\n")
        report = ScanOrchestrator().run_scan(ScanRequest(self.root, AuditConfig(), ScanProfile.STANDARD, True, False))
        public_json = json_report.render(report)
        public_html = html.render(report)
        self.assertNotIn(TOKEN, public_json)
        self.assertNotIn(TOKEN, public_html)
        self.assertEqual(evaluate_gate(json.loads(public_json)).status, GateStatus.BLOCK)


if __name__ == "__main__":
    unittest.main()
