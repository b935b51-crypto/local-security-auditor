"""Sixteen synthetic JS/TS source-provenance golden cases; no target is run."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import SecretLimits
from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget, Severity
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.secrets import SecretScanner
from security_auditor.scanners.secrets.js_source import (
    expression_source, proven_environment_parameters,
)


ASSIGNMENT = "SECRET.GENERIC.ASSIGNMENT"
ENTROPY = "SECRET.GENERIC.ENTROPY"


class SecretSourceAwarenessGoldenTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="auditor-source-awareness-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"),
                                   ScanProfile.STANDARD, datetime.now(timezone.utc))

    def scan(self, path: str, source: str, limits: SecretLimits | None = None):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
        result = SecretScanner(limits).scan_discovery(
            self.session, discover(self.session.target, DiscoveryPolicy()),
        )
        self.assertEqual(result.status, "completed")
        return result

    def assert_no_generic(self, result) -> None:
        self.assertFalse({ASSIGNMENT, ENTROPY}.intersection(f.rule_id for f in result.findings))

    def test_01_typed_environment_wrapper_trim_is_reference(self):
        source = ("export function read(environment: Partial<NodeJS.ProcessEnv>) {\n"
                  "  const apiKey = environment.FUGLE_API_KEY?.trim();\n}\n")
        self.assertEqual(proven_environment_parameters(source), frozenset({"environment"}))
        self.assertEqual(expression_source("environment.FUGLE_API_KEY?.trim()",
                                           frozenset({"environment"})), "ENV_REFERENCE")
        self.assert_no_generic(self.scan("src/environment.ts", source))

    def test_02_direct_process_environment(self):
        self.assertEqual(expression_source("process.env.FUGLE_API_KEY"), "ENV_REFERENCE")
        self.assert_no_generic(self.scan("src/config.ts", "const apiKey = process.env.FUGLE_API_KEY;\n"))

    def test_03_bracket_process_environment(self):
        self.assertEqual(expression_source('process.env["FUGLE_API_KEY"]'), "ENV_REFERENCE")
        self.assert_no_generic(self.scan("src/config.ts", 'const apiKey = process.env["FUGLE_API_KEY"];\n'))

    def test_04_process_environment_literal_fallback_stays_visible(self):
        result = self.scan("src/config.ts", "const apiKey = process.env.API_KEY ?? 'A9b8C7d6E5f4G3h2I1j0';\n")
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_05_wrapper_literal_fallback_stays_visible(self):
        source = ("function read(environment: Partial<NodeJS.ProcessEnv>) {\n"
                  "  const apiKey = environment.API_KEY || 'A9b8C7d6E5f4G3h2I1j0';\n}\n")
        result = self.scan("src/config.ts", source)
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_06_unknown_config_object_is_not_trusted(self):
        self.assertEqual(expression_source("config.API_KEY", frozenset({"environment"})),
                         "RUNTIME_REFERENCE")
        self.assert_no_generic(self.scan("src/config.ts", "const apiKey = config.API_KEY;\n"))

    def test_07_direct_hardcoded_literal_stays_visible(self):
        result = self.scan("src/config.ts", "const apiKey = 'A9b8C7d6E5f4G3h2I1j0';\n")
        self.assertIn((ASSIGNMENT, Severity.MEDIUM),
                      {(f.rule_id, f.severity) for f in result.findings})

    def test_08_unknown_helper_is_neither_trusted_nor_hardcoded(self):
        self.assertEqual(expression_source("loadApiKey()"), "RUNTIME_REFERENCE")
        self.assert_no_generic(self.scan("src/config.ts", "const apiKey = loadApiKey();\n"))

    def test_09_runtime_preview_token_property_is_not_entropy_material(self):
        source = ("success(service.commitInitialPortfolio({ token: "
                  "success(await service.previewInitialPortfolio(input)).token }));\n")
        self.assert_no_generic(self.scan("test/opening-portfolio.test.ts", source))

    def test_10_synthetic_test_literal_is_not_medium_credential(self):
        result = self.scan("test/auth.test.ts", "const apiKey = 'fake-test-api-key-A9b8C7d6E5f4';\n")
        self.assert_no_generic(result)

    def test_11_same_marker_in_production_is_not_suppressed(self):
        result = self.scan("src/auth.ts", "const apiKey = 'fake-test-api-key-A9b8C7d6E5f4';\n")
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_12_provider_shape_in_test_remains_high(self):
        fake_provider = "ghp_" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:36])
        result = self.scan("test/provider.test.ts", f"const apiKey = '{fake_provider}';\n")
        self.assertIn(("SECRET.GITHUB.TOKEN", Severity.HIGH),
                      {(f.rule_id, f.severity) for f in result.findings})
        self.assertNotIn(fake_provider, repr(result))

    def test_13_uuid_identifier_is_not_secret_entropy(self):
        self.assert_no_generic(self.scan("src/id.ts",
                                         "const transactionId = '550e8400-e29b-41d4-a716-446655440000';\n"))

    def test_14_digest_identifier_is_not_secret_entropy(self):
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assert_no_generic(self.scan("src/digest.ts", f"const expectedDigest = '{digest}';\n"))

    def test_15_opaque_literal_in_secret_identifier_is_detected(self):
        opaque = "Ab7Cde9FgH2IjK4LmN6OpQ8RsT0UvW1XyZ3aBcD5eFgH7iJkL9mNoP2qRsT4uVwX6"
        result = self.scan("src/auth.ts", f"const apiToken = '{opaque}';\n")
        self.assertTrue({ASSIGNMENT, ENTROPY}.intersection(f.rule_id for f in result.findings))
        self.assertNotIn(opaque, repr(result))

    def test_16_synthetic_private_note_fixture_is_not_credential(self):
        result = self.scan("test/portfolio-ai.test.ts",
                           "const secret = 'PRIVATE_MESSAGE_NOTE_123';\n"
                           "const context = fixture({ hiddenNote: secret });\n")
        self.assert_no_generic(result)

    def test_multiline_literal_keeps_relative_location(self):
        result = self.scan("src/multiline.ts", "const apiKey =\n  'A9b8C7d6E5f4G3h2I1j0';\n")
        matches = [f for f in result.findings if f.rule_id == ASSIGNMENT]
        self.assertEqual(len(matches), 1)
        self.assertEqual((matches[0].location.path, matches[0].location.start_line,
                          matches[0].location.start_column), ("src/multiline.ts", 2, 4))

    def test_mixed_template_keeps_static_literal_control(self):
        source = "const apiKey = `${process.env.API_KEY}-A9b8C7d6E5f4G3h2I1j0`;\n"
        result = self.scan("src/mixed.ts", source)
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_marker_must_have_word_boundary(self):
        result = self.scan("test/contest.test.ts", "const apiKey = 'contest-A9b8C7d6E5f4G3h2I1j0';\n")
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_bounded_large_text_path_uses_literal_provenance(self):
        limits = replace(SecretLimits(), full_buffer_threshold_bytes=64)
        source = ("const token = previewInitialPortfolio(input).token;\n" +
                  "// inert padding\n" * 12 + "const apiKey = 'A9b8C7d6E5f4G3h2I1j0';\n")
        result = self.scan("src/large.ts", source, limits)
        self.assertEqual([f.rule_id for f in result.findings], [ASSIGNMENT])

    def test_unknown_config_or_helper_with_literal_fallback_stays_visible(self):
        source = ("const apiKey = config.API_KEY ?? 'A9b8C7d6E5f4G3h2I1j0';\n"
                  "const token = makeToken() || 'Q1w2E3r4T5y6U7i8O9p0';\n")
        result = self.scan("src/fallback.ts", source)
        self.assertEqual(len([f for f in result.findings if f.rule_id == ASSIGNMENT]), 2)

    def test_template_literal_material_remains_detectable(self):
        result = self.scan("src/template.ts", "const apiKey = `A9b8C7d6E5f4G3h2I1j0`;\n")
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_ternary_literal_fallback_remains_detectable(self):
        source = "const apiKey = selected ? process.env.API_KEY : 'A9b8C7d6E5f4G3h2I1j0';\n"
        result = self.scan("src/ternary.ts", source)
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})

    def test_template_interpolation_literal_fallback_remains_detectable(self):
        source = 'const apiKey = `${process.env.API_KEY || "A9b8C7d6E5f4G3h2I1j0"}`;\n'
        result = self.scan("src/interpolated.ts", source)
        self.assertIn(ASSIGNMENT, {f.rule_id for f in result.findings})


if __name__ == "__main__":
    unittest.main()
