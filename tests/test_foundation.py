"""Contract and parser checks; no target fixture is executed."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import load_config  # noqa: E402
from security_auditor.core.models import (  # noqa: E402
    Confidence, Evidence, Finding, Location, Remediation, ScanProfile, Severity,
)


class FoundationTests(unittest.TestCase):
    def test_example_config_loads(self):
        config = load_config(Path(__file__).resolve().parents[1] / "security-auditor.example.toml")
        self.assertEqual(config.profile, ScanProfile.STANDARD)
        self.assertTrue(config.offline)
        self.assertFalse(config.respect_gitignore)

    def test_config_rejects_unsafe_limit(self):
        with patch.object(Path, "open", return_value=BytesIO(b"[discovery]\nmax_file_count = 999999999\n")):
            with self.assertRaises(ValueError):
                load_config(Path("unused.toml"))

    def test_finding_keeps_severity_and_confidence_distinct(self):
        finding = Finding(
            id="test", rule_id="FAKE-1", scanner_id="fake", category="test",
            title="Synthetic", description="Clearly fake", severity=Severity.HIGH,
            confidence=Confidence.LOW, location=Location("sample.py", 1, 1),
            evidence=Evidence("redacted", "[REDACTED]"), rationale="test",
            remediation=Remediation("Use a fake test value"), fingerprint="sample",
            created_at=datetime.now(timezone.utc), tool_version="0.0.0",
        )
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.LOW)
        with self.assertRaises(FrozenInstanceError):
            finding.title = "changed"


if __name__ == "__main__":
    unittest.main()
