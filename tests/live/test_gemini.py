"""One opt-in synthetic Gemini request; never reads a real target repository."""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from security_auditor.ai import AIReviewer, AIReviewStatus
from security_auditor.core.config import AISettings
from security_auditor.core.models import (Confidence, Evidence, Finding, Location,
                                          Remediation, ScanProfile, ScanSession,
                                          ScanTarget, ScannerMetadata, ScannerResult,
                                          Severity)


@unittest.skipUnless(os.environ.get("SECURITY_AUDITOR_LIVE_GEMINI_TEST") == "1"
                     and bool(os.environ.get("GEMINI_API_KEY")),
                     "Live Gemini test requires explicit gate and GEMINI_API_KEY")
class LiveGeminiTest(unittest.TestCase):
    def test_one_synthetic_review(self):
        with tempfile.TemporaryDirectory(prefix="auditor-live-gemini-") as directory:
            root = Path(directory)
            session = ScanSession("live-synthetic", ScanTarget(root, "synthetic"),
                                  ScanProfile.DEEP, datetime.now(timezone.utc), offline=False)
            fingerprint = hashlib.sha256(b"live-synthetic-finding").hexdigest()
            finding = Finding(
                fingerprint[:16], "SAST.PYTHON.SQL_INJECTION", "sast", "sast",
                "Synthetic potential SQL injection", "Synthetic static example only.",
                Severity.HIGH, Confidence.MEDIUM, Location("example.py", 3, 1),
                Evidence("static", "[REDACTED]", (("source_category", "HTTP_INPUT"),)),
                "A synthetic external input may reach a SQL sink.",
                Remediation("Use parameterized SQL queries."), fingerprint,
                datetime.now(timezone.utc), "test",
            )
            scanner = ScannerResult(ScannerMetadata("sast", "test", "test", True), (finding,))
            reviewer = AIReviewer(AISettings(enabled=True, max_reviews=1,
                                             max_requests=1, max_output_tokens=1024,
                                             thinking_level="low"))
            result = reviewer.review(session, (scanner,), allow_online_ai=True)
            self.assertEqual(result.summary.status, AIReviewStatus.COMPLETE)
            self.assertEqual(len(result.reviews), 1)
