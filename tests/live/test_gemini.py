"""One opt-in synthetic Gemini request; never reads a real target repository."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from security_auditor.ai import AIReviewer, AIReviewStatus
from security_auditor.ai.credentials import gemini_api_key
from security_auditor.core.config import AISettings
from security_auditor.core.models import (Confidence, Evidence, Finding, Location,
                                          Remediation, ScanProfile, ScanSession,
                                          ScanTarget, ScannerMetadata, ScannerResult,
                                          Severity)


@unittest.skipUnless(os.environ.get("SECURITY_AUDITOR_LIVE_GEMINI_TEST") == "1",
                     "Live Gemini test requires explicit gate")
class LiveGeminiTest(unittest.TestCase):
    def test_one_synthetic_review(self):
        with tempfile.TemporaryDirectory(prefix="auditor-live-gemini-") as directory:
            root = Path(directory)
            tool_dir = Path(__file__).resolve().parents[2]
            key = gemini_api_key(root, tool_dir)
            if key is None:
                self.skipTest("No trusted Gemini API key available")
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
                                             max_requests=1, max_retries=0,
                                             max_output_tokens=1024,
                                             thinking_level="medium"))
            output = StringIO()
            errors = StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                result = reviewer.review(session, (scanner,), allow_online_ai=True)
            serialized = json.dumps(asdict(result), default=str)
            self.assertFalse(key in output.getvalue(), "API key leaked to stdout")
            self.assertFalse(key in errors.getvalue(), "API key leaked to stderr")
            self.assertFalse(key in serialized, "API key leaked to serialized review")
            self.assertEqual(result.summary.requests, 1)
            self.assertEqual(result.summary.status, AIReviewStatus.COMPLETE,
                             tuple(d.code for d in result.summary.diagnostics))
            self.assertEqual(len(result.reviews), 1)
            review = result.reviews[0]
            self.assertEqual(review.provider, "gemini")
            self.assertEqual(review.model, "gemini-3.8-flash")
            self.assertIn(review.verdict.value, {
                "CONFIRMED", "LIKELY_VALID", "UNCERTAIN",
                "LIKELY_FALSE_POSITIVE", "INSUFFICIENT_CONTEXT"})
            self.assertIn(review.confidence.value, {"HIGH", "MEDIUM", "LOW"})
            print("LIVE_GEMINI_RESULT "
                  f"verdict={review.verdict.value} confidence={review.confidence.value} "
                  f"input_tokens={review.usage.input_tokens} "
                  f"output_tokens={review.usage.output_tokens} "
                  f"total_tokens={review.usage.total_tokens}")
