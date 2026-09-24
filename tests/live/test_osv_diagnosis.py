"""Explicitly gated, bounded OSV shape diagnosis over synthetic coordinates."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from security_auditor.core.config import VulnerabilityLimits
from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.dependencies import DependencyScanner
from security_auditor.scanners.dependencies.cache import VulnerabilityCache
from security_auditor.scanners.dependencies.providers import OSV_BASE, OSVProvider, _transport


@unittest.skipUnless(os.environ.get("SECURITY_AUDITOR_LIVE_OSV_DIAGNOSIS") == "1",
                     "OSV diagnosis requires an explicit live gate")
class LiveOSVDiagnosis(unittest.TestCase):
    def test_staged_synthetic_flow_stops_at_first_failure(self):
        coordinates = (
            "PyYAML==5.3.1", "idna==3.10", "Jinja2==2.10", "requests==2.19.0",
            "urllib3==1.25.8", "Django==2.2.0", "Flask==0.12",
            "cryptography==2.8", "Pillow==6.2.0", "packaging==24.2",
        )
        limits = VulnerabilityLimits(max_queries=10, max_batch_size=10,
                                     max_total_batch_requests=1,
                                     max_total_detail_requests=3,
                                     max_total_provider_requests=4,
                                     max_advisories=100)
        cumulative = {"batch": 0, "detail": 0}
        with tempfile.TemporaryDirectory(prefix="auditor-osv-diagnosis-") as directory:
            base = Path(directory)
            for flow, count in enumerate((1, 2, 5, 10), start=1):
                target = base / f"synthetic-{count}"
                target.mkdir()
                (target / "requirements.txt").write_text("\n".join(coordinates[:count]) + "\n", encoding="utf-8")
                cache = VulnerabilityCache(base / f"tool-cache-{count}")
                attempts: list[str] = []
                shapes: list[dict] = []

                def guarded_transport(method, url, body, request_limits):
                    self.assertTrue(url.startswith(OSV_BASE + "/"))
                    self.assertLessEqual(request_limits.timeout_seconds, 10)
                    self.assertLessEqual(request_limits.max_response_bytes, 1024 * 1024)
                    if method == "POST":
                        self.assertEqual(url, OSV_BASE + "/querybatch")
                        parsed = json.loads(body)
                        self.assertEqual(set(parsed), {"queries"})
                        self.assertEqual(len(parsed["queries"]), count)
                        self.assertTrue(all(set(query) == {"package", "version"}
                                            and set(query["package"]) == {"ecosystem", "name"}
                                            for query in parsed["queries"]))
                    else:
                        self.assertEqual(method, "GET")
                        self.assertTrue(url.startswith(OSV_BASE + "/vulns/"))
                        self.assertIsNone(body)
                    attempts.append(method)

                    def observe(shape):
                        shapes.append(shape)

                    value, size = _transport(method, url, body, request_limits, observer=observe)
                    if method == "POST" and isinstance(value.get("results"), list):
                        results = value["results"]
                        shapes[-1]["results_count"] = len(results)
                        shapes[-1]["result_types"] = [type(item).__name__ for item in results[:10]]
                        shapes[-1]["result_keys"] = [tuple(sorted(k for k in item if k in {"vulns", "next_page_token"}))
                                                      if isinstance(item, dict) else () for item in results[:10]]
                        shapes[-1]["vulns_counts"] = [len(item["vulns"]) if isinstance(item, dict)
                                                      and isinstance(item.get("vulns"), list) else None
                                                      for item in results[:10]]
                        shapes[-1]["advisory_id_count"] = sum(n or 0 for n in shapes[-1]["vulns_counts"])
                    return value, size

                discovery = discover(ScanTarget(target, "synthetic"), DiscoveryPolicy())
                session = ScanSession(f"synthetic-{count}", ScanTarget(target, "synthetic"),
                                      ScanProfile.STANDARD, datetime.now(timezone.utc), offline=False)
                outcome = DependencyScanner(vulnerability=limits,
                                            provider=OSVProvider(guarded_transport), cache=cache).scan_with_inventory(
                                                session, discovery)
                stats = dict(outcome.result.summary.details)
                batch = attempts.count("POST")
                detail = attempts.count("GET")
                cumulative["batch"] += batch
                cumulative["detail"] += detail
                bad = [d.message for d in outcome.result.diagnostics if d.code == "VULN_PROVIDER_BAD_RESPONSE"]
                print("LIVE_OSV_DIAGNOSIS " + json.dumps({
                    "flow": flow, "keys": count, "batch_attempts": batch, "detail_attempts": detail,
                    "total_attempts": len(attempts), "provider_batch_used": stats["batch_requests_used"],
                    "provider_detail_used": stats["detail_requests_used"],
                    "findings": len(outcome.result.findings), "coverage": outcome.result.status,
                    "diagnostics": [d.code for d in outcome.result.diagnostics], "bad_response": bad,
                    "shapes": shapes, "cumulative": {**cumulative, "total": sum(cumulative.values())},
                }, sort_keys=True), flush=True)
                self.assertLessEqual(batch, 1)
                self.assertLessEqual(detail, 3)
                self.assertLessEqual(len(attempts), 4)
                if bad or not outcome.result.findings:
                    self.fail("Live diagnosis stopped at first failed flow; see safe structural output")
