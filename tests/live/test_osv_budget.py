"""Explicitly gated, single bounded live OSV operation over inert coordinates."""

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


@unittest.skipUnless(os.environ.get("SECURITY_AUDITOR_LIVE_OSV_BUDGET_TEST") == "1",
                     "Bounded live OSV test requires explicit gate")
class BoundedLiveOSVTest(unittest.TestCase):
    def test_one_bounded_synthetic_scan_and_offline_replay(self):
        coordinates = (
            "PyYAML==5.3.1", "Jinja2==2.10", "requests==2.19.0",
            "urllib3==1.25.8", "Django==2.2.0", "Flask==0.12",
            "cryptography==2.8", "Pillow==6.2.0", "idna==3.10",
            "packaging==24.2",
        )
        limits = VulnerabilityLimits(max_queries=10, max_batch_size=10,
                                     max_total_batch_requests=1,
                                     max_total_detail_requests=3,
                                     max_total_provider_requests=4,
                                     max_advisories=100)
        with tempfile.TemporaryDirectory(prefix="auditor-osv-budget-") as directory:
            base = Path(directory)
            target = base / "synthetic"
            target.mkdir()
            (target / "requirements.txt").write_text("\n".join(coordinates) + "\n", encoding="utf-8")
            cache = VulnerabilityCache(base / "tool-cache")
            calls = []
            shapes = []

            def guarded_transport(method, url, body, request_limits):
                self.assertTrue(url.startswith(OSV_BASE + "/"))
                self.assertTrue(url.startswith("https://"))
                self.assertLessEqual(request_limits.timeout_seconds, 10)
                self.assertLessEqual(request_limits.max_response_bytes, 1024 * 1024)
                if method == "POST":
                    payload = json.loads(body)
                    self.assertEqual(set(payload), {"queries"})
                    self.assertEqual(len(payload["queries"]), len(coordinates))
                    self.assertEqual({tuple(sorted(query)) for query in payload["queries"]},
                                     {("package", "version")})
                else:
                    self.assertEqual(method, "GET")
                    self.assertIsNone(body)
                calls.append(method)
                value, size = _transport(method, url, body, request_limits, observer=shapes.append)
                if method == "POST" and isinstance(value.get("results"), list):
                    shapes[-1]["results_count"] = len(value["results"])
                    shapes[-1]["max_advisories_in_result"] = max(
                        (len(item["vulns"]) for item in value["results"]
                         if isinstance(item, dict) and isinstance(item.get("vulns"), list)), default=0)
                return value, size

            discovery = discover(ScanTarget(target, "synthetic"), DiscoveryPolicy())
            online_session = ScanSession("synthetic-online", ScanTarget(target, "synthetic"),
                                         ScanProfile.STANDARD, datetime.now(timezone.utc), offline=False)
            online = DependencyScanner(vulnerability=limits,
                                       provider=OSVProvider(guarded_transport), cache=cache).scan_with_inventory(
                                           online_session, discovery)
            stats = dict(online.result.summary.details)
            diagnostic_codes = tuple(d.code for d in online.result.diagnostics)
            print("LIVE_OSV_OVERFLOW_RESULT " + json.dumps({
                "keys": len(coordinates), "batch": calls.count("POST"), "detail": calls.count("GET"),
                "total": len(calls), "findings": len(online.result.findings),
                "status": online.result.status, "diagnostics": diagnostic_codes,
                "advisories_seen": stats["advisories_seen"],
                "advisories_accepted": stats["advisories_accepted"],
                "advisories_truncated": stats["advisories_truncated"],
                "advisory_limit": stats["advisory_limit"], "shapes": shapes,
            }, sort_keys=True), flush=True)
            self.assertEqual(stats["unique_package_versions"], 10)
            self.assertEqual(stats["batch_requests_used"], calls.count("POST"))
            self.assertEqual(stats["detail_requests_used"], calls.count("GET"))
            self.assertEqual(stats["total_requests_used"], len(calls))
            self.assertLessEqual(calls.count("POST"), limits.max_total_batch_requests)
            self.assertLessEqual(calls.count("GET"), limits.max_total_detail_requests)
            self.assertLessEqual(len(calls), limits.max_total_provider_requests)
            self.assertTrue(online.result.findings,
                            (tuple(d.code for d in online.result.diagnostics),
                             calls.count("POST"), calls.count("GET")))
            self.assertNotIn("VULN_PROVIDER_BAD_RESPONSE", diagnostic_codes)
            self.assertEqual(online.result.status, "partial")
            self.assertTrue(any(x.incomplete for x in online.lookups))
            self.assertFalse(any(x.status.value == "no_match" and x.incomplete for x in online.lookups))
            if shapes and shapes[0].get("max_advisories_in_result", 0) > limits.max_advisories:
                self.assertIn("DEPENDENCY_OSV_ADVISORY_LIMIT_REACHED", diagnostic_codes)
                self.assertTrue(stats["advisory_limit_reached"])
            for lookup in online.lookups:
                if lookup.incomplete:
                    self.assertFalse(cache._path(lookup.key).exists())

            offline_calls = []
            def forbidden_transport(*args):
                offline_calls.append(1)
                raise AssertionError("Offline replay attempted network")
            offline_session = ScanSession("synthetic-offline", ScanTarget(target, "synthetic"),
                                          ScanProfile.STANDARD, datetime.now(timezone.utc), offline=True)
            replay = DependencyScanner(vulnerability=limits,
                                       provider=OSVProvider(forbidden_transport), cache=cache).scan_with_inventory(
                                           offline_session, discovery)
            self.assertEqual(offline_calls, [])
            self.assertEqual(dict(replay.result.summary.details)["total_requests_used"], 0)
            print("LIVE_OSV_OFFLINE_REPLAY " + json.dumps({
                "requests": len(offline_calls),
                "cache_hits": dict(replay.result.summary.details)["cache_hits"],
            }, sort_keys=True), flush=True)
