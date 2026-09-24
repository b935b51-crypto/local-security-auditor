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
                return _transport(method, url, body, request_limits)

            discovery = discover(ScanTarget(target, "synthetic"), DiscoveryPolicy())
            online_session = ScanSession("synthetic-online", ScanTarget(target, "synthetic"),
                                         ScanProfile.STANDARD, datetime.now(timezone.utc), offline=False)
            online = DependencyScanner(vulnerability=limits,
                                       provider=OSVProvider(guarded_transport), cache=cache).scan_with_inventory(
                                           online_session, discovery)
            stats = dict(online.result.summary.details)
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
            self.assertTrue(stats["provider_budget_reached"])
            self.assertEqual(online.result.status, "partial")
            self.assertTrue(any(x.incomplete for x in online.lookups))
            self.assertFalse(any(x.status.value == "no_match" and x.incomplete for x in online.lookups))

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
            self.assertGreaterEqual(dict(replay.result.summary.details)["cache_hits"], 1)
            print("LIVE_OSV_BUDGET_RESULT "
                  f"packages={len(coordinates)} keys={stats['unique_package_versions']} "
                  f"batch={calls.count('POST')} detail={calls.count('GET')} total={len(calls)} "
                  f"matches={len(online.result.findings)} cache_hits={dict(replay.result.summary.details)['cache_hits']} "
                  f"deduplicated={stats['deduplicated_advisories']} budget_reached=1 "
                  f"ids={','.join(sorted({f.vulnerability.advisory_id for f in online.result.findings}))} "
                  "offline_requests=0")
