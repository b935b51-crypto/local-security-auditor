"""Opt-in live OSV integration over one synthetic exact-version manifest."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from security_auditor.core.config import VulnerabilityLimits
from security_auditor.core.models import Confidence, ScanProfile, ScanSession, ScanTarget, Severity
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.dependencies import DependencyScanner
from security_auditor.scanners.dependencies.cache import VulnerabilityCache
from security_auditor.scanners.dependencies.models import LookupStatus
from security_auditor.scanners.dependencies.providers import OSV_BASE, OSVProvider, _transport


@unittest.skipUnless(os.environ.get("SECURITY_AUDITOR_LIVE_OSV_TEST") == "1",
                     "Live OSV test requires explicit gate")
class LiveOSVTest(unittest.TestCase):
    def test_one_synthetic_exact_version_and_offline_replay(self):
        key = ("PyPI", "pyyaml", "5.3.1")
        limits = VulnerabilityLimits(max_queries=1, max_batch_size=1, max_advisories=8,
                                     max_provider_seconds=60)
        with tempfile.TemporaryDirectory(prefix="auditor-live-osv-") as directory:
            base = Path(directory)
            target = base / "synthetic-target"
            target.mkdir()
            (target / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")
            cache = VulnerabilityCache(base / "tool-cache")
            self.assertFalse(cache.directory.is_relative_to(target))
            requests: list[str] = []

            def guarded_transport(method, url, body, request_limits):
                self.assertTrue(url.startswith(OSV_BASE + "/"))
                self.assertEqual(request_limits.timeout_seconds, 10)
                self.assertLessEqual(request_limits.max_response_bytes, 1024 * 1024)
                if method == "POST":
                    self.assertEqual(url, OSV_BASE + "/querybatch")
                    self.assertEqual(json.loads(body),
                                     {"queries": [{"package": {"ecosystem": "PyPI",
                                                               "name": "pyyaml"},
                                                   "version": "5.3.1"}]})
                else:
                    self.assertEqual(method, "GET")
                    self.assertTrue(url.startswith(OSV_BASE + "/vulns/"))
                    self.assertIsNone(body)
                requests.append(method)
                return _transport(method, url, body, request_limits)

            discovery = discover(ScanTarget(target, "synthetic"), DiscoveryPolicy())
            self.assertEqual([artifact.path for artifact in discovery.artifacts], ["requirements.txt"])
            session = ScanSession("synthetic-online", ScanTarget(target, "synthetic"),
                                  ScanProfile.STANDARD, datetime.now(timezone.utc), offline=False)
            online = DependencyScanner(vulnerability=limits,
                                       provider=OSVProvider(guarded_transport),
                                       cache=cache).scan_with_inventory(session, discovery)
            self.assertEqual(requests.count("POST"), 1)
            self.assertLessEqual(requests.count("GET"), limits.max_advisories)
            self.assertEqual(online.inventory.exact_keys(), (key,))
            self.assertEqual(len(online.lookups), 1)
            lookup = online.lookups[0]
            self.assertEqual(lookup.status, LookupStatus.MATCHED,
                             tuple(d.code for d in online.result.diagnostics))
            self.assertFalse(lookup.stale)
            self.assertTrue(lookup.vulnerabilities)
            self.assertEqual(online.result.status, "completed")
            self.assertEqual(len(online.result.findings), len(lookup.vulnerabilities))
            for advisory, finding in zip(sorted(lookup.vulnerabilities, key=lambda v: v.id),
                                         online.result.findings):
                self.assertFalse(advisory.withdrawn)
                self.assertIsInstance(advisory.severity, Severity)
                self.assertIsInstance(advisory.aliases, tuple)
                self.assertIsInstance(advisory.fixed_versions, tuple)
                self.assertLessEqual(len(advisory.references), 20)
                self.assertEqual(finding.rule_id, "DEPENDENCY.KNOWN_VULNERABILITY")
                self.assertEqual(finding.confidence, Confidence.MEDIUM)
                self.assertEqual(finding.severity, advisory.severity)
                self.assertEqual(finding.vulnerability.source, "OSV")
                self.assertEqual(finding.vulnerability.advisory_id, advisory.id)
                self.assertEqual((finding.dependency.ecosystem, finding.dependency.name,
                                  finding.dependency.version), key)
            cache_file = cache._path(key)
            self.assertTrue(cache_file.is_file())
            cached_text = cache_file.read_text(encoding="ascii")
            self.assertNotIn(str(target), cached_text)
            self.assertNotIn("requirements.txt", cached_text)
            cached = json.loads(cached_text)
            self.assertEqual(set(cached), {"schema", "key", "fetched_at", "status", "vulnerabilities"})
            self.assertTrue(all("affected" not in item and "ranges" not in item
                                for item in cached["vulnerabilities"]))

            offline_requests: list[str] = []
            def forbidden_transport(method, url, body, request_limits):
                offline_requests.append(method)
                raise AssertionError("Offline replay attempted network access")

            offline_session = ScanSession("synthetic-offline", ScanTarget(target, "synthetic"),
                                          ScanProfile.STANDARD, datetime.now(timezone.utc),
                                          offline=True)
            replay = DependencyScanner(vulnerability=limits,
                                       provider=OSVProvider(forbidden_transport),
                                       cache=cache).scan_with_inventory(offline_session, discovery)
            self.assertEqual(offline_requests, [])
            self.assertEqual(replay.lookups[0].status, LookupStatus.MATCHED)
            self.assertFalse(replay.lookups[0].stale)
            self.assertEqual(dict(replay.result.summary.details)["cache_hits"], 1)
            self.assertEqual(len(replay.result.findings), len(online.result.findings))
            print("LIVE_OSV_RESULT package=pyyaml version=5.3.1 ecosystem=PyPI "
                  f"requests={len(requests)} batch=1 details={requests.count('GET')} "
                  f"matches={len(lookup.vulnerabilities)} "
                  f"ids={','.join(v.id for v in lookup.vulnerabilities)} "
                  "cache_hit=1 offline_requests=0")


if __name__ == "__main__":
    unittest.main()
