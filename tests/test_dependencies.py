"""Phase 4 static parser, provider, cache, and no-target-execution tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import DependencyLimits, VulnerabilityLimits, load_config
from security_auditor.core.models import ScanProfile, ScanSession, ScanTarget, Severity
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.dependencies import DependencyScanner
from security_auditor.scanners.dependencies.cache import VulnerabilityCache
from security_auditor.scanners.dependencies.models import DependencyIdentity, LookupResult, LookupStatus, Vulnerability
from security_auditor.scanners.dependencies.providers import OSVProvider, ProviderError


class FakeProvider:
    def __init__(self, advisories=None):
        self.calls = []
        self.advisories = advisories or {}

    def lookup_batch(self, keys, limits):
        self.calls.append(tuple(keys))
        return tuple(LookupResult(key, LookupStatus.MATCHED if self.advisories.get(key) else LookupStatus.NO_MATCH,
                                  tuple(self.advisories.get(key, ()))) for key in keys)


class DependencyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="auditor-phase4-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "target"
        self.root.mkdir()
        self.cache = VulnerabilityCache(self.base / "cache")

    def write(self, path: str, contents: str):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")

    def outcome(self, *, offline=True, provider=None, limits=None, vulnerability=None):
        session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"), ScanProfile.STANDARD,
                              datetime.now(timezone.utc), offline=offline)
        scanner = DependencyScanner(limits, vulnerability, provider, self.cache)
        return scanner.scan_with_inventory(session, discover(session.target, DiscoveryPolicy()))

    def test_requirements_exact_constraint_include_and_outside_root(self):
        self.write("requirements.txt", "-r nested/other.txt\n-c constraints.txt\nrequests>=2\nurllib3==1.26.5\n-r ../outside.txt\n")
        self.write("nested/other.txt", "idna==3.5\n")
        self.write("constraints.txt", "certifi==2024.1.1\n")
        result = self.outcome()
        keys = set(result.inventory.exact_keys())
        self.assertEqual(keys, {("PyPI", "urllib3", "1.26.5"), ("PyPI", "idna", "3.5")})
        self.assertEqual(result.result.status, "partial")
        self.assertIn("DEPENDENCY_INCLUDE_OUTSIDE_ROOT", {d.code for d in result.result.diagnostics})
        self.assertEqual(result.lookups[0].status, LookupStatus.OFFLINE_NO_CACHE)

    def test_manifest_lock_precedence_and_multiple_npm_versions(self):
        self.write("package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/other/node_modules/lodash": {"version": "4.17.20"},
        }}))
        result = self.outcome()
        self.assertEqual(set(result.inventory.exact_keys()), {("npm", "lodash", "4.17.20"), ("npm", "lodash", "4.17.21")})
        self.assertTrue(all(r.version_kind.value == "exact" for r in result.inventory.records))
        nested = next(r for r in result.inventory.records if r.version == "4.17.20")
        self.assertEqual(nested.directness.value, "transitive")
        self.assertEqual(nested.declared_constraint, "^4.17.0")

    def test_python_toml_locks_and_cargo_go(self):
        self.write("pyproject.toml", '[project]\ndependencies=["Requests>=2", "idna==3.5"]\n[project.optional-dependencies]\ntest=["pytest>=7"]\n')
        self.write("uv.lock", '[[package]]\nname="requests"\nversion="2.32.3"\nsource={registry="https://pypi.org/simple"}\n')
        self.write("Cargo.toml", '[dependencies]\nserde="1.0"\nlocal={path="../local"}\n')
        self.write("Cargo.lock", '[[package]]\nname="serde"\nversion="1.0.200"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n')
        self.write("go.mod", 'module example.com/app\nrequire (\n example.com/remote v1.2.3\n example.com/local v0.1.0\n)\nreplace example.com/local => ../local\n')
        result = self.outcome()
        keys = set(result.inventory.exact_keys())
        self.assertIn(("PyPI", "requests", "2.32.3"), keys)
        self.assertIn(("crates.io", "serde", "1.0.200"), keys)
        self.assertIn(("Go", "example.com/remote", "v1.2.3"), keys)
        self.assertNotIn(("Go", "example.com/local", "v0.1.0"), keys)
        self.assertFalse(any(r.name == "local" and r.key for r in result.inventory.records))

    def test_constraint_only_never_queried_or_finding(self):
        self.write("package.json", '{"dependencies":{"lodash":"^4.17.0"}}')
        provider = FakeProvider({("npm", "lodash", "4.17.0"): (Vulnerability("GHSA-fake"),)})
        result = self.outcome(offline=False, provider=provider)
        self.assertEqual(provider.calls, [])
        self.assertFalse(result.result.findings)
        self.assertIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in result.result.diagnostics})

    def test_fake_provider_findings_dedup_and_confidence(self):
        self.write("requirements.txt", "urllib3==1.26.5\nurllib3==1.26.5\n")
        key = ("PyPI", "urllib3", "1.26.5")
        provider = FakeProvider({key: (Vulnerability("GHSA-fake", ("CVE-2099-0001",), severity=Severity.HIGH,
                                                   fixed_versions=("1.26.6",)),)})
        result = self.outcome(offline=False, provider=provider)
        self.assertEqual(provider.calls, [(key,)])
        self.assertEqual(len(result.result.findings), 1)
        finding = result.result.findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.cve, ("CVE-2099-0001",))
        self.assertEqual(finding.confidence.value, "MEDIUM")
        self.assertIn("reachability is unknown", finding.description)
        self.assertIn("1.26.6", finding.remediation.recommendation)
        self.assertEqual(result.result.status, "completed")

    def test_offline_fresh_stale_and_corrupt_cache(self):
        self.write("requirements.txt", "idna==3.5\n")
        key = ("PyPI", "idna", "3.5")
        provider = FakeProvider({key: (Vulnerability("GHSA-fake"),)})
        online = self.outcome(offline=False, provider=provider)
        self.assertEqual(online.result.status, "completed")
        offline = self.outcome()
        self.assertEqual(offline.result.status, "completed")
        self.assertEqual(len(offline.result.findings), 1)
        stale_limits = replace(VulnerabilityLimits(), cache_ttl_seconds=1)
        path = self.cache._path(key)
        payload = json.loads(path.read_text())
        payload["fetched_at"] = 1
        path.write_text(json.dumps(payload))
        stale = self.outcome(vulnerability=stale_limits)
        self.assertEqual(stale.result.status, "partial")
        self.assertIn("DEPENDENCY_CACHE_STALE", {d.code for d in stale.result.diagnostics})
        path.write_text("{broken")
        corrupt = self.outcome()
        self.assertEqual(corrupt.result.status, "partial")
        self.assertIn("DEPENDENCY_CACHE_CORRUPT", {d.code for d in corrupt.result.diagnostics})

    def test_osv_two_step_normalization_and_withdrawn(self):
        calls = []
        def transport(method, url, body, limits):
            calls.append((method, url))
            if method == "POST":
                return {"results": [{"vulns": [{"id": "GHSA-test"}, {"id": "GHSA-withdrawn"}]}]}
            identifier = url.rsplit("/", 1)[-1]
            return {"id": identifier, "aliases": ["CVE-2099-0001"], "summary": "Synthetic advisory",
                    "affected": [{"package": {"ecosystem": "PyPI", "name": "idna"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.6"}]}]}],
                    "database_specific": {"severity": "HIGH"},
                    "withdrawn": "2025-01-01T00:00:00Z" if identifier == "GHSA-withdrawn" else None,
                    "references": [{"url": "https://osv.dev/vulnerability/GHSA-test"}, {"url": "file:///unsafe"}]}
        provider = OSVProvider(transport)
        result = provider.lookup_batch([("PyPI", "idna", "3.5")], VulnerabilityLimits())
        self.assertEqual(len(calls), 3)
        self.assertEqual(result[0].status, LookupStatus.MATCHED)
        self.assertEqual([v.id for v in result[0].vulnerabilities], ["GHSA-test"])
        self.assertEqual(result[0].vulnerabilities[0].fixed_versions, ("3.6",))
        self.assertEqual(result[0].vulnerabilities[0].references, ("https://osv.dev/vulnerability/GHSA-test",))

    def test_osv_pagination_and_bad_schema_fail_closed(self):
        key = ("npm", "lodash", "4.17.20")
        provider = OSVProvider(lambda *args: {"results": [{"vulns": [], "next_page_token": "opaque"}]})
        with self.assertRaises(ProviderError): provider.lookup_batch([key], VulnerabilityLimits())

    def test_malformed_unsupported_budget_and_no_execution(self):
        self.write("pyproject.toml", "[project\n")
        self.write("pnpm-lock.yaml", "packages: {}\n")
        self.write("setup.py", "raise RuntimeError('TARGET_EXECUTED')\n")
        self.write("requirements.txt", "a==1.0\n")
        result = self.outcome(limits=replace(DependencyLimits(), max_file_bytes=40))
        self.assertEqual(result.result.status, "partial")
        codes = {d.code for d in result.result.diagnostics}
        self.assertIn("DEPENDENCY_PARSE_FAILED", codes)
        self.assertIn("DEPENDENCY_UNSUPPORTED_FORMAT", codes)
        self.assertEqual((self.root / "setup.py").read_text(), "raise RuntimeError('TARGET_EXECUTED')\n")

    def test_provider_failure_partial_and_config(self):
        self.write("requirements.txt", "idna==3.5\n")
        class FailingProvider:
            def lookup_batch(self, keys, limits): raise ProviderError("VULN_PROVIDER_RATE_LIMITED")
        result = self.outcome(offline=False, provider=FailingProvider())
        self.assertEqual(result.result.status, "partial")
        self.assertIn("VULN_PROVIDER_RATE_LIMITED", {d.code for d in result.result.diagnostics})
        config_file = self.base / "operator.toml"
        config_file.write_text('[dependencies]\nmax_entries=50\n[vulnerability]\nmax_queries=20\n')
        config = load_config(config_file)
        self.assertEqual(config.dependencies.max_entries, 50)
        self.assertEqual(config.vulnerability.max_queries, 20)

    def test_package_lock_v1_and_go_indirect(self):
        self.write("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
            "parent": {"version": "1.0.0", "dependencies": {"child": {"version": "2.0.0"}}}}}))
        self.write("go.mod", "module example.com/app\nrequire example.com/direct v1.2.3\nrequire example.com/indirect v2.0.0 // indirect\n")
        inventory = self.outcome().inventory.records
        self.assertEqual(next(r for r in inventory if r.name == "child").directness.value, "transitive")
        self.assertEqual(next(r for r in inventory if r.name == "example.com/indirect").directness.value, "transitive")

    def test_include_loop_and_local_sources_are_not_queried(self):
        self.write("requirements.txt", "-r other.txt\n-e git+https://example.invalid/fake.git#egg=fake\n-e .\n")
        self.write("other.txt", "-r requirements.txt\n")
        self.write("uv.lock", '[[package]]\nname="local"\nversion="1.2.3"\nsource={editable="."}\n')
        result = self.outcome(offline=False, provider=FakeProvider())
        self.assertEqual(result.inventory.exact_keys(), ())
        self.assertIn("DEPENDENCY_INCLUDE_LOOP", {d.code for d in result.result.diagnostics})
        self.assertIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in result.result.diagnostics})
        self.assertEqual({r.version_kind.value for r in result.inventory.records}, {"vcs", "local_path"})

    def test_admitted_manifest_and_exact_root_editable_identity(self):
        self.write("pyproject.toml", '[project]\nname="Demo.Project"\nversion="0.1.0"\n')
        self.write("uv.lock", '[[package]]\nname="demo-project"\nversion="0.1.0"\nsource={editable="."}\n')
        provider = FakeProvider()
        outcome = self.outcome(offline=False, provider=provider)
        self.assertEqual(provider.calls, [])
        self.assertEqual(len(outcome.inventory.records), 1)
        root = outcome.inventory.records[0]
        self.assertEqual(root.identity, DependencyIdentity.FIRST_PARTY_ROOT)
        self.assertEqual(root.source_paths, ("pyproject.toml", "uv.lock"))
        self.assertIsNone(root.key)
        self.assertEqual(dict(outcome.result.summary.details)["first_party_roots"], 1)
        self.assertEqual(dict(outcome.result.summary.details)["unresolved_dependencies"], 0)
        self.assertNotIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in outcome.result.diagnostics})
        self.assertEqual(outcome.result.status, "completed")

    def test_matching_name_without_root_evidence_is_not_first_party(self):
        self.write("pyproject.toml", '[project]\nname="demo"\n')
        self.write("uv.lock", '[[package]]\nname="demo"\nversion="1.2.3"\nsource={registry="https://pypi.org/simple"}\n')
        provider = FakeProvider()
        outcome = self.outcome(offline=False, provider=provider)
        self.assertEqual(outcome.inventory.records[0].identity, DependencyIdentity.REGISTRY)
        self.assertEqual(provider.calls, [(('PyPI', 'demo', '1.2.3'),)])
        self.assertEqual(dict(outcome.result.summary.details)["first_party_roots"], 0)

    def test_root_editable_without_manifest_or_with_conflicting_entry_is_unresolved(self):
        self.write("uv.lock", '[[package]]\nname="demo"\nversion="0.1.0"\nsource={editable="."}\n')
        absent = self.outcome(offline=False, provider=FakeProvider())
        self.assertEqual(absent.inventory.records[0].identity, DependencyIdentity.LOCAL_PATH)
        self.assertIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in absent.result.diagnostics})

        self.write("pyproject.toml", '[project]\nname="demo"\n')
        self.write("uv.lock", '[[package]]\nname="demo"\nversion="0.1.0"\nsource={editable="."}\n'
                              '[[package]]\nname="demo"\nversion="0.1.0"\nsource={path="../outside"}\n')
        conflicting = self.outcome(offline=False, provider=FakeProvider())
        self.assertTrue(all(r.identity is not DependencyIdentity.FIRST_PARTY_ROOT
                            for r in conflicting.inventory.records))
        self.assertIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in conflicting.result.diagnostics})

    def test_editable_outside_root_and_sibling_remain_unresolved(self):
        self.write("pyproject.toml", '[project]\nname="demo"\n')
        for source in ('{editable="../outside"}', '{editable="../../outside"}', '{path="../shared"}'):
            with self.subTest(source=source):
                self.write("uv.lock", '[[package]]\nname="demo"\nversion="0.1.0"\nsource=' + source + '\n')
                outcome = self.outcome(offline=False, provider=FakeProvider())
                self.assertEqual(outcome.inventory.records[0].identity, DependencyIdentity.LOCAL_PATH)
                self.assertEqual(outcome.inventory.exact_keys(), ())
                self.assertIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in outcome.result.diagnostics})
                self.assertEqual(dict(outcome.result.summary.details)["first_party_roots"], 0)
                self.assertEqual(outcome.result.status, "partial")

    def test_root_does_not_hide_offline_registry_no_cache(self):
        self.write("pyproject.toml", '[project]\nname="demo"\n')
        self.write("uv.lock", '[[package]]\nname="demo"\nversion="0.1.0"\nsource={editable="."}\n'
                              '[[package]]\nname="idna"\nversion="3.5"\nsource={registry="https://pypi.org/simple"}\n')
        provider = FakeProvider()
        outcome = self.outcome(provider=provider)
        self.assertEqual(provider.calls, [])
        self.assertEqual(len(outcome.inventory.records), 2)
        self.assertEqual(dict(outcome.result.summary.details)["first_party_roots"], 1)
        self.assertEqual(dict(outcome.result.summary.details)["unresolved_dependencies"], 0)
        self.assertEqual(outcome.lookups[0].status, LookupStatus.OFFLINE_NO_CACHE)
        self.assertNotIn("DEPENDENCY_UNRESOLVED_VERSION", {d.code for d in outcome.result.diagnostics})
        self.assertIn("DEPENDENCY_PROVIDER_NO_DATA", {d.code for d in outcome.result.diagnostics})
        self.assertEqual(outcome.result.status, "partial")

    def test_bad_provider_result_and_response_budget_fail_closed(self):
        self.write("requirements.txt", "idna==3.5\n")
        key = ("PyPI", "idna", "3.5")
        invalid = FakeProvider({key: (Vulnerability("GHSA-evil\x1b[31m"),)})
        result = self.outcome(offline=False, provider=invalid)
        self.assertEqual(result.result.status, "partial")
        self.assertFalse(result.result.findings)
        self.assertIn("VULN_PROVIDER_BAD_RESPONSE", {d.code for d in result.result.diagnostics})
        provider = OSVProvider(lambda *args: {"results": [{"vulns": []}], "padding": "x" * 100})
        with self.assertRaises(ProviderError):
            provider.lookup_batch([key], replace(VulnerabilityLimits(), max_provider_bytes_total=10))

    def test_cache_inside_target_refused_and_config_ceiling(self):
        self.write("requirements.txt", "idna==3.5\n")
        key = ("PyPI", "idna", "3.5")
        self.cache = VulnerabilityCache(self.root / "cache")
        result = self.outcome(offline=False, provider=FakeProvider({key: (Vulnerability("GHSA-fake"),)}))
        self.assertEqual(result.result.status, "partial")
        self.assertFalse((self.root / "cache").exists())
        self.assertIn("DEPENDENCY_CACHE_WRITE_FAILED", {d.code for d in result.result.diagnostics})
        with self.assertRaises(ValueError):
            replace(VulnerabilityLimits(), max_queries=5001)

    def test_scanner_sources_parse_and_no_package_manager_subprocess(self):
        source_dir = Path(__file__).resolve().parents[1] / "src" / "security_auditor" / "scanners" / "dependencies"
        for path in source_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
            self.assertFalse(any((node.module or "").startswith("subprocess") if isinstance(node, ast.ImportFrom)
                                 else any(alias.name.startswith("subprocess") for alias in node.names)
                                 for node in imports), path)

    def test_manifest_secret_shaped_coordinates_do_not_leave_parser(self):
        fake_token = "ghp_" + "A" * 36
        self.write("requirements.txt", fake_token + "==1.0\nnormal==" + fake_token + "\n")
        self.write("package.json", json.dumps({"dependencies": {"safe": "https://user:FAKE_PASSWORD@example.invalid/archive.tgz"}}))
        provider = FakeProvider()
        result = self.outcome(offline=False, provider=provider)
        self.assertEqual(provider.calls, [])
        self.assertFalse(result.result.findings)
        self.assertNotIn(fake_token, repr(result.inventory))
        self.assertNotIn("FAKE_PASSWORD", repr(result.inventory))
        self.assertNotIn("FAKE_PASSWORD", repr(result.result))

    def test_identical_advisory_deduplicates_across_manifest_locations(self):
        self.write("first/requirements.txt", "idna==3.5\n")
        self.write("second/requirements.txt", "idna==3.5\n")
        key = ("PyPI", "idna", "3.5")
        outcome = self.outcome(offline=False, provider=FakeProvider({key: (Vulnerability("GHSA-fake"),)}))
        self.assertEqual(len(outcome.result.findings), 1)
        self.assertEqual(outcome.result.findings[0].dependency.source_paths,
                         ("first/requirements.txt", "second/requirements.txt"))
        self.assertEqual(outcome.result.summary.duplicates_suppressed, 1)

    def test_offline_never_calls_provider_and_no_data_is_not_no_match(self):
        self.write("requirements.txt", "idna==3.5\n")
        provider = FakeProvider()
        offline = self.outcome(provider=provider)
        self.assertEqual(provider.calls, [])
        self.assertEqual(offline.lookups[0].status, LookupStatus.OFFLINE_NO_CACHE)
        self.assertEqual(offline.result.status, "partial")
        online = self.outcome(offline=False, provider=provider)
        self.assertEqual(online.lookups[0].status, LookupStatus.NO_MATCH)
        self.assertEqual(online.result.status, "completed")

    def test_global_batch_budget_leaves_unqueried_as_no_data(self):
        self.write("requirements.txt", "alpha==1.0\nbeta==1.0\ngamma==1.0\n")
        calls = []
        def transport(method, url, body, limits):
            calls.append(method)
            return {"results": [{"vulns": []} for _ in json.loads(body)["queries"]]}
        limits = replace(VulnerabilityLimits(), max_batch_size=1, max_total_batch_requests=1)
        outcome = self.outcome(offline=False, provider=OSVProvider(transport), vulnerability=limits)
        self.assertEqual(calls, ["POST"])
        self.assertEqual([x.status for x in outcome.lookups],
                         [LookupStatus.NO_MATCH, LookupStatus.NO_DATA, LookupStatus.NO_DATA])
        self.assertEqual(outcome.result.status, "partial")
        self.assertIn("DEPENDENCY_OSV_BATCH_BUDGET_REACHED", {d.code for d in outcome.result.diagnostics})
        stats = dict(outcome.result.summary.details)
        self.assertEqual((stats["batch_requests_used"], stats["detail_requests_used"],
                          stats["total_requests_used"]), (1, 0, 1))

    def test_global_detail_and_total_budget_preserve_partial_finding(self):
        self.write("requirements.txt", "idna==3.5\n")
        calls = []
        def transport(method, url, body, limits):
            calls.append(method)
            if method == "POST":
                return {"results": [{"vulns": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}]}
            return {"id": url.rsplit("/", 1)[-1], "affected": [
                {"package": {"ecosystem": "PyPI", "name": "idna"}}]}
        for field, code in (("max_total_detail_requests", "DEPENDENCY_OSV_DETAIL_BUDGET_REACHED"),
                            ("max_total_provider_requests", "DEPENDENCY_OSV_TOTAL_REQUEST_BUDGET_REACHED")):
            with self.subTest(field=field):
                calls.clear()
                limits = replace(VulnerabilityLimits(), **{field: 2 if field.endswith("provider_requests") else 1})
                outcome = self.outcome(offline=False, provider=OSVProvider(transport), vulnerability=limits)
                self.assertEqual(calls, ["POST", "GET"])
                self.assertEqual(outcome.result.status, "partial")
                self.assertIn(code, {d.code for d in outcome.result.diagnostics})
                self.assertEqual([f.vulnerability.advisory_id for f in outcome.result.findings], ["GHSA-a"])
                self.assertTrue(outcome.lookups[0].incomplete)
                self.assertFalse(self.cache._path(("PyPI", "idna", "3.5")).exists())
                stats = dict(outcome.result.summary.details)
                self.assertEqual((stats["batch_requests_used"], stats["detail_requests_used"],
                                  stats["total_requests_used"]), (1, 1, 2))

    def test_advisory_id_reused_across_batches_and_cache_is_network_free(self):
        self.write("requirements.txt", "idna==3.5\nurllib3==1.0\n")
        calls = []
        def transport(method, url, body, limits):
            calls.append(method)
            if method == "POST":
                return {"results": [{"vulns": [{"id": "GHSA-shared"}]}]}
            return {"id": "GHSA-shared", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "idna"}},
                {"package": {"ecosystem": "PyPI", "name": "urllib3"}}]}
        limits = replace(VulnerabilityLimits(), max_batch_size=1)
        online = self.outcome(offline=False, provider=OSVProvider(transport), vulnerability=limits)
        self.assertEqual(calls, ["POST", "GET", "POST"])
        self.assertEqual(len(online.result.findings), 2)
        stats = dict(online.result.summary.details)
        self.assertEqual(stats["deduplicated_advisories"], 1)
        self.assertEqual(stats["total_requests_used"], 3)
        calls.clear()
        offline = self.outcome(provider=OSVProvider(transport), vulnerability=limits)
        self.assertEqual(calls, [])
        self.assertEqual(len(offline.result.findings), 2)
        self.assertEqual(dict(offline.result.summary.details)["total_requests_used"], 0)
        self.assertEqual(dict(offline.result.summary.details)["cache_hits"], 2)

    def test_secret_shaped_filename_is_redacted_in_inventory(self):
        fake_token = "ghp_" + "A" * 36
        self.write(f"requirements-{fake_token}.txt", "idna==3.5\n")
        outcome = self.outcome()
        self.assertEqual(len(outcome.inventory.records), 1)
        self.assertNotIn(fake_token, repr(outcome.inventory))
        self.assertIn("[REDACTED]", outcome.inventory.records[0].source_path)


if __name__ == "__main__":
    unittest.main()
