"""Phase 4 dependency scanner over Phase 1 admitted files only."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
from time import monotonic
from typing import Sequence

from security_auditor import __version__
from security_auditor.core.config import DependencyLimits, VulnerabilityLimits
from security_auditor.core.models import (
    ArtifactKind, Confidence, ContentKind, DependencyArtifact, Evidence, FileArtifact,
    Finding, Location, Remediation, RuleReference, ScanSession, ScannerDiagnostic,
    ScannerMetadata, ScannerResult, ScannerSummary, VulnerabilityReference,
)
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.models import DiscoveryResult, ScanCompleteness
from security_auditor.scanners._common import safe_finding_path
from .cache import CacheError, VulnerabilityCache
from .models import (DependencyInventory, DependencyRecord, Directness, ECOSYSTEMS,
                     LookupResult, LookupStatus, VersionKind, Vulnerability, reconcile)
from .parsers import parse_npm, parse_python, parse_rust_go
from .parsers.common import ParseError, ParseResult
from .providers import OSVProvider, ProviderError, VulnerabilityProvider, validate_lookup


RULE = RuleReference("DEPENDENCY.KNOWN_VULNERABILITY", "Known vulnerable dependency")
_MESSAGES = {
    "DEPENDENCY_DISCOVERY_INCOMPLETE": "file discovery was incomplete",
    "DEPENDENCY_PARSE_FAILED": "dependency artifact could not be parsed safely",
    "DEPENDENCY_UNSUPPORTED_FORMAT": "dependency format is not supported by this version",
    "DEPENDENCY_UNRESOLVED_VERSION": "dependency version is not exact; no vulnerability match inferred",
    "DEPENDENCY_INCLUDE_OUTSIDE_ROOT": "requirements include was outside the admitted root or not admitted",
    "DEPENDENCY_INCLUDE_LOOP": "requirements include loop or depth limit reached",
    "DEPENDENCY_FILE_TOO_LARGE": "dependency artifact exceeds file byte limit",
    "DEPENDENCY_BYTE_LIMIT_REACHED": "dependency total byte limit reached",
    "DEPENDENCY_ENTRY_LIMIT_REACHED": "dependency entry limit reached",
    "DEPENDENCY_QUERY_LIMIT_REACHED": "vulnerability query budget reached",
    "DEPENDENCY_PROVIDER_NO_DATA": "no vulnerability data available for an exact dependency",
    "DEPENDENCY_PROVIDER_FAILED": "vulnerability provider did not return complete data",
    "DEPENDENCY_CACHE_CORRUPT": "vulnerability cache entry was invalid",
    "DEPENDENCY_CACHE_STALE": "stale vulnerability cache data was used",
    "DEPENDENCY_CACHE_READ_FAILED": "vulnerability cache could not be read",
    "DEPENDENCY_CACHE_WRITE_FAILED": "vulnerability cache could not be written safely",
    "DEPENDENCY_UNSUPPORTED_ECOSYSTEM": "ecosystem has no configured vulnerability provider",
    "DEPENDENCY_READ_FAILED": "admitted dependency artifact could not be safely read",
    "DEPENDENCY_TIMEOUT": "dependency scan elapsed time limit reached",
    "VULN_PROVIDER_TIMEOUT": "vulnerability provider timed out",
    "VULN_PROVIDER_NETWORK_ERROR": "vulnerability provider network request failed",
    "VULN_PROVIDER_BAD_RESPONSE": "vulnerability provider response was invalid or incomplete",
    "VULN_PROVIDER_RESPONSE_TOO_LARGE": "vulnerability provider response exceeded byte limit",
    "VULN_PROVIDER_RATE_LIMITED": "vulnerability provider rate limited the request",
}


@dataclass(frozen=True, slots=True)
class DependencyScanOutcome:
    inventory: DependencyInventory
    result: ScannerResult
    lookups: tuple[LookupResult, ...]


def _parse(artifact: FileArtifact, data: bytes, *, included_text: bool = False) -> ParseResult:
    name = PurePosixPath(artifact.path).name.lower()
    if included_text and artifact.kind not in {ArtifactKind.DEPENDENCY_MANIFEST, ArtifactKind.LOCKFILE}:
        return parse_python("requirements.txt", artifact.path, data)
    if artifact.manifest_kind and artifact.manifest_kind.value == "python":
        return parse_python(name, artifact.path, data)
    if artifact.manifest_kind and artifact.manifest_kind.value == "node":
        return parse_npm(name, artifact.path, data)
    if artifact.manifest_kind and artifact.manifest_kind.value in {"rust", "go"}:
        return parse_rust_go(name, artifact.path, data)
    raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")


def _include_path(parent: str, reference: str) -> str | None:
    value = reference.strip().replace("\\", "/")
    if (not value or len(value) > 300 or value.startswith(("/", "//")) or
            ":" in value or "\x00" in value or any(ord(ch) < 32 for ch in value)):
        return None
    candidate = posixpath.normpath(posixpath.join(posixpath.dirname(parent), value))
    if candidate in {"", ".", ".."} or candidate.startswith("../"):
        return None
    return candidate


def _fingerprint(fields: tuple[str, ...]) -> str:
    raw = b"".join(len(part.encode("utf-8")).to_bytes(4, "big") + part.encode("utf-8") for part in fields)
    return hashlib.sha256(raw).hexdigest()


def _finding(record: DependencyRecord, vulnerability: Vulnerability, stale: bool) -> Finding:
    path = safe_finding_path(record.source_path)
    fingerprint = _fingerprint(("dependency-v1", RULE.id, record.ecosystem, record.name,
                                record.version or "", vulnerability.id))
    aliases = tuple(a for a in vulnerability.aliases if a.startswith("CVE-"))
    fixed = vulnerability.fixed_versions
    recommendation = ("Upgrade the direct dependency to a version outside the affected range."
                      if record.directness is Directness.DIRECT else
                      "Upgrade the parent dependency or regenerate the lockfile with a fixed transitive version.")
    if fixed:
        recommendation += " Provider reports fixed version(s): " + ", ".join(fixed[:5]) + "."
    evidence = (("ecosystem", record.ecosystem), ("package", record.name),
                ("resolved_version", record.version or ""), ("directness", record.directness.value),
                ("vulnerability_id", vulnerability.id), ("provider", "OSV"),
                ("affected_status", "matched_exact_version"), ("cache_stale", str(stale).lower()))
    if fixed:
        evidence += (("fixed_versions", ", ".join(fixed[:5])),)
    dependency = DependencyArtifact(record.ecosystem, record.name, record.version, path,
                                    record.directness is Directness.DIRECT if record.directness is not Directness.UNKNOWN else None,
                                    record.name, record.version_kind.value, record.group.value,
                                    record.package_source, record.declared_constraint,
                                    tuple(safe_finding_path(p) for p in record.source_paths))
    reference = VulnerabilityReference(vulnerability.id, "OSV", aliases[0] if aliases else None,
                                       vulnerability.cvss_vector,
                                       f"https://osv.dev/vulnerability/{vulnerability.id}",
                                       vulnerability.aliases, vulnerability.summary, fixed,
                                       vulnerability.published, vulnerability.modified,
                                       vulnerability.severity_source, False)
    return Finding(
        fingerprint[:16], RULE.id, "dependencies", "dependency",
        f"Known vulnerable dependency: {record.name} {record.version}",
        "The exact dependency version matches an active OSV vulnerability record; application reachability is unknown.",
        vulnerability.severity, Confidence.HIGH if record.resolved else Confidence.MEDIUM,
        Location(path, record.line), Evidence("dependency_match", "[NO SOURCE CONTENT]", evidence),
        "An exact package/version lookup returned this advisory; no application exploitability claim is made.",
        Remediation(recommendation, (reference.reference_uri,) if reference.reference_uri else ()),
        fingerprint, datetime.now(timezone.utc), __version__, cve=aliases,
        cvss=vulnerability.cvss_vector, tags=("supply_chain", "known_vulnerability"),
        rule=RULE, dependency=dependency, vulnerability=reference,
    )


class DependencyScanner:
    def __init__(self, limits: DependencyLimits | None = None,
                 vulnerability: VulnerabilityLimits | None = None,
                 provider: VulnerabilityProvider | None = None,
                 cache: VulnerabilityCache | None = None):
        self.limits = limits or DependencyLimits()
        self.vulnerability = vulnerability or VulnerabilityLimits()
        self.provider = provider or OSVProvider()
        self.cache = cache or VulnerabilityCache()
        self.metadata = ScannerMetadata("dependencies", "0.4.0", "Dependency vulnerability scanner", False)

    def supports(self, artifact: FileArtifact) -> bool:
        return (artifact.kind in {ArtifactKind.DEPENDENCY_MANIFEST, ArtifactKind.LOCKFILE}
                and artifact.content_kind is ContentKind.TEXT and artifact.manifest_kind is not None
                and artifact.filesystem_type == "regular" and not artifact.is_reparse_point)

    def rules(self) -> Sequence[RuleReference]:
        return (RULE,)

    def capabilities(self) -> frozenset[str]:
        return frozenset({"offline_inventory", "optional_online_exact_version_lookup", "local_cache"})

    def scan(self, session: ScanSession, artifacts: Sequence[FileArtifact]) -> ScannerResult:
        return self._run(session, artifacts, session.target.root, ScanCompleteness.COMPLETE).result

    def scan_discovery(self, session: ScanSession, discovery: DiscoveryResult) -> ScannerResult:
        return self.scan_with_inventory(session, discovery).result

    def scan_with_inventory(self, session: ScanSession, discovery: DiscoveryResult) -> DependencyScanOutcome:
        try:
            if (discovery.root is None or discovery.completeness is ScanCompleteness.FAILED or
                    session.target.root.resolve(strict=True) != discovery.root):
                raise ValueError()
        except (OSError, RuntimeError, ValueError):
            result = ScannerResult(self.metadata, status="failed",
                                   diagnostics=(ScannerDiagnostic("DEPENDENCY_DISCOVERY_INCOMPLETE", _MESSAGES["DEPENDENCY_DISCOVERY_INCOMPLETE"]),),
                                   summary=ScannerSummary(completeness="failed"))
            return DependencyScanOutcome(DependencyInventory((), ("DEPENDENCY_DISCOVERY_INCOMPLETE",), False), result, ())
        return self._run(session, discovery.artifacts, discovery.root, discovery.completeness)

    def _run(self, session: ScanSession, artifacts: Sequence[FileArtifact], root: Path,
             discovery_state: ScanCompleteness) -> DependencyScanOutcome:
        if not self.limits.enabled:
            result = ScannerResult(self.metadata, status="skipped", summary=ScannerSummary())
            return DependencyScanOutcome(DependencyInventory(()), result, ())
        deadline = monotonic() + self.limits.max_seconds
        admitted = {a.path: a for a in artifacts if a.content_kind is ContentKind.TEXT
                    and a.encoding is not None and a.filesystem_type == "regular" and not a.is_reparse_point}
        diagnostics: list[ScannerDiagnostic] = []
        seen_codes = set()
        records: list[DependencyRecord] = []
        parsed: set[tuple[str, bool]] = set()
        processing: set[str] = set()
        considered = scanned = skipped = byte_count = entries = limits_hit = parse_failures = 0
        state = "complete"

        def note(code: str) -> None:
            nonlocal state
            if code not in _MESSAGES:
                code = "DEPENDENCY_PARSE_FAILED"
            if code not in seen_codes:
                seen_codes.add(code)
                diagnostics.append(ScannerDiagnostic(code, _MESSAGES[code]))
            if state == "complete": state = "partial"

        if discovery_state is not ScanCompleteness.COMPLETE:
            note("DEPENDENCY_DISCOVERY_INCOMPLETE")
            if discovery_state is ScanCompleteness.ABORTED: state = "aborted"

        def parse_one(path: str, depth: int, constraint_only: bool = False,
                      included_text: bool = False) -> None:
            nonlocal scanned, skipped, byte_count, entries, limits_hit, parse_failures, state
            if path in processing or depth > self.limits.max_include_depth:
                note("DEPENDENCY_INCLUDE_LOOP"); skipped += 1; return
            if (path, constraint_only) in parsed: return
            artifact = admitted.get(path)
            if artifact is None:
                note("DEPENDENCY_INCLUDE_OUTSIDE_ROOT"); skipped += 1; return
            if monotonic() >= deadline:
                note("DEPENDENCY_TIMEOUT"); state = "aborted"; limits_hit += 1; return
            parsed.add((path, constraint_only))
            if artifact.size_bytes > self.limits.max_file_bytes:
                note("DEPENDENCY_FILE_TOO_LARGE"); skipped += 1; limits_hit += 1; return
            if byte_count + artifact.size_bytes > self.limits.max_total_bytes:
                note("DEPENDENCY_BYTE_LIMIT_REACHED"); state = "aborted"; limits_hit += 1; return
            try:
                data = read_admitted_artifact(root, artifact, max_bytes=self.limits.max_file_bytes)
            except ArtifactReadError:
                note("DEPENDENCY_READ_FAILED"); skipped += 1; return
            byte_count += len(data)
            try:
                parsed_file = _parse(artifact, data, included_text=included_text)
            except ParseError as error:
                note(str(error)); parse_failures += 1; skipped += 1; return
            except (ValueError, TypeError, KeyError, RecursionError):
                note("DEPENDENCY_PARSE_FAILED"); parse_failures += 1; skipped += 1; return
            finally:
                del data
            scanned += 1
            for code in parsed_file.diagnostics: note(code)
            entries += len(parsed_file.records)
            if entries > self.limits.max_entries or len(records) + len(parsed_file.records) > self.limits.max_dependencies:
                note("DEPENDENCY_ENTRY_LIMIT_REACHED"); state = "aborted"; limits_hit += 1; return
            if constraint_only:
                records.extend(replace(item, version=None, version_kind=VersionKind.CONSTRAINT,
                                       directness=Directness.UNKNOWN, declared_constraint=("==" + item.version)
                                       if item.version_kind is VersionKind.EXACT and item.version else item.declared_constraint)
                               for item in parsed_file.records)
            else:
                records.extend(parsed_file.records)
            processing.add(path)
            for reference in parsed_file.includes:
                include = _include_path(path, reference.path)
                if include is None:
                    note("DEPENDENCY_INCLUDE_OUTSIDE_ROOT"); skipped += 1; continue
                parse_one(include, depth + 1, constraint_only or reference.constraint_only, True)
                if state == "aborted": break
            processing.remove(path)

        for artifact in sorted(artifacts, key=lambda a: (a.path.casefold(), a.path)):
            if artifact.kind not in {ArtifactKind.DEPENDENCY_MANIFEST, ArtifactKind.LOCKFILE}:
                continue
            considered += 1
            if not self.supports(artifact):
                note("DEPENDENCY_UNSUPPORTED_FORMAT"); skipped += 1; continue
            parse_one(artifact.path, 0)
            if state == "aborted": break
        inventory_records = reconcile(records)
        if any(r.key is None for r in inventory_records):
            note("DEPENDENCY_UNRESOLVED_VERSION")
        inventory = DependencyInventory(inventory_records, tuple(d.code for d in diagnostics), state == "complete")

        lookups: dict[tuple[str, str, str], LookupResult] = {}
        cache_hits = stale_hits = provider_queries = provider_failures = 0
        keys = inventory.exact_keys()
        if len(keys) > self.vulnerability.max_queries:
            note("DEPENDENCY_QUERY_LIMIT_REACHED"); state = "aborted"; limits_hit += 1
            keys = keys[:self.vulnerability.max_queries]
        cache_ok = self.vulnerability.cache_enabled
        if cache_ok:
            try: self.cache.validate_outside(root)
            except CacheError as error:
                note(str(error)); cache_ok = False
        pending = []
        for key in keys:
            if key[0] not in ECOSYSTEMS:
                lookups[key] = LookupResult(key, LookupStatus.UNSUPPORTED_ECOSYSTEM)
                note("DEPENDENCY_UNSUPPORTED_ECOSYSTEM"); continue
            cached = None
            if cache_ok:
                try:
                    cached = self.cache.read(key, self.vulnerability.cache_ttl_seconds)
                    if cached:
                        validate_lookup(cached, self.vulnerability)
                except CacheError as error: note(str(error))
                except ProviderError:
                    note("DEPENDENCY_CACHE_CORRUPT"); cached = None
            if cached and (session.offline or not cached.stale):
                lookups[key] = cached; cache_hits += 1
                if cached.stale:
                    stale_hits += 1; note("DEPENDENCY_CACHE_STALE")
            elif session.offline or not self.vulnerability.enabled:
                lookups[key] = LookupResult(key, LookupStatus.OFFLINE_NO_CACHE if session.offline else LookupStatus.NO_DATA)
                note("DEPENDENCY_PROVIDER_NO_DATA")
            else:
                pending.append(key)
        if not session.offline and self.vulnerability.enabled and state != "aborted":
            provider_deadline = min(deadline, monotonic() + self.vulnerability.max_provider_seconds)
            for start in range(0, len(pending), self.vulnerability.max_batch_size):
                batch = pending[start:start + self.vulnerability.max_batch_size]
                remaining = provider_deadline - monotonic()
                if remaining <= 0:
                    note("VULN_PROVIDER_TIMEOUT"); state = "aborted"; break
                try:
                    batch_limits = replace(self.vulnerability, max_provider_seconds=max(1, int(remaining)))
                    results = self.provider.lookup_batch(batch, batch_limits)
                    if len(results) != len(batch) or tuple(result.key for result in results) != tuple(batch):
                        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
                    for result in results:
                        validate_lookup(result, self.vulnerability)
                except ProviderError as error:
                    note(str(error)); note("DEPENDENCY_PROVIDER_FAILED")
                    provider_failures += len(batch)
                    results = tuple(LookupResult(key, LookupStatus.QUERY_FAILED) for key in batch)
                except (OSError, ValueError, TypeError):
                    note("DEPENDENCY_PROVIDER_FAILED"); provider_failures += len(batch)
                    results = tuple(LookupResult(key, LookupStatus.QUERY_FAILED) for key in batch)
                provider_queries += len(batch)
                for result in results:
                    lookups[result.key] = result
                    if result.status is LookupStatus.QUERY_FAILED: note("DEPENDENCY_PROVIDER_FAILED")
                    elif cache_ok:
                        try: self.cache.write(result)
                        except CacheError as error: note(str(error))
        for key in keys:
            if key not in lookups:
                lookups[key] = LookupResult(key, LookupStatus.NO_DATA)
                note("DEPENDENCY_PROVIDER_NO_DATA")

        findings = []
        matched: dict[tuple[str, str, str, str], tuple[DependencyRecord, Vulnerability, bool, set[str]]] = {}
        raw_matches = 0
        for record in inventory_records:
            if record.key is None: continue
            lookup = lookups.get(record.key)
            if lookup is None or lookup.status is not LookupStatus.MATCHED: continue
            for vulnerability in sorted(lookup.vulnerabilities, key=lambda v: v.id):
                if vulnerability.withdrawn: continue
                raw_matches += 1
                finding_key = (*record.key, vulnerability.id)
                if finding_key not in matched:
                    matched[finding_key] = (record, vulnerability, lookup.stale,
                                            set(record.source_paths or (record.source_path,)))
                else:
                    primary, advisory, stale, paths = matched[finding_key]
                    paths.update(record.source_paths or (record.source_path,))
                    if primary.directness is not Directness.DIRECT and record.directness is Directness.DIRECT:
                        primary = replace(primary, directness=Directness.DIRECT)
                    matched[finding_key] = (primary, advisory, stale or lookup.stale, paths)
        for key in sorted(matched):
            record, advisory, stale, paths = matched[key]
            findings.append(_finding(replace(record, source_paths=tuple(sorted(paths))), advisory, stale))
        metrics = (
            ("dependency_artifacts_considered", considered), ("files_parsed", scanned),
            ("parse_failures", parse_failures), ("dependencies_discovered", len(inventory_records)),
            ("exact_dependencies", sum(r.key is not None for r in inventory_records)),
            ("unresolved_dependencies", sum(r.key is None for r in inventory_records)),
            ("unique_package_versions", len(keys)), ("cache_hits", cache_hits),
            ("stale_cache_hits", stale_hits), ("provider_queries", provider_queries),
            ("provider_failures", provider_failures), ("vulnerability_matches", len(findings)),
        )
        summary = ScannerSummary(considered, scanned, skipped, byte_count, len(keys), len(findings),
                                 0, raw_matches - len(findings), limits_hit, state, metrics)
        result = ScannerResult(self.metadata, tuple(findings), "completed" if state == "complete" else state,
                               tuple(diagnostics), summary)
        return DependencyScanOutcome(inventory, result, tuple(lookups[key] for key in sorted(lookups)))
