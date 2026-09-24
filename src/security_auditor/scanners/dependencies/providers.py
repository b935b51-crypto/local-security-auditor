"""OSV exact-version adapter. Only tool-owned HTTPS endpoints are contacted."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from time import monotonic
from typing import Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from security_auditor.core.config import VulnerabilityLimits
from security_auditor.core.models import Severity
from security_auditor.scanners._common import safe_finding_path
from .models import LookupResult, LookupStatus, Vulnerability, normalize_name, safe_exact_version


OSV_BASE = "https://api.osv.dev/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_CVSS_VECTOR = re.compile(r"^CVSS:[0-9.]+/[A-Za-z0-9:/._-]{1,190}$")


class ProviderError(Exception):
    """Fixed diagnostic code only; never include network payloads."""


class ProviderBudgetReached(ProviderError):
    """A request was refused before network access."""


@dataclass(slots=True)
class ProviderScanState:
    """One operation's actual network requests and bounded advisory reuse."""

    batch_requests: int = 0
    detail_requests: int = 0
    deduplicated_advisories: int = 0
    budget_code: str | None = None
    details: dict[str, dict] = field(default_factory=dict)

    @property
    def total_requests(self) -> int:
        return self.batch_requests + self.detail_requests

    def reserve(self, method: str, limits: VulnerabilityLimits) -> None:
        if method == "POST" and self.batch_requests >= limits.max_total_batch_requests:
            self.budget_code = "DEPENDENCY_OSV_BATCH_BUDGET_REACHED"
        elif method == "GET" and self.detail_requests >= limits.max_total_detail_requests:
            self.budget_code = "DEPENDENCY_OSV_DETAIL_BUDGET_REACHED"
        elif self.total_requests >= limits.max_total_provider_requests:
            self.budget_code = "DEPENDENCY_OSV_TOTAL_REQUEST_BUDGET_REACHED"
        if self.budget_code:
            raise ProviderBudgetReached(self.budget_code)
        if method == "POST":
            self.batch_requests += 1
        else:
            self.detail_requests += 1


class VulnerabilityProvider(Protocol):
    def lookup_batch(self, keys: Sequence[tuple[str, str, str]], limits: VulnerabilityLimits) -> tuple[LookupResult, ...]: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ProviderError("VULN_PROVIDER_NETWORK_ERROR")


def _transport(method: str, url: str, body: bytes | None, limits: VulnerabilityLimits) -> tuple[dict, int]:
    if not url.startswith(OSV_BASE + "/"):
        raise ProviderError("VULN_PROVIDER_NETWORK_ERROR")
    request = Request(url, data=body, method=method,
                      headers={"Content-Type": "application/json", "User-Agent": "LocalSecurityAuditor/0.4"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=limits.timeout_seconds) as response:
            raw = response.read(limits.max_response_bytes + 1)
    except HTTPError as error:
        raise ProviderError("VULN_PROVIDER_RATE_LIMITED" if error.code == 429 else "VULN_PROVIDER_NETWORK_ERROR") from None
    except (URLError, OSError, TimeoutError) as error:
        raise ProviderError("VULN_PROVIDER_TIMEOUT" if isinstance(error, TimeoutError) else "VULN_PROVIDER_NETWORK_ERROR") from None
    if len(raw) > limits.max_response_bytes:
        raise ProviderError("VULN_PROVIDER_RESPONSE_TOO_LARGE")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE") from None
    if not isinstance(value, dict):
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    return value, len(raw)


def _bounded(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        return None
    return value


def _safe_reference(value: object) -> str | None:
    url = _bounded(value, 500)
    if not url: return None
    try: parts = urlsplit(url)
    except ValueError: return None
    if (parts.scheme not in {"http", "https"} or not parts.hostname or
            parts.username is not None or parts.password is not None or parts.query or parts.fragment or
            safe_finding_path(url) != url):
        return None
    return url


def validate_lookup(result: LookupResult, limits: VulnerabilityLimits) -> None:
    """Validate even injected adapters before results reach findings or cache."""
    if (not isinstance(result, LookupResult) or not isinstance(result.status, LookupStatus)
            or type(result.incomplete) is not bool
            or len(result.vulnerabilities) > limits.max_advisories):
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    if result.status not in {LookupStatus.MATCHED, LookupStatus.NO_MATCH}:
        if result.vulnerabilities:
            raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
        return
    if result.status is LookupStatus.NO_MATCH and result.incomplete:
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    if bool(result.vulnerabilities) != (result.status is LookupStatus.MATCHED):
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    for vuln in result.vulnerabilities:
        if (not isinstance(vuln, Vulnerability) or vuln.withdrawn or not _ID.fullmatch(vuln.id)
                or safe_finding_path(vuln.id) != vuln.id
                or not isinstance(vuln.severity, Severity)
                or not isinstance(vuln.summary, str) or len(vuln.summary) > 300
                or safe_finding_path(vuln.summary) != vuln.summary
                or len(vuln.aliases) > 100 or any(not isinstance(x, str) or not _ID.fullmatch(x)
                                                     or safe_finding_path(x) != x for x in vuln.aliases)
                or len(vuln.fixed_versions) > 40 or any(not safe_exact_version(x) for x in vuln.fixed_versions)
                or len(vuln.references) > 20 or any(_safe_reference(x) != x for x in vuln.references)
                or not isinstance(vuln.severity_source, str) or len(vuln.severity_source) > 100
                or (vuln.cvss_vector is not None and
                    (not isinstance(vuln.cvss_vector, str) or not _CVSS_VECTOR.fullmatch(vuln.cvss_vector)))):
            raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")


def normalize_vulnerability_severity(obj: dict) -> tuple[Severity, str, str | None]:
    database = obj.get("database_specific", {})
    label = database.get("severity") if isinstance(database, dict) else None
    vector = None
    values = obj.get("severity", [])
    if isinstance(values, list):
        for entry in values[:8]:
            if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS_"):
                vector = _bounded(entry.get("score"), 200)
                if vector and not _CVSS_VECTOR.fullmatch(vector):
                    vector = None
                if vector: break
    if isinstance(label, str) and label.upper() in Severity.__members__:
        return Severity[label.upper()], "database_specific.severity", vector
    return Severity.MEDIUM, "conservative_default", vector


def _normalize_advisory(obj: dict, key: tuple[str, str, str]) -> Vulnerability:
    advisory_id = _bounded(obj.get("id"), 100)
    if advisory_id is None or not _ID.fullmatch(advisory_id) or safe_finding_path(advisory_id) != advisory_id:
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    affected = obj.get("affected", [])
    if not isinstance(affected, list) or len(affected) > 1000:
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    relevant = []
    for entry in affected:
        if not isinstance(entry, dict): continue
        package = entry.get("package", {})
        if isinstance(package, dict) and package.get("ecosystem") == key[0] and normalize_name(key[0], package.get("name")) == key[1]:
            relevant.append(entry)
    if not relevant:
        raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    aliases = obj.get("aliases", [])
    if not isinstance(aliases, list): raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
    aliases = tuple(sorted({a for a in aliases[:100] if _bounded(a, 100) and _ID.fullmatch(a)
                            and safe_finding_path(a) == a}))
    severity, source, vector = normalize_vulnerability_severity(obj)
    fixed = set()
    for entry in relevant:
        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list): continue
        for range_ in ranges[:100]:
            if not isinstance(range_, dict): continue
            events = range_.get("events", [])
            if not isinstance(events, list): continue
            for event in events[:100]:
                if isinstance(event, dict) and _bounded(event.get("fixed"), 100):
                    fixed.add(event["fixed"])
    refs = obj.get("references", [])
    if not isinstance(refs, list): refs = []
    urls = []
    for entry in refs[:40]:
        if not isinstance(entry, dict): continue
        url = _safe_reference(entry.get("url"))
        if url:
            urls.append(url)
    return Vulnerability(advisory_id, aliases, safe_finding_path(_bounded(obj.get("summary"), 300) or ""),
                         severity, source, vector, tuple(sorted(fixed))[:40], tuple(urls[:20]),
                         _bounded(obj.get("published"), 50), _bounded(obj.get("modified"), 50),
                         isinstance(obj.get("withdrawn"), str) and bool(obj["withdrawn"]))


class OSVProvider:
    def __init__(self, transport=None):
        self._transport = transport or _transport

    def lookup_batch(self, keys: Sequence[tuple[str, str, str]], limits: VulnerabilityLimits,
                     state: ProviderScanState | None = None) -> tuple[LookupResult, ...]:
        if len(keys) > limits.max_batch_size:
            raise ProviderError("DEPENDENCY_QUERY_LIMIT_REACHED")
        state = state if state is not None else ProviderScanState()
        deadline = monotonic() + limits.max_provider_seconds
        total_bytes = 0

        def fetch(method: str, url: str, body: bytes | None) -> dict:
            nonlocal total_bytes
            if monotonic() >= deadline:
                raise ProviderError("VULN_PROVIDER_TIMEOUT")
            state.reserve(method, limits)
            response = self._transport(method, url, body, limits)
            if isinstance(response, tuple) and len(response) == 2:
                value, size = response
            else:
                value = response
                size = len(json.dumps(value, separators=(",", ":")).encode("utf-8"))
            total_bytes += size
            if total_bytes > limits.max_provider_bytes_total:
                raise ProviderError("VULN_PROVIDER_RESPONSE_TOO_LARGE")
            if not isinstance(value, dict):
                raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
            return value

        payload = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in keys]}
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > limits.max_response_bytes:
            raise ProviderError("VULN_PROVIDER_RESPONSE_TOO_LARGE")
        response = fetch("POST", OSV_BASE + "/querybatch", body)
        results = response.get("results")
        if not isinstance(results, list) or len(results) != len(keys):
            raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
        ids_by_key = []
        unique_ids = set()
        for entry in results:
            if not isinstance(entry, dict) or entry.get("next_page_token"):
                raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
            vulns = entry.get("vulns", [])
            if not isinstance(vulns, list) or len(vulns) > limits.max_advisories:
                raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
            ids = []
            for vuln in vulns:
                identifier = vuln.get("id") if isinstance(vuln, dict) else None
                if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                    raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
                ids.append(identifier)
                unique_ids.add(identifier)
            ids_by_key.append(tuple(dict.fromkeys(ids)))
        if len(unique_ids) > limits.max_advisories:
            raise ProviderError("DEPENDENCY_QUERY_LIMIT_REACHED")
        details = {}
        detail_budget_exhausted = False
        for identifier in sorted(unique_ids):
            if identifier in state.details:
                details[identifier] = state.details[identifier]
                state.deduplicated_advisories += 1
                continue
            if detail_budget_exhausted:
                continue
            try:
                detail = fetch("GET", OSV_BASE + "/vulns/" + quote(identifier, safe=""), None)
            except ProviderBudgetReached:
                detail_budget_exhausted = True
                continue
            if detail.get("id") != identifier:
                raise ProviderError("VULN_PROVIDER_BAD_RESPONSE")
            details[identifier] = detail
            state.details[identifier] = detail
        output = []
        for key, ids in zip(keys, ids_by_key):
            missing = any(identifier not in details for identifier in ids)
            vulns = tuple(_normalize_advisory(details[identifier], key) for identifier in ids if identifier in details)
            active = tuple(v for v in vulns if not v.withdrawn)
            status = LookupStatus.MATCHED if active else (LookupStatus.NO_DATA if missing else LookupStatus.NO_MATCH)
            output.append(LookupResult(key, status, active, incomplete=missing))
        return tuple(output)
