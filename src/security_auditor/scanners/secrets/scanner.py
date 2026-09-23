"""Offline secret scanner over Phase 1 admitted file artifacts only."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from time import monotonic
from typing import Sequence

from security_auditor import __version__ as TOOL_VERSION
from security_auditor.core.config import SecretLimits
from security_auditor.core.models import (
    ArtifactKind, Confidence, ContentKind, Evidence, FileArtifact, Finding,
    Location, Remediation, RuleReference, ScanSession, ScannerDiagnostic,
    ScannerMetadata, ScannerResult, ScannerSummary, Severity,
)
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.models import DiscoveryResult, ScanCompleteness
from . import detectors
from .fingerprint import finding_fingerprint
from .models import SecretCandidate
from .rules import RULES, RULE_BY_ID


_RULES = tuple(rule.to_reference() for rule in RULES)
_INELIGIBLE = {ArtifactKind.ARCHIVE, ArtifactKind.BINARY, ArtifactKind.EXECUTABLE}
_DIAGNOSTIC_TEXT = {
    "SECRET_FILE_TOO_LARGE": "admitted text file exceeds the secret scan file limit",
    "SECRET_SCAN_BYTE_BUDGET_REACHED": "secret scan total byte budget reached",
    "SECRET_MATCH_LIMIT_REACHED": "secret scan match or finding limit reached",
    "SECRET_LINE_TOO_LONG": "line exceeds the secret scan line limit",
    "SECRET_DECODE_UNAVAILABLE": "text decoding unavailable",
    "SECRET_READ_FAILED": "admitted file could not be safely read",
    "SECRET_RULE_ERROR": "secret rule failed without exposing source content",
    "SECRET_SCAN_ABORTED": "secret scan elapsed time limit reached",
    "SECRET_DISCOVERY_INCOMPLETE": "file discovery was incomplete",
    "SECRET_PRIVATE_KEY_UNTERMINATED": "private-key begin marker has no matching end marker",
}


def _deduplicate(candidates: list[SecretCandidate]) -> tuple[list[SecretCandidate], int]:
    selected: list[SecretCandidate] = []
    for candidate in sorted(candidates, key=lambda c: (c.priority, c.start, -(c.end - c.start), c.rule_id)):
        if not any(candidate.overlaps(existing) for existing in selected):
            selected.append(candidate)
    selected.sort(key=lambda c: (c.start, c.end, c.rule_id))
    return selected, len(candidates) - len(selected)


class SecretScanner:
    def __init__(self, limits: SecretLimits | None = None):
        self.limits = limits or SecretLimits()
        self.metadata = ScannerMetadata("secrets", "0.2.0", "Native secret scanner", True)

    def supports(self, artifact: FileArtifact) -> bool:
        return (artifact.content_kind is ContentKind.TEXT and artifact.encoding is not None
                and artifact.kind not in _INELIGIBLE and not artifact.is_reparse_point
                and artifact.filesystem_type == "regular")

    def rules(self) -> Sequence[RuleReference]:
        return _RULES

    def capabilities(self) -> frozenset[str]:
        return frozenset({"offline", "secret_detection", "redacted_evidence"})

    def scan_discovery(self, session: ScanSession, discovery: DiscoveryResult) -> ScannerResult:
        """Preferred entry: retains discovery completeness and its canonical root."""
        if discovery.root is None or discovery.completeness is ScanCompleteness.FAILED:
            return ScannerResult(self.metadata, status="failed",
                                 diagnostics=(self._diagnostic("SECRET_DISCOVERY_INCOMPLETE"),),
                                 summary=ScannerSummary(completeness="failed"))
        try:
            if session.target.root.resolve(strict=True) != discovery.root:
                raise ValueError("root mismatch")
        except (OSError, RuntimeError, ValueError):
            return ScannerResult(self.metadata, status="failed",
                                 diagnostics=(self._diagnostic("SECRET_DISCOVERY_INCOMPLETE"),),
                                 summary=ScannerSummary(completeness="failed"))
        return self._scan(session, discovery.artifacts, discovery.root,
                          discovery.completeness)

    def scan(self, session: ScanSession, artifacts: Sequence[FileArtifact]) -> ScannerResult:
        """Scanner Protocol entry; the orchestrator supplies admitted artifacts."""
        return self._scan(session, artifacts, session.target.root, ScanCompleteness.COMPLETE)

    @staticmethod
    def _diagnostic(code: str) -> ScannerDiagnostic:
        return ScannerDiagnostic(code, _DIAGNOSTIC_TEXT[code])

    def _scan(self, session: ScanSession, artifacts: Sequence[FileArtifact], root: Path,
              discovery_state: ScanCompleteness) -> ScannerResult:
        if not self.limits.enabled:
            return ScannerResult(self.metadata, status="skipped",
                                 summary=ScannerSummary(completeness="complete"))
        started = monotonic()
        findings: list[Finding] = []
        diagnostics: list[ScannerDiagnostic] = []
        diagnosed: set[str] = set()

        def note(code: str) -> None:
            if code not in diagnosed:
                diagnosed.add(code)
                diagnostics.append(self._diagnostic(code))

        considered = scanned = skipped = byte_count = match_count = placeholders = duplicates = limits_hit = 0
        state = "complete"
        if discovery_state is not ScanCompleteness.COMPLETE:
            note("SECRET_DISCOVERY_INCOMPLETE")
            state = "aborted" if discovery_state is ScanCompleteness.ABORTED else "partial"
        created_at = datetime.now(timezone.utc)
        for artifact in sorted(artifacts, key=lambda a: (a.path.casefold(), a.path)):
            considered += 1
            if monotonic() - started >= self.limits.max_elapsed_seconds:
                note("SECRET_SCAN_ABORTED")
                state = "aborted"
                limits_hit += 1
                break
            if not self.supports(artifact):
                skipped += 1
                continue
            if artifact.size_bytes > self.limits.max_file_bytes:
                note("SECRET_FILE_TOO_LARGE")
                state = "partial" if state == "complete" else state
                skipped += 1
                limits_hit += 1
                continue
            if byte_count + artifact.size_bytes > self.limits.max_total_bytes:
                note("SECRET_SCAN_BYTE_BUDGET_REACHED")
                state = "aborted"
                limits_hit += 1
                break
            try:
                data = read_admitted_artifact(root, artifact, max_bytes=self.limits.max_file_bytes)
            except ArtifactReadError:
                note("SECRET_READ_FAILED")
                state = "partial" if state == "complete" else state
                skipped += 1
                continue
            byte_count += len(data)
            try:
                source = data.decode(artifact.encoding or "utf-8", errors="strict")
            except (UnicodeError, LookupError):
                note("SECRET_DECODE_UNAVAILABLE")
                state = "partial" if state == "complete" else state
                skipped += 1
                continue
            finally:
                del data
            scanned += 1
            file_candidates: list[tuple[int, SecretCandidate]] = []
            rule_counts: dict[str, int] = {}
            inside_key = False
            file_limited = False
            for line_number, line in enumerate(StringIO(source), 1):
                if monotonic() - started >= self.limits.max_elapsed_seconds:
                    note("SECRET_SCAN_ABORTED")
                    state = "aborted"
                    limits_hit += 1
                    file_limited = True
                    break
                if len(line.encode(artifact.encoding or "utf-8")) > self.limits.max_line_bytes:
                    note("SECRET_LINE_TOO_LONG")
                    state = "partial" if state == "complete" else state
                    limits_hit += 1
                    continue
                if inside_key:
                    if detectors.PRIVATE_END.search(line):
                        inside_key = False
                    continue
                try:
                    private, inside_key = detectors.private_key(line)
                except Exception:
                    note("SECRET_RULE_ERROR")
                    state = "partial" if state == "complete" else state
                    continue
                groups = [private]
                for detector in (detectors.provider, detectors.connection_string,
                                 detectors.jwt,
                                 *((detectors.assignment,) if self.limits.enable_generic_assignment else ()),
                                 *((detectors.entropy_context,) if self.limits.enable_entropy else ())):
                    try:
                        items, suppressed = detector(line)
                        groups.append(items)
                        placeholders += suppressed
                    except Exception:
                        # One rule fails independently. Its exception may embed source.
                        note("SECRET_RULE_ERROR")
                        state = "partial" if state == "complete" else state
                line_candidates = [item for group in groups for item in group]
                match_count += len(line_candidates)
                admitted: list[SecretCandidate] = []
                for candidate in line_candidates:
                    count = rule_counts.get(candidate.rule_id, 0)
                    if count >= self.limits.max_matches_per_rule_per_file:
                        if not file_limited:
                            note("SECRET_MATCH_LIMIT_REACHED")
                            limits_hit += 1
                            file_limited = True
                        state = "partial" if state == "complete" else state
                        continue
                    rule_counts[candidate.rule_id] = count + 1
                    admitted.append(candidate)
                chosen, dropped = _deduplicate(admitted)
                duplicates += dropped
                if len(file_candidates) + len(chosen) > self.limits.max_findings_per_file:
                    allowed = self.limits.max_findings_per_file - len(file_candidates)
                    chosen = chosen[:allowed]
                    note("SECRET_MATCH_LIMIT_REACHED")
                    limits_hit += 1
                    state = "partial" if state == "complete" else state
                    file_candidates.extend((line_number, item) for item in chosen)
                    file_limited = True
                    break
                file_candidates.extend((line_number, item) for item in chosen)
            if inside_key:
                note("SECRET_PRIVATE_KEY_UNTERMINATED")
                state = "partial" if state == "complete" else state
            del source
            aws_id_lines = [number for number, item in file_candidates if item.rule_id == "SECRET.AWS.ACCESS_KEY"]
            aws_secret_lines = [number for number, item in file_candidates
                                if item.rule_id == "SECRET.GENERIC.ASSIGNMENT" and item.label == "aws_secret_access_key"]
            for line_number, candidate in file_candidates:
                if candidate.rule_id == "SECRET.AWS.ACCESS_KEY" and any(abs(line_number - other) <= 5 for other in aws_secret_lines):
                    candidate = replace(candidate, severity=Severity.HIGH, confidence=Confidence.HIGH)
                elif candidate.label == "aws_secret_access_key" and any(abs(line_number - other) <= 5 for other in aws_id_lines):
                    candidate = replace(candidate, severity=Severity.HIGH, confidence=Confidence.HIGH)
                fingerprint = finding_fingerprint(candidate.rule_id, artifact.path, line_number,
                                                  candidate.start + 1, candidate.family, candidate.label)
                finding = Finding(
                    id=fingerprint[:16], rule_id=candidate.rule_id, scanner_id=self.metadata.id,
                    category="secret", title=RULE_BY_ID[candidate.rule_id].title,
                    description=RULE_BY_ID[candidate.rule_id].description,
                    severity=candidate.severity, confidence=candidate.confidence,
                    location=Location(artifact.path, line_number, candidate.start + 1,
                                      line_number, candidate.end + 1),
                    evidence=Evidence("redacted_secret", candidate.preview,
                                      (("family", candidate.family), ("length", str(candidate.value_length)),
                                       ("label", candidate.label))),
                    rationale="Static structure and bounded local context indicate a possible hardcoded credential.",
                    remediation=Remediation("Remove the credential from source; use a secret manager or secure environment. If real, rotate or revoke it and review committed history."),
                    fingerprint=fingerprint, created_at=created_at, tool_version=TOOL_VERSION,
                    cwe=("CWE-798",),
                    attack_scenario="Someone with source access could potentially reuse this credential if it is valid and active.",
                    tags=("secret", candidate.family),
                    rule=RULE_BY_ID[candidate.rule_id].to_reference(),
                )
                findings.append(finding)
                if len(findings) >= self.limits.max_findings_total:
                    note("SECRET_MATCH_LIMIT_REACHED")
                    limits_hit += 1
                    state = "aborted"
                    break
            if state == "aborted":
                break
        summary = ScannerSummary(considered, scanned, skipped, byte_count, match_count,
                                 len(findings), placeholders, duplicates, limits_hit, state)
        status = "completed" if state == "complete" else state
        return ScannerResult(self.metadata, tuple(findings), status, tuple(diagnostics), summary)
