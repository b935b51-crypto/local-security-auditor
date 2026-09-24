"""Offline secret scanner over Phase 1 admitted file artifacts only."""

from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from time import monotonic
from typing import Sequence

from security_auditor import __version__ as TOOL_VERSION
from security_auditor.core.config import SecretLimits
from security_auditor.core.redaction import safe_finding_path
from security_auditor.core.models import (
    ArtifactKind, Confidence, ContentKind, Evidence, FileArtifact, Finding,
    Location, Remediation, RuleReference, ScanSession, ScannerDiagnostic,
    ScannerMetadata, ScannerResult, ScannerSummary, Severity,
)
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.models import DiscoveryResult, ScanCompleteness
from . import detectors
from .fingerprint import finding_fingerprint
from .large_text import LargeTextDeadline, LargeTextResult, scan_large_artifact
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
    "SECRET_FINGERPRINT_COLLISION": "redacted finding anchors collided; distinct safe identities were assigned",
    "SECRET_LARGE_TEXT_INCOMPLETE": "bounded large-text rule context or match budget was incomplete",
}


def _trusted_generated_lines(source: str) -> frozenset[int]:
    """Prove a direct standard-library secrets call without a local shadow.

    Parsing is only attempted for a small Python source containing the exact
    module call syntax. Any uncertainty leaves the normal detector enabled.
    """
    if len(source) > 128 * 1024 or "secrets.token_" not in source:
        return frozenset()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return frozenset()
    nodes: list[ast.AST] = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > 20_000:
            return frozenset()
    imports = [node.lineno for node in tree.body if isinstance(node, ast.Import)
               for alias in node.names if alias.name == "secrets" and alias.asname in {None, "secrets"}]
    if not imports:
        return frozenset()
    for node in nodes:
        if isinstance(node, ast.Name) and node.id == "secrets" and isinstance(node.ctx, (ast.Store, ast.Del)):
            return frozenset()
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name) and node.value.id == "secrets"):
            return frozenset()
        if isinstance(node, ast.arg) and node.arg == "secrets":
            return frozenset()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == "secrets":
            return frozenset()
        if isinstance(node, ast.ExceptHandler) and node.name == "secrets":
            return frozenset()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound == "secrets" and not (isinstance(node, ast.Import) and alias.name == "secrets"):
                    return frozenset()
    allowed = {"token_urlsafe", "token_hex", "token_bytes"}
    lines = set()
    for node in nodes:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        call = node.value
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in allowed and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "secrets" and any(line < node.lineno for line in imports)):
            lines.add(node.lineno)
    return frozenset(lines)


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
        used_fingerprints: set[str] = set()
        diagnostics: list[ScannerDiagnostic] = []
        diagnosed: set[str] = set()

        def note(code: str, artifact: FileArtifact | None = None) -> None:
            if code not in diagnosed:
                diagnosed.add(code)
                diagnostics.append(ScannerDiagnostic(
                    code, _DIAGNOSTIC_TEXT[code],
                    safe_finding_path(artifact.path) if artifact is not None else None,
                ))

        considered = scanned = skipped = byte_count = match_count = placeholders = duplicates = limits_hit = 0
        full_buffer_files = large_text_files = large_text_partial_files = 0
        large_text_bytes = long_lines = incomplete_long_lines = 0
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
                note("SECRET_FILE_TOO_LARGE", artifact)
                state = "partial" if state == "complete" else state
                skipped += 1
                limits_hit += 1
                continue
            if byte_count + artifact.size_bytes > self.limits.max_total_bytes:
                note("SECRET_SCAN_BYTE_BUDGET_REACHED")
                state = "aborted"
                limits_hit += 1
                break
            is_large = artifact.size_bytes > self.limits.full_buffer_threshold_bytes
            large = LargeTextResult([], artifact.path) if is_large else None
            if is_large:
                try:
                    large = scan_large_artifact(root, artifact, self.limits, started, large)
                except LargeTextDeadline:
                    byte_count += large.bytes_scanned
                    note("SECRET_SCAN_ABORTED")
                    state = "aborted"
                    skipped += 1
                    limits_hit += 1
                    break
                except (UnicodeError, LookupError):
                    byte_count += large.bytes_scanned
                    note("SECRET_DECODE_UNAVAILABLE", artifact)
                    state = "partial" if state == "complete" else state
                    skipped += 1
                    continue
                except ArtifactReadError:
                    byte_count += large.bytes_scanned
                    note("SECRET_READ_FAILED", artifact)
                    state = "partial" if state == "complete" else state
                    skipped += 1
                    continue
                except Exception:
                    byte_count += large.bytes_scanned
                    note("SECRET_RULE_ERROR")
                    state = "partial" if state == "complete" else state
                    skipped += 1
                    continue
                byte_count += large.bytes_scanned
                large_text_files += 1
                large_text_bytes += large.bytes_scanned
                long_lines += large.long_lines
                incomplete_long_lines += large.incomplete_lines
                match_count += large.candidate_matches
                placeholders += large.placeholders
                duplicates += large.duplicates
                limits_hit += large.limit_hits
                if large.incomplete:
                    large_text_partial_files += 1
                    note("SECRET_LARGE_TEXT_INCOMPLETE", artifact)
                    state = "partial" if state == "complete" else state
                source = ""
            else:
                try:
                    data = read_admitted_artifact(root, artifact, max_bytes=self.limits.max_file_bytes)
                except ArtifactReadError:
                    note("SECRET_READ_FAILED", artifact)
                    state = "partial" if state == "complete" else state
                    skipped += 1
                    continue
                byte_count += len(data)
                try:
                    source = data.decode(artifact.encoding or "utf-8", errors="strict")
                except (UnicodeError, LookupError):
                    note("SECRET_DECODE_UNAVAILABLE", artifact)
                    state = "partial" if state == "complete" else state
                    skipped += 1
                    continue
                finally:
                    del data
                full_buffer_files += 1
            generated_lines = (_trusted_generated_lines(source)
                               if large is None and artifact.language.language == "python" else frozenset())
            is_test = detectors.test_context_path(artifact.path)
            scanned += 1
            file_candidates: list[tuple[int, SecretCandidate]] = (
                large.candidates if large is not None else [])
            safe_path = large.safe_path if large is not None else artifact.path
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
                    note("SECRET_LINE_TOO_LONG", artifact)
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
                                 *((lambda text: detectors.assignment(
                                     text, trusted_generated=line_number in generated_lines,
                                     test_context=is_test),) if self.limits.enable_generic_assignment else ()),
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
                for candidate in chosen:
                    # A target may put the matched value in its filename too.
                    # Keep the original path only for the bounded reader.
                    matched_value = line[candidate.start:candidate.end]
                    if matched_value and matched_value in safe_path:
                        safe_path = safe_path.replace(matched_value, "[REDACTED]")
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
            if large is not None and large.inside_key:
                if not large.incomplete:
                    large_text_partial_files += 1
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
                fingerprint = finding_fingerprint(candidate.rule_id, safe_path, line_number,
                                                  candidate.start + 1, candidate.family, candidate.label)
                if fingerprint in used_fingerprints:
                    note("SECRET_FINGERPRINT_COLLISION")
                    state = "partial" if state == "complete" else state
                    identity = artifact.identity
                    discriminator = (f"{identity.volume_id}:{identity.file_id}" if identity is not None
                                     and identity.file_id is not None else str(considered))
                    suffix = 0
                    while fingerprint in used_fingerprints:
                        fingerprint = finding_fingerprint(
                            candidate.rule_id, safe_path, line_number, candidate.start + 1,
                            candidate.family, f"{candidate.label}|{discriminator}|{suffix}",
                        )
                        suffix += 1
                used_fingerprints.add(fingerprint)
                finding = Finding(
                    id=fingerprint[:16], rule_id=candidate.rule_id, scanner_id=self.metadata.id,
                    category="secret", title=RULE_BY_ID[candidate.rule_id].title,
                    description=RULE_BY_ID[candidate.rule_id].description,
                    severity=candidate.severity, confidence=candidate.confidence,
                    location=Location(safe_path, line_number, candidate.start + 1,
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
                    if large is not None and not (large.incomplete or large.inside_key):
                        large_text_partial_files += 1
                    note("SECRET_MATCH_LIMIT_REACHED")
                    limits_hit += 1
                    state = "aborted"
                    break
            if state == "aborted":
                break
        summary = ScannerSummary(
            considered, scanned, skipped, byte_count, match_count,
            len(findings), placeholders, duplicates, limits_hit, state,
            details=(("full_buffer_files", full_buffer_files),
                     ("large_text_files_scanned", large_text_files),
                     ("large_text_files_partial", large_text_partial_files),
                     ("large_text_bytes_scanned", large_text_bytes),
                     ("long_lines_segment_scanned", long_lines),
                     ("long_lines_partially_scanned", incomplete_long_lines)),
        )
        status = "completed" if state == "complete" else state
        return ScannerResult(self.metadata, tuple(findings), status, tuple(diagnostics), summary)
