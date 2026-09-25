"""Separate neutral behavior scanner over admitted source and script text."""

from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Sequence

from security_auditor.core.config import BehaviorLimits
from security_auditor.core.models import (
    ArtifactKind, ContentKind, FileArtifact, RuleReference, ScanSession,
    ScannerDiagnostic, ScannerMetadata, ScannerResult, ScannerSummary,
)
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.models import DiscoveryResult, ScanCompleteness
from security_auditor.scanners._common import make_finding
from security_auditor.scanners.sast.python.frontend import ASTBudgetError, PythonParseError, parse_python
from .python_rules import scan_python_behavior
from .rules import RULES, RULE_BY_ID
from .text_rules import analyze_text


_LANGUAGES = {"python", "powershell", "batch", "shell", "javascript", "typescript", "jsx", "tsx"}
_ROLES = {ArtifactKind.SOURCE_CODE, ArtifactKind.SCRIPT, ArtifactKind.CONFIG,
          ArtifactKind.CI_CONFIG, ArtifactKind.CONTAINER_CONFIG}
_MESSAGES = {
    "BEHAVIOR_FILE_TOO_LARGE": "file exceeds the behavior scan byte limit",
    "BEHAVIOR_TOTAL_BYTE_BUDGET_REACHED": "behavior scan total byte budget reached",
    "BEHAVIOR_LINE_TOO_LONG": "line exceeds behavior text-rule limit",
    "BEHAVIOR_MATCH_LIMIT_REACHED": "behavior match or finding limit reached",
    "BEHAVIOR_RULE_ERROR": "behavior rule failed without exposing source content",
    "BEHAVIOR_ANALYSIS_TIMEOUT": "behavior elapsed time limit reached",
    "BEHAVIOR_PARSE_FAILED": "Python source could not be parsed for behavior analysis",
    "BEHAVIOR_AST_NODE_LIMIT_REACHED": "Python AST node limit reached",
    "BEHAVIOR_AST_DEPTH_LIMIT_REACHED": "Python AST depth limit reached",
    "BEHAVIOR_UNSUPPORTED_ENCODING": "behavior source decoding unavailable",
    "BEHAVIOR_READ_FAILED": "admitted file could not be safely read",
    "BEHAVIOR_DISCOVERY_INCOMPLETE": "file discovery was incomplete",
}


class BehaviorScanner:
    def __init__(self, limits: BehaviorLimits | None = None):
        self.limits = limits or BehaviorLimits()
        self.metadata = ScannerMetadata("behavior.static", "0.3.0", "Static behavior scanner", True)

    def supports(self, artifact: FileArtifact) -> bool:
        return (artifact.content_kind is ContentKind.TEXT and artifact.encoding is not None
                and artifact.kind in _ROLES and artifact.filesystem_type == "regular"
                and not artifact.is_reparse_point
                and (artifact.language.language in _LANGUAGES or artifact.kind is ArtifactKind.CI_CONFIG))

    def rules(self) -> Sequence[RuleReference]:
        return tuple(rule.reference() for rule in RULES)

    def capabilities(self) -> frozenset[str]:
        return frozenset({"offline", "python_ast_behavior", "bounded_text_behavior"})

    def scan_discovery(self, session: ScanSession, discovery: DiscoveryResult) -> ScannerResult:
        if discovery.root is None or discovery.completeness is ScanCompleteness.FAILED:
            return self._failed()
        try:
            if session.target.root.resolve(strict=True) != discovery.root:
                return self._failed()
        except (OSError, RuntimeError, ValueError):
            return self._failed()
        return self._scan(discovery.artifacts, discovery.root, discovery.completeness)

    def scan(self, session: ScanSession, artifacts: Sequence[FileArtifact]) -> ScannerResult:
        return self._scan(artifacts, session.target.root, ScanCompleteness.COMPLETE)

    def _failed(self) -> ScannerResult:
        return ScannerResult(self.metadata, status="failed",
                             diagnostics=(ScannerDiagnostic("BEHAVIOR_DISCOVERY_INCOMPLETE", _MESSAGES["BEHAVIOR_DISCOVERY_INCOMPLETE"]),),
                             summary=ScannerSummary(completeness="failed"))

    def _scan(self, artifacts: Sequence[FileArtifact], root: Path,
              discovery_state: ScanCompleteness) -> ScannerResult:
        if not self.limits.enabled:
            return ScannerResult(self.metadata, status="skipped",
                                 summary=ScannerSummary(completeness="complete"))
        deadline = monotonic() + self.limits.max_seconds
        findings = []
        diagnostics: list[ScannerDiagnostic] = []
        seen: set[tuple[str, str | None]] = set()
        considered = applicable = not_applicable = scanned = skipped = byte_count = candidate_count = limits_hit = 0
        state = "complete"

        def note(code: str, path: str | None = None) -> None:
            if (code, path) not in seen:
                seen.add((code, path))
                diagnostics.append(ScannerDiagnostic(code, _MESSAGES[code], path))

        if discovery_state is not ScanCompleteness.COMPLETE:
            note("BEHAVIOR_DISCOVERY_INCOMPLETE")
            state = "aborted" if discovery_state is ScanCompleteness.ABORTED else "partial"
        for artifact in sorted(artifacts, key=lambda item: (item.path.casefold(), item.path)):
            considered += 1
            if monotonic() >= deadline:
                note("BEHAVIOR_ANALYSIS_TIMEOUT")
                state = "aborted"
                limits_hit += 1
                break
            if not self.supports(artifact):
                not_applicable += 1
                continue
            applicable += 1
            if artifact.size_bytes > self.limits.max_file_bytes:
                note("BEHAVIOR_FILE_TOO_LARGE")
                skipped += 1
                limits_hit += 1
                state = "partial" if state == "complete" else state
                continue
            if byte_count + artifact.size_bytes > self.limits.max_total_bytes:
                note("BEHAVIOR_TOTAL_BYTE_BUDGET_REACHED")
                limits_hit += 1
                state = "aborted"
                break
            try:
                data = read_admitted_artifact(root, artifact, max_bytes=self.limits.max_file_bytes)
            except ArtifactReadError:
                note("BEHAVIOR_READ_FAILED")
                skipped += 1
                state = "partial" if state == "complete" else state
                continue
            byte_count += len(data)
            try:
                source = data.decode(artifact.encoding or "utf-8", errors="strict")
            except (UnicodeError, LookupError):
                note("BEHAVIOR_UNSUPPORTED_ENCODING")
                skipped += 1
                state = "partial" if state == "complete" else state
                continue
            finally:
                del data
            language = artifact.language.language or "shell"
            if artifact.kind is ArtifactKind.CI_CONFIG and language not in _LANGUAGES:
                language = "shell"
            if language == "python":
                try:
                    parsed = parse_python(source, max_nodes=self.limits.max_ast_nodes,
                                          max_depth=self.limits.max_ast_depth)
                    hits = scan_python_behavior(parsed.tree)
                    long_line = limited = False
                except PythonParseError:
                    note("BEHAVIOR_PARSE_FAILED")
                    skipped += 1
                    state = "partial" if state == "complete" else state
                    continue
                except ASTBudgetError as error:
                    note("BEHAVIOR_" + str(error), artifact.path)
                    skipped += 1
                    limits_hit += 1
                    state = "partial" if state == "complete" else state
                    continue
                except Exception:
                    note("BEHAVIOR_RULE_ERROR")
                    skipped += 1
                    state = "partial" if state == "complete" else state
                    continue
            else:
                try:
                    analysis = analyze_text(source, language=language,
                                            encoding=artifact.encoding or "utf-8",
                                            max_line_bytes=self.limits.max_line_bytes,
                                            max_matches=self.limits.max_matches_per_file)
                except Exception:
                    note("BEHAVIOR_RULE_ERROR")
                    skipped += 1
                    state = "partial" if state == "complete" else state
                    continue
                hits, long_line, limited = analysis.hits, analysis.long_line, analysis.limit_reached
            del source
            scanned += 1
            if long_line:
                note("BEHAVIOR_LINE_TOO_LONG")
                limits_hit += 1
                state = "partial" if state == "complete" else state
            if limited or len(hits) > self.limits.max_matches_per_file:
                note("BEHAVIOR_MATCH_LIMIT_REACHED")
                limits_hit += 1
                state = "partial" if state == "complete" else state
                hits = hits[:self.limits.max_matches_per_file]
            candidate_count += len(hits)
            for hit in hits:
                rule = RULE_BY_ID[hit.rule_id]
                evidence = (("behavior_type", hit.rule_id), ("detection", hit.detail))
                if hit.context:
                    evidence += (("dynamic_input", hit.context),)
                findings.append(make_finding(rule, self.metadata.id, artifact.path,
                                             hit.line, hit.column, anchor=hit.rule_id,
                                             evidence=evidence,
                                             sink=hit.detail, confidence=hit.confidence))
                if len(findings) >= self.limits.max_findings_total:
                    note("BEHAVIOR_MATCH_LIMIT_REACHED")
                    limits_hit += 1
                    state = "aborted"
                    break
            if state == "aborted":
                break
            if monotonic() >= deadline:
                note("BEHAVIOR_ANALYSIS_TIMEOUT")
                state = "aborted"
                limits_hit += 1
                break
        summary = ScannerSummary(considered, scanned, skipped, byte_count, candidate_count,
                                 len(findings), 0, 0, limits_hit, state,
                                 artifacts_applicable=applicable,
                                 artifacts_not_applicable=not_applicable)
        return ScannerResult(self.metadata, tuple(findings),
                             "completed" if state == "complete" else state,
                             tuple(diagnostics), summary)
