"""Python-only AST SAST scanner over Phase 1 admitted artifacts."""

from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Sequence

from security_auditor.core.config import SASTLimits
from security_auditor.core.models import (
    ArtifactKind, ContentKind, FileArtifact, RuleReference, ScanSession,
    ScannerDiagnostic, ScannerMetadata, ScannerResult, ScannerSummary,
)
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.models import DiscoveryResult, ScanCompleteness
from security_auditor.scanners._common import make_finding
from .python.engine import PythonTaintAnalyzer
from .python.frontend import ASTBudgetError, PythonParseError, parse_python
from .python.rules import RULES, RULE_BY_ID


_MESSAGES = {
    "SAST_FILE_TOO_LARGE": "Python file exceeds the SAST file byte limit",
    "SAST_TOTAL_BYTE_BUDGET_REACHED": "SAST total byte budget reached",
    "SAST_PARSE_FAILED": "Python source could not be parsed",
    "SAST_AST_NODE_LIMIT_REACHED": "Python AST node limit reached",
    "SAST_AST_DEPTH_LIMIT_REACHED": "Python AST depth limit reached",
    "SAST_FUNCTION_LIMIT_REACHED": "Python function analysis node limit reached",
    "SAST_FINDING_LIMIT_REACHED": "SAST finding limit reached",
    "SAST_ANALYSIS_TIMEOUT": "SAST elapsed time limit reached",
    "SAST_RULE_ERROR": "SAST rule failed without exposing source content",
    "SAST_UNSUPPORTED_ENCODING": "Python source decoding unavailable",
    "SAST_READ_FAILED": "admitted Python file could not be safely read",
    "SAST_DISCOVERY_INCOMPLETE": "file discovery was incomplete",
}


class SASTScanner:
    def __init__(self, limits: SASTLimits | None = None):
        self.limits = limits or SASTLimits()
        self.metadata = ScannerMetadata("sast.python", "0.3.0", "Python AST SAST", True)

    def supports(self, artifact: FileArtifact) -> bool:
        return (artifact.content_kind is ContentKind.TEXT and artifact.encoding is not None
                and artifact.language.language == "python"
                and artifact.kind in {ArtifactKind.SOURCE_CODE, ArtifactKind.SCRIPT}
                and artifact.filesystem_type == "regular" and not artifact.is_reparse_point)

    def rules(self) -> Sequence[RuleReference]:
        return tuple(rule.reference() for rule in RULES)

    def capabilities(self) -> frozenset[str]:
        return frozenset({"offline", "python_ast", "intraprocedural_taint"})

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
                             diagnostics=(ScannerDiagnostic("SAST_DISCOVERY_INCOMPLETE", _MESSAGES["SAST_DISCOVERY_INCOMPLETE"]),),
                             summary=ScannerSummary(completeness="failed"))

    def _scan(self, artifacts: Sequence[FileArtifact], root: Path,
              discovery_state: ScanCompleteness) -> ScannerResult:
        if not self.limits.enabled:
            return ScannerResult(self.metadata, status="skipped",
                                 summary=ScannerSummary(completeness="complete"))
        started = monotonic()
        deadline = started + self.limits.max_seconds
        findings = []
        diagnostics: list[ScannerDiagnostic] = []
        seen: set[tuple[str, str | None]] = set()
        considered = applicable = not_applicable = scanned = skipped = byte_count = candidates = limits_hit = 0
        state = "complete"

        def note(code: str, path: str | None = None) -> None:
            if (code, path) not in seen:
                seen.add((code, path))
                diagnostics.append(ScannerDiagnostic(code, _MESSAGES[code], path))

        if discovery_state is not ScanCompleteness.COMPLETE:
            note("SAST_DISCOVERY_INCOMPLETE")
            state = "aborted" if discovery_state is ScanCompleteness.ABORTED else "partial"
        for artifact in sorted(artifacts, key=lambda item: (item.path.casefold(), item.path)):
            considered += 1
            if monotonic() >= deadline:
                note("SAST_ANALYSIS_TIMEOUT")
                state = "aborted"
                limits_hit += 1
                break
            if not self.supports(artifact):
                not_applicable += 1
                continue
            applicable += 1
            if artifact.size_bytes > self.limits.max_file_bytes:
                note("SAST_FILE_TOO_LARGE")
                state = "partial" if state == "complete" else state
                skipped += 1
                limits_hit += 1
                continue
            if byte_count + artifact.size_bytes > self.limits.max_total_bytes:
                note("SAST_TOTAL_BYTE_BUDGET_REACHED")
                state = "aborted"
                limits_hit += 1
                break
            try:
                data = read_admitted_artifact(root, artifact, max_bytes=self.limits.max_file_bytes)
            except ArtifactReadError:
                note("SAST_READ_FAILED")
                state = "partial" if state == "complete" else state
                skipped += 1
                continue
            byte_count += len(data)
            try:
                source = data.decode(artifact.encoding or "utf-8", errors="strict")
            except (UnicodeError, LookupError):
                note("SAST_UNSUPPORTED_ENCODING")
                state = "partial" if state == "complete" else state
                skipped += 1
                continue
            finally:
                del data
            try:
                parsed = parse_python(source, max_nodes=self.limits.max_ast_nodes,
                                      max_depth=self.limits.max_ast_depth)
            except PythonParseError:
                note("SAST_PARSE_FAILED")
                state = "partial" if state == "complete" else state
                skipped += 1
                continue
            except ASTBudgetError as error:
                note("SAST_" + str(error), artifact.path)
                state = "partial" if state == "complete" else state
                skipped += 1
                limits_hit += 1
                continue
            finally:
                del source
            scanned += 1
            analysis = PythonTaintAnalyzer(max_function_nodes=self.limits.max_function_nodes,
                                           max_hits=self.limits.max_findings_per_file,
                                           deadline=deadline).analyze(parsed.tree)
            candidates += len(analysis.hits)
            for code in analysis.diagnostics:
                note(code)
                if code in {"SAST_FINDING_LIMIT_REACHED", "SAST_FUNCTION_LIMIT_REACHED", "SAST_ANALYSIS_TIMEOUT"}:
                    limits_hit += 1
                state = "partial" if state == "complete" else state
            for hit in analysis.hits:
                rule = RULE_BY_ID[hit.rule_id]
                taint = hit.taint
                evidence = (("sink_kind", hit.sink),)
                source_label = None
                if taint:
                    source_label = f"{taint.category.value} at line {taint.source_line}"
                    evidence += (("source_category", taint.category.value),
                                 ("source_line", str(taint.source_line)),
                                 ("trace", " > ".join(f"{label}:{line}" for label, line in taint.trace)))
                findings.append(make_finding(rule, self.metadata.id, artifact.path, hit.line,
                                             hit.column, anchor=hit.anchor, evidence=evidence,
                                             source=source_label, sink=hit.sink,
                                             confidence=hit.confidence))
                if len(findings) >= self.limits.max_findings_total:
                    note("SAST_FINDING_LIMIT_REACHED")
                    state = "aborted"
                    limits_hit += 1
                    break
            if state == "aborted" or "SAST_ANALYSIS_TIMEOUT" in analysis.diagnostics:
                state = "aborted" if "SAST_ANALYSIS_TIMEOUT" in analysis.diagnostics else state
                break
        summary = ScannerSummary(considered, scanned, skipped, byte_count, candidates,
                                 len(findings), 0, 0, limits_hit, state,
                                 artifacts_applicable=applicable,
                                 artifacts_not_applicable=not_applicable)
        return ScannerResult(self.metadata, tuple(findings),
                             "completed" if state == "complete" else state,
                             tuple(diagnostics), summary)
