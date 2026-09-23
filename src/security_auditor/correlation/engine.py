"""Bounded deterministic correlation. Consumes findings; never reads a target."""

from __future__ import annotations

from collections import Counter, defaultdict
from time import monotonic
from typing import Sequence

from security_auditor.core.config import CorrelationLimits
from security_auditor.core.models import Confidence, Finding, ScannerResult
from .graph import _State, _TOKEN, _id, _location, _metadata, _node, _valid
from .models import (Completeness, CorrelationDiagnostic, CorrelationResult, CorrelationSummary, NodeType, RelationshipType, RiskGraph)
from .rules import apply_rules
from .scoring import assess


class CorrelationEngine:
    """Pure result consumer. Input findings must already satisfy the redaction contract."""

    def __init__(self, limits: CorrelationLimits | None = None):
        self.limits = limits or CorrelationLimits()

    def correlate(self, results: Sequence[ScannerResult]) -> CorrelationResult:
        start = monotonic()
        state = _State(self.limits, start + self.limits.max_seconds, {}, {}, Counter())
        coverage = tuple(sorted((result.scanner.id,
                                 result.summary.completeness if result.summary and
                                 result.summary.completeness != "complete" else result.status)
                                for result in results))
        raw_count = sum(len(result.findings) for result in results)
        if not self.limits.enabled:
            return self._finish(state, (), (), (), raw_count, coverage, Completeness.PARTIAL)
        findings: dict[str, Finding] = {}
        for result in results:
            for finding in result.findings:
                if not state.time_ok():
                    break
                if len(findings) >= self.limits.max_findings:
                    state.notes["CORRELATION_FINDING_LIMIT"] += 1
                    state.aborted = True
                    break
                if not _valid(finding):
                    state.notes["CORRELATION_INVALID_FINDING"] += 1
                    continue
                prior = findings.get(finding.fingerprint)
                if prior is not None:
                    if (prior.rule_id, prior.scanner_id, prior.location) != (finding.rule_id, finding.scanner_id, finding.location):
                        state.notes["CORRELATION_FINGERPRINT_COLLISION"] += 1
                    else:
                        state.notes["CORRELATION_DUPLICATE_INPUT"] += 1
                    continue
                findings[finding.fingerprint] = finding
            if state.aborted:
                break
        ordered = tuple(findings[key] for key in sorted(findings))
        locations: dict[tuple[str, int], list[Finding]] = defaultdict(list)
        files: dict[str, list[Finding]] = defaultdict(list)
        functions: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        imports: dict[str, list[Finding]] = defaultdict(list)
        for finding in ordered:
            if not state.time_ok() or state.aborted:
                break
            path, line, _ = _location(finding)  # validated at ingestion
            key = _node(finding)
            if not state.add_node(key, NodeType.FINDING, finding.fingerprint):
                break
            file_key = "file:" + _id(path)
            if not state.add_node(file_key, NodeType.FILE):
                break
            state.add_edge(RelationshipType.SAME_FILE, key, file_key, Confidence.HIGH,
                           "CORRELATION.ENTITY.FILE", "Same normalized file identity.", ("path",))
            locations[(path, line)].append(finding)
            files[path].append(finding)
            func = _metadata(finding, "function_id")
            if func:
                functions[(path, func)].append(finding)
                function_key = "function:" + _id(path, func)
                if not state.add_node(function_key, NodeType.FUNCTION):
                    break
                state.add_edge(RelationshipType.SAME_FUNCTION, key, function_key, Confidence.HIGH,
                               "CORRELATION.ENTITY.FUNCTION",
                               "Same scanner-provided function identity within one file.",
                               ("function_id",))
            name = _metadata(finding, "import_name")
            if name and finding.category == "import_reference":
                imports[name.casefold()].append(finding)
            if finding.dependency:
                dep = finding.dependency
                if _TOKEN.fullmatch(dep.ecosystem) and _TOKEN.fullmatch(dep.name):
                    dep_key = "dependency:" + _id(dep.ecosystem, dep.name.casefold(), dep.version or "")
                    if not state.add_node(dep_key, NodeType.DEPENDENCY):
                        break
                    state.add_edge(RelationshipType.SAME_DEPENDENCY, key, dep_key, Confidence.HIGH,
                                   "CORRELATION.ENTITY.DEPENDENCY", "Exact dependency coordinate.", ("coordinate",))
                    if finding.vulnerability and _TOKEN.fullmatch(finding.vulnerability.advisory_id):
                        vuln_key = "vulnerability:" + _id(finding.vulnerability.advisory_id)
                        if not state.add_node(vuln_key, NodeType.VULNERABILITY):
                            break
                        state.add_edge(RelationshipType.SAME_VULNERABILITY, key, vuln_key, Confidence.HIGH,
                                       "CORRELATION.ENTITY.VULNERABILITY", "Same advisory identifier.", ("advisory_id",))
            source_key = None
            source = _metadata(finding, "source_category")
            source_line = _metadata(finding, "source_line")
            if source and source_line and source_line.isdecimal() and finding.category == "sast":
                source_key = "source:" + _id(path, source, source_line)
                if not state.add_node(source_key, NodeType.SOURCE):
                    break
                state.add_edge(RelationshipType.SAME_SOURCE, source_key, key, finding.confidence,
                               "CORRELATION.ENTITY.SOURCE", "Scanner-provided source category and line.",
                               ("source_category", "source_line"), directed=True)
            sink = _metadata(finding, "sink_kind")
            if sink and finding.category == "sast":
                sink_key = "sink:" + _id(path, str(line), sink)
                if not state.add_node(sink_key, NodeType.SINK):
                    break
                state.add_edge(RelationshipType.SAME_SINK, key, sink_key, finding.confidence,
                               "CORRELATION.ENTITY.SINK", "Scanner-provided sink kind and location.",
                               ("sink_kind",), directed=True)
                if source_key is not None:
                    state.add_edge(RelationshipType.SOURCE_TO_SINK, source_key, sink_key, finding.confidence,
                                   "CORRELATION.SAST.TRACE", "Scanner-reported source-to-sink trace.",
                                   ("source_category", "sink_kind"), directed=True)
        paths: list[AttackPathCandidate] = []
        if not state.aborted:
            apply_rules(state, self.limits, locations, files, functions, imports, paths)
        groups, assessments = assess(state, ordered, coverage)
        status = (Completeness.ABORTED if state.aborted else
                  Completeness.FAILED if any(item[1] == "failed" for item in coverage) else
                  Completeness.PARTIAL if (not coverage or any(item[1] != "completed" for item in coverage)
                                           or state.notes["CORRELATION_INVALID_FINDING"]
                                           or state.notes["CORRELATION_FINGERPRINT_COLLISION"]) else
                  Completeness.COMPLETE)
        return self._finish(state, groups, paths, assessments, raw_count, coverage, status)

    @staticmethod
    def _finish(state, groups, paths, assessments, raw_count, coverage, completeness):
        graph = RiskGraph(tuple(state.nodes[key] for key in sorted(state.nodes)),
                          tuple(state.edges[key] for key in sorted(state.edges)))
        diagnostics = tuple(CorrelationDiagnostic(code, count) for code, count in sorted(state.notes.items()) if count)
        summary = CorrelationSummary(completeness, raw_count,
                                     sum(node.kind is NodeType.FINDING for node in graph.nodes),
                                     len(graph.nodes), len(graph.edges), len(groups), len(paths),
                                     coverage, diagnostics)
        return CorrelationResult(graph, tuple(sorted(groups, key=lambda g: g.id)),
                                 tuple(sorted(paths, key=lambda p: p.id)),
                                 tuple(sorted(assessments, key=lambda a: a.id)), summary)
