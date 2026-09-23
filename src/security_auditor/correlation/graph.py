"""Validated structural identities and bounded graph construction."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import re
from time import monotonic

from security_auditor.core.config import CorrelationLimits
from security_auditor.core.models import (Confidence, DependencyArtifact, Evidence, Finding, Location, Severity, VulnerabilityReference)
from security_auditor.core.redaction import safe_finding_path
from .models import NodeType, RelationshipType, RiskEdge, RiskNode


_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@+\-]{1,128}$")
_SEVERITIES = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_CONFIDENCES = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)
_COMMAND_BEHAVIOR = {"BEHAVIOR.SHELL_EXEC", "BEHAVIOR.PROCESS_EXEC",
                     "BEHAVIOR.POWERSHELL_EXEC", "BEHAVIOR.CMD_EXEC"}
_NETWORK = "BEHAVIOR.NETWORK_REQUEST"
_PROCESS = "BEHAVIOR.PROCESS_EXEC"
_PERSISTENCE = {"BEHAVIOR.STARTUP_PERSISTENCE", "BEHAVIOR.SCHEDULED_TASK",
                "BEHAVIOR.SERVICE_MODIFICATION"}
_MAX_LOCAL_BUCKET = 32


def _id(*parts: str) -> str:
    raw = b"".join(len(part.encode("utf-8")).to_bytes(4, "big") + part.encode("utf-8") for part in parts)
    return hashlib.sha256(raw).hexdigest()[:24]


def _metadata(finding: Finding, name: str) -> str | None:
    for key, value in finding.evidence.structured:
        if key == name and isinstance(value, str) and _TOKEN.fullmatch(value):
            return value
    return None


def _location(finding: Finding) -> tuple[str, int, int] | None:
    path = finding.location.path
    line = finding.location.start_line
    column = finding.location.start_column
    if not isinstance(path, str):
        return None
    try:
        path.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if (not isinstance(path, str) or not path or len(path) > 512 or
            path.startswith("/") or "\\" in path or ":" in path or
            any(part in {"", ".", ".."} for part in path.split("/")) or
            safe_finding_path(path) != path or any(ord(ch) < 32 for ch in path) or
            type(line) is not int or line < 1 or line > 10_000_000 or
            (column is not None and (type(column) is not int or not 1 <= column <= 1_000_000))):
        return None
    return path, line, column or 0


def _valid(finding: Finding) -> bool:
    if (not isinstance(finding, Finding) or not isinstance(finding.fingerprint, str)
            or not isinstance(finding.location, Location)):
        return False
    if (not isinstance(finding.evidence, Evidence) or
            not isinstance(finding.evidence.structured, tuple) or
            len(finding.evidence.structured) > 64 or any(
                not isinstance(item, tuple) or len(item) != 2 or
                not isinstance(item[0], str) or not isinstance(item[1], str) or
                len(item[0]) > 128 or len(item[1]) > 2048
                for item in finding.evidence.structured)):
        return False
    if finding.dependency is not None and (
            not isinstance(finding.dependency, DependencyArtifact) or
            not isinstance(finding.dependency.ecosystem, str) or
            not isinstance(finding.dependency.name, str) or
            _TOKEN.fullmatch(finding.dependency.ecosystem) is None or
            _TOKEN.fullmatch(finding.dependency.name) is None or
            (finding.dependency.version is not None and
             (not isinstance(finding.dependency.version, str) or
              _TOKEN.fullmatch(finding.dependency.version) is None))):
        return False
    if finding.vulnerability is not None and (
            not isinstance(finding.vulnerability, VulnerabilityReference) or
            not isinstance(finding.vulnerability.advisory_id, str) or
            _TOKEN.fullmatch(finding.vulnerability.advisory_id) is None):
        return False
    return (_HEX.fullmatch(finding.fingerprint) is not None
            and _location(finding) is not None and isinstance(finding.severity, Severity)
            and isinstance(finding.confidence, Confidence)
            and isinstance(finding.rule_id, str) and _TOKEN.fullmatch(finding.rule_id) is not None
            and isinstance(finding.scanner_id, str) and _TOKEN.fullmatch(finding.scanner_id) is not None
            and isinstance(finding.category, str) and _TOKEN.fullmatch(finding.category) is not None)


def _node(finding: Finding) -> str:
    return "f:" + finding.fingerprint


def _minimum(*values: Confidence) -> Confidence:
    return min(values, key=_CONFIDENCES.index)


@dataclass(slots=True)
class _State:
    limits: CorrelationLimits
    deadline: float
    nodes: dict[str, RiskNode]
    edges: dict[str, RiskEdge]
    notes: Counter[str]
    aborted: bool = False

    def time_ok(self) -> bool:
        if monotonic() >= self.deadline:
            self.notes["CORRELATION_TIMEOUT"] += 1
            self.aborted = True
            return False
        return True

    def add_node(self, key: str, kind: NodeType, finding_id: str | None = None) -> bool:
        if key in self.nodes:
            return True
        if len(self.nodes) >= self.limits.max_nodes:
            self.notes["CORRELATION_NODE_LIMIT"] += 1
            self.aborted = True
            return False
        self.nodes[key] = RiskNode(key, kind, finding_id)
        return True

    def add_edge(self, relation: RelationshipType, left: str, right: str,
                 confidence: Confidence, rule: str, rationale: str,
                 evidence: tuple[str, ...], *, directed: bool = False) -> str | None:
        if not directed and left > right:
            left, right = right, left
        key = _id("edge-v1", relation.value, left, right, rule)
        if key in self.edges:
            return key
        if left not in self.nodes or right not in self.nodes:
            return None
        if len(self.edges) >= self.limits.max_edges:
            self.notes["CORRELATION_EDGE_LIMIT"] += 1
            self.aborted = True
            return None
        self.edges[key] = RiskEdge(key, relation, left, right, confidence,
                                   evidence, rationale, rule)
        return key
