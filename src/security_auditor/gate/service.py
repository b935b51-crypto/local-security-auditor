"""Bounded, fail-closed evaluation of untrusted canonical report JSON."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from security_auditor.reporting.serialization import safe_path

MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 1000
MAX_GROUPS = 1000
MAX_DIAGNOSTICS = 300
MAX_TEXT = 2000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")
_SCANNER_CATEGORY = {"secrets": "secret", "sast.python": "vulnerability",
                     "behavior.static": "behavior", "dependencies": "dependency"}
_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_PRIORITY = {"critical", "high", "medium", "low", "info"}
_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


class GateReportError(ValueError):
    """Only a fixed code is exposed to a CLI or GUI."""

    def __init__(self, code: str = "GATE_INVALID_REPORT") -> None:
        self.code = code
        super().__init__(code)


class GateStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class SecurityGatePolicy:
    policy_version: str = "1.0"
    block_severity: str = "HIGH"
    block_priority: str = "high"
    partial_coverage: GateStatus = GateStatus.BLOCK
    dependency_no_data: GateStatus = GateStatus.WARN
    behavior_only: GateStatus = GateStatus.WARN
    ai_advisory_authoritative: bool = False

    def __post_init__(self) -> None:
        if (self.block_severity not in _SEVERITY or self.block_priority not in _PRIORITY or
                self.partial_coverage not in {GateStatus.BLOCK, GateStatus.WARN} or
                self.dependency_no_data not in {GateStatus.BLOCK, GateStatus.WARN} or
                self.behavior_only not in {GateStatus.PASS, GateStatus.WARN} or
                self.ai_advisory_authoritative):
            raise ValueError("invalid gate policy")


@dataclass(frozen=True, slots=True)
class SecurityGateResult:
    status: GateStatus
    policy_version: str
    blocking_findings: tuple[str, ...]
    warning_findings: tuple[str, ...]
    coverage_status: str
    reasons: tuple[str, ...]
    diagnostics: tuple[str, ...]
    report_schema_version: str


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateReportError()
        result[key] = value
    return result


def _object(value: Any, *keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(key not in value for key in keys):
        raise GateReportError()
    return value


def _array(value: Any, cap: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > cap:
        raise GateReportError()
    return value


def _text(value: Any, *, values: set[str] | None = None, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or len(value) > limit or (values is not None and value not in values):
        raise GateReportError()
    return value


def _count(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise GateReportError()
    return value


def _identifier(value: Any) -> str:
    value = _text(value, limit=128)
    if not _IDENTIFIER.fullmatch(value):
        raise GateReportError()
    return value


def _fingerprint(value: Any) -> str:
    value = _text(value, limit=64)
    if not _FINGERPRINT.fullmatch(value):
        raise GateReportError()
    return value


def _relative_path(value: Any) -> None:
    if value is None:
        return
    value = _text(value, limit=500)
    if value != safe_path(value) or value == "[UNSAFE PATH]":
        raise GateReportError()


def load_report(path: Path) -> dict[str, Any]:
    """Read one regular non-reparse report with a fixed byte cap."""
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > MAX_REPORT_BYTES):
            raise GateReportError("GATE_UNSAFE_REPORT_FILE")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev or
                    opened.st_ino != info.st_ino or opened.st_size > MAX_REPORT_BYTES):
                raise GateReportError("GATE_UNSAFE_REPORT_FILE")
            data = stream.read(MAX_REPORT_BYTES + 1)
            if os.fstat(stream.fileno()).st_size != opened.st_size:
                raise GateReportError("GATE_UNSAFE_REPORT_FILE")
        if len(data) > MAX_REPORT_BYTES:
            raise GateReportError("GATE_REPORT_TOO_LARGE")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(GateReportError()))
    except GateReportError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise GateReportError() from None
    validate_report(value)
    return value


def validate_report(report: Any) -> None:
    """Validate every field used for a gate decision; reject missing/corrupt evidence."""
    root = _object(report, "schema_version", "tool", "scan", "coverage", "summary",
                   "diagnostics", "findings", "finding_groups", "risk_assessments",
                   "ai_reviews", "remediation_proposals", "report_truncated")
    if root["schema_version"] != "1.1":
        raise GateReportError("GATE_UNSUPPORTED_SCHEMA")
    tool = _object(root["tool"], "name", "version")
    if _text(tool["name"]) != "Local Security Auditor":
        raise GateReportError()
    _text(tool["version"], limit=100)
    scan = _object(root["scan"], "scan_id", "target", "profile", "offline")
    _text(scan["scan_id"], limit=128)
    _text(scan["target"], limit=200)
    _text(scan["profile"], values={"quick", "standard", "deep"})
    if type(scan["offline"]) is not bool:
        raise GateReportError()
    coverage = _object(root["coverage"], "overall", "components", "reasons",
                       "skipped_files", "unsupported_files", "budget_limits_hit")
    _text(coverage["overall"], values={"COMPLETE", "PARTIAL", "ABORTED", "FAILED"})
    components = _array(coverage["components"], 32)
    if not components:
        raise GateReportError()
    deterministic_incomplete = False
    for item in components:
        component = _object(item, "component", "status", "reasons")
        _text(component["component"], limit=100)
        state = _text(component["status"], values={"COMPLETE", "PARTIAL", "ABORTED", "FAILED", "DISABLED"})
        if component["component"] != "ai" and state not in {"COMPLETE", "DISABLED"}:
            deterministic_incomplete = True
        for reason in _array(component["reasons"], 100):
            _text(reason, limit=100)
    for reason in _array(coverage["reasons"], 100):
        _text(reason, limit=100)
    if coverage["overall"] == "COMPLETE" and deterministic_incomplete:
        raise GateReportError()
    for key in ("skipped_files", "unsupported_files", "budget_limits_hit"):
        _count(coverage[key])
    if type(root["report_truncated"]) is not bool:
        raise GateReportError()
    summary = _object(root["summary"], "counts", "dependency", "external_services", "ai_status")
    _text(summary["ai_status"], limit=100)
    counts = _object(summary["counts"], "total_findings", "rendered_findings", "severity", "risk_priority")
    total = _count(counts["total_findings"])
    rendered = _count(counts["rendered_findings"])
    for key in ("severity", "risk_priority"):
        values = _object(counts[key])
        if len(values) > 10:
            raise GateReportError()
        for label, count in values.items():
            _text(label, limit=30)
            _count(count)
    services = _object(summary["external_services"])
    if len(services) > 10 or any(type(value) is not bool for value in services.values()):
        raise GateReportError()
    for name in services:
        _text(name, limit=50)
    dependency = _object(summary["dependency"], "no_data", "matches", "exact_versions")
    for key in ("no_data", "matches", "exact_versions"):
        _count(dependency[key])
    findings = _array(root["findings"], MAX_FINDINGS)
    discovery = _object(root.get("discovery"), "admitted_files")
    _count(discovery["admitted_files"])
    for key in ("ai_eligible", "ai_reviewed"):
        _count(coverage.get(key))
    if rendered != len(findings) or total < rendered or (total > rendered and not root["report_truncated"]):
        raise GateReportError()
    ids: set[str] = set()
    fingerprints: set[str] = set()
    for item in findings:
        finding = _object(item, "id", "fingerprint", "rule_id", "scanner_id", "category", "title",
                          "description", "severity", "confidence", "role", "risk_priority", "location",
                          "evidence", "rationale", "cwe", "cve", "ai_review", "remediation_proposal_id",
                          "dependency", "vulnerability")
        identity = _identifier(finding["id"])
        fingerprint = _fingerprint(finding["fingerprint"])
        if identity in ids or fingerprint in fingerprints:
            raise GateReportError()
        ids.add(identity)
        fingerprints.add(fingerprint)
        scanner_id = _text(finding["scanner_id"], limit=100)
        category = _text(finding["category"], limit=100)
        if _SCANNER_CATEGORY.get(scanner_id) != category:
            raise GateReportError()
        for key, cap in (("rule_id", 128), ("title", 500), ("description", 2000), ("rationale", 2000)):
            _text(finding[key], limit=cap)
        _text(finding["severity"], values=_SEVERITY)
        _text(finding["confidence"], values=_CONFIDENCE)
        _text(finding["role"], values={"primary", "supporting", "contextual", "duplicate"})
        if finding["risk_priority"] is not None:
            _text(finding["risk_priority"], values=_PRIORITY)
        location = _object(finding["location"], "path", "start_line")
        _relative_path(location["path"])
        if location["start_line"] is not None:
            _count(location["start_line"])
        evidence = _object(finding["evidence"], "summary")
        _text(evidence["summary"], limit=500)
        for key in ("cwe", "cve"):
            for value in _array(finding[key], 100):
                _text(value, limit=100)
        if finding["ai_review"] is not None:
            review = _object(finding["ai_review"], "verdict", "confidence")
            _text(review["verdict"], limit=100)
            _text(review["confidence"], values=_CONFIDENCE)
        if finding["remediation_proposal_id"] is not None:
            _identifier(finding["remediation_proposal_id"])
        if finding["dependency"] is not None:
            dependency_finding = _object(finding["dependency"], "ecosystem", "name", "version", "direct")
            _text(dependency_finding["ecosystem"], limit=100)
            _text(dependency_finding["name"], limit=200)
            if dependency_finding["version"] is not None:
                _text(dependency_finding["version"], limit=100)
            if dependency_finding["direct"] is not None and type(dependency_finding["direct"]) is not bool:
                raise GateReportError()
        if finding["vulnerability"] is not None:
            vulnerability = _object(finding["vulnerability"], "id", "source", "fixed_versions")
            _text(vulnerability["id"], limit=100)
            _text(vulnerability["source"], limit=100)
            for version in _array(vulnerability["fixed_versions"], 100):
                _text(version, limit=100)
    groups = _array(root["finding_groups"], MAX_GROUPS)
    supporting: set[str] = set()
    for item in groups:
        group = _object(item, "id", "primary", "members")
        _identifier(group["id"])
        primary = _fingerprint(group["primary"])
        if primary not in fingerprints:
            raise GateReportError()
        for member in _array(group["members"], 100):
            member = _object(member, "fingerprint", "role")
            fp = _fingerprint(member["fingerprint"])
            if fp not in fingerprints:
                raise GateReportError()
            role = _text(member["role"], values={"primary", "supporting", "contextual", "duplicate"})
            if role != "primary":
                supporting.add(fp)
    for finding in findings:
        if finding["fingerprint"] in supporting and finding["role"] == "primary":
            raise GateReportError()
    for diagnostic in _array(root["diagnostics"], MAX_DIAGNOSTICS):
        diagnostic = _object(diagnostic, "code", "source", "message", "path")
        code = _text(diagnostic["code"], limit=100)
        if not _CODE.fullmatch(code):
            raise GateReportError()
        _text(diagnostic["source"], limit=100)
        _text(diagnostic["message"], limit=500)
        _relative_path(diagnostic["path"])
    for assessment in _array(root["risk_assessments"], MAX_FINDINGS):
        assessment = _object(assessment, "priority", "subject", "rationale")
        _text(assessment["priority"], values=_PRIORITY)
        _text(assessment["subject"], limit=128)
        _text(assessment["rationale"])
    for path in _array(root.get("attack_paths"), 100):
        path = _object(path, "title", "confidence", "rationale", "contributing_findings", "limitations")
        _text(path["title"], limit=500)
        _text(path["confidence"], values=_CONFIDENCE)
        _text(path["rationale"])
        for key in ("contributing_findings", "limitations"):
            for value in _array(path[key], 100):
                _text(value, limit=500)
    for review in _array(root["ai_reviews"], 100):
        review = _object(review, "subject_id", "verdict", "confidence", "summary", "rationale",
                         "supporting_evidence", "contradictory_evidence", "missing_context",
                         "remediation", "limitations")
        for key in ("subject_id", "verdict", "confidence", "summary"):
            _text(review[key], limit=500)
        for key in ("rationale", "supporting_evidence", "contradictory_evidence",
                    "missing_context", "remediation", "limitations"):
            for value in _array(review[key], 100):
                _text(value, limit=500)
    for proposal in _array(root["remediation_proposals"], 100):
        proposal = _object(proposal, "proposal_id", "title", "strategy", "status", "summary",
                           "remediation_steps", "assumptions", "external_actions_required",
                           "patch_candidate", "validation", "human_approval_required", "runtime_tests_status")
        _identifier(proposal["proposal_id"])
        for key in ("title", "strategy", "status", "summary"):
            _text(proposal[key], limit=500)
        for key in ("remediation_steps", "assumptions", "external_actions_required"):
            for value in _array(proposal[key], 100):
                _text(value, limit=500)
        if proposal["human_approval_required"] is not True or proposal["runtime_tests_status"] != "NOT_RUN":
            raise GateReportError()
        if proposal["patch_candidate"] is not None:
            candidate = _object(proposal["patch_candidate"], "unified_diff")
            _text(candidate["unified_diff"], limit=32768)
        if proposal["validation"] is not None:
            validation = _object(proposal["validation"], "static_validation_status")
            _text(validation["static_validation_status"], limit=100)


def evaluate_gate(report: Mapping[str, Any], policy: SecurityGatePolicy | None = None) -> SecurityGateResult:
    """AI reviews and remediation never alter the deterministic decision."""
    validate_report(report)
    policy = policy or SecurityGatePolicy()
    blockers: list[str] = []
    warnings: list[str] = []
    reasons: set[str] = set()
    coverage = report["coverage"]["overall"]
    if coverage in {"ABORTED", "FAILED"}:
        reasons.add("SCAN_" + coverage)
    elif coverage == "PARTIAL":
        reasons.add("COVERAGE_PARTIAL")
    if report["report_truncated"]:
        reasons.add("REPORT_TRUNCATED")
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for finding in report["findings"]:
        if finding["role"] != "primary":
            continue
        fp = finding["fingerprint"]
        severity = finding["severity"]
        scanner = finding["scanner_id"]
        priority = finding["risk_priority"]
        if scanner.startswith("behavior"):
            if policy.behavior_only == GateStatus.WARN:
                warnings.append(fp)
            continue
        severe = rank[severity] <= rank[policy.block_severity]
        high_priority = priority is not None and priority_rank[priority] <= priority_rank[policy.block_priority]
        # Dependency matches in this report represent exact version matches; do not infer reachability.
        if scanner.startswith("sast") and severity in {"HIGH", "CRITICAL"} and finding["confidence"] != "HIGH":
            severe = False
        if severe or high_priority:
            blockers.append(fp)
        else:
            warnings.append(fp)
    if blockers:
        reasons.add("BLOCKING_PRIMARY_FINDINGS")
    if warnings:
        reasons.add("NON_BLOCKING_PRIMARY_FINDINGS")
    if report["summary"]["dependency"]["no_data"]:
        reasons.add("DEPENDENCY_NO_DATA")
    if report["diagnostics"]:
        reasons.add("SCAN_DIAGNOSTICS")
    blocked = bool(blockers or coverage in {"ABORTED", "FAILED"} or report["report_truncated"] or
                   coverage == "PARTIAL" and policy.partial_coverage == GateStatus.BLOCK or
                   report["summary"]["dependency"]["no_data"] and policy.dependency_no_data == GateStatus.BLOCK)
    warned = bool(warnings or report["diagnostics"] or
                  coverage == "PARTIAL" or report["summary"]["dependency"]["no_data"])
    status = GateStatus.BLOCK if blocked else GateStatus.WARN if warned else GateStatus.PASS
    return SecurityGateResult(status, policy.policy_version, tuple(blockers), tuple(warnings),
                              coverage, tuple(sorted(reasons)),
                              tuple(sorted({d["code"] for d in report["diagnostics"]})), "1.1")


def result_view(result: SecurityGateResult) -> dict[str, Any]:
    return {"status": result.status.value, "policy_version": result.policy_version,
            "blocking_findings": list(result.blocking_findings),
            "warning_findings": list(result.warning_findings),
            "coverage_status": result.coverage_status, "reasons": list(result.reasons),
            "diagnostics": list(result.diagnostics),
            "report_schema_version": result.report_schema_version}
