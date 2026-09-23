"""Bounded, plain-text presentation of the canonical public report."""

from __future__ import annotations

import unicodedata
from typing import Any, Mapping

from security_auditor.ai.redaction import redact_text
from security_auditor.reporting.serialization import safe_diff


def display_text(value: object, *, limit: int = 2000) -> str:
    """Keep Tcl widgets inert and legible even with hostile report strings."""
    text = redact_text(str(value)[:limit])
    return "".join(ch if ch in {"\n", "\t"} or unicodedata.category(ch) not in {"Cc", "Cf"} else " "
                   for ch in text)[:limit]


def coverage_message(report: Mapping[str, Any]) -> str:
    coverage = report["coverage"]["overall"]
    total = report["summary"]["counts"]["total_findings"]
    if coverage == "COMPLETE" and total == 0:
        return "No findings detected in the analyzed coverage. This is not proof of security."
    if coverage == "PARTIAL" and total == 0:
        return "No findings detected in the analyzed portion. Coverage is incomplete."
    return {"COMPLETE": "Deterministic scan completed for the selected coverage.",
            "PARTIAL": "Coverage is incomplete. Review skipped files and diagnostics.",
            "ABORTED": "Scan stopped before completing the selected coverage.",
            "FAILED": "Scan could not complete. No clean result is available."}[coverage]


def visible_findings(report: Mapping[str, Any], *, search: str = "", category: str = "All",
                     severity: str = "All", priority: str = "All", ai_verdict: str = "All",
                     include_supporting: bool = False) -> list[dict[str, Any]]:
    needle = search.casefold().strip()[:100]
    result: list[dict[str, Any]] = []
    for finding in report["findings"]:
        if not include_supporting and finding["role"] != "primary":
            continue
        if category != "All" and finding["category"] != category:
            continue
        if severity != "All" and finding["severity"] != severity:
            continue
        if priority != "All" and (finding["risk_priority"] or "None") != priority:
            continue
        review = finding.get("ai_review") or {}
        if ai_verdict != "All" and review.get("verdict", "None") != ai_verdict:
            continue
        haystack = " ".join(str(finding.get(key, "")) for key in
                            ("title", "category", "rule_id", "scanner_id")) + " " + \
                   str(finding["location"].get("path") or "")
        if needle and needle not in haystack.casefold():
            continue
        result.append(finding)
    return result


def public_patch_text(proposal: Mapping[str, Any]) -> str:
    candidate = proposal.get("patch_candidate")
    if not isinstance(candidate, dict):
        return "No patch available. Guidance only."
    diff = candidate.get("unified_diff", "")
    if not isinstance(diff, str):
        return "[PATCH DIFF OMITTED]"
    return display_text(safe_diff(diff), limit=32768)
