"""Compact, source-free terminal presentation."""

from __future__ import annotations

from .models import ScanReport
from .serialization import report_view


def render(report: ScanReport, *, top: int = 20, verbose: bool = False) -> str:
    view = report_view(report)
    coverage = view["coverage"]
    counts = view["summary"]["counts"]
    lines = ["Local Security Auditor", f"Target: {view['scan']['target']}",
             f"Profile: {view['scan']['profile']}  Offline: {view['scan']['offline']}",
             f"SCAN COVERAGE: {coverage['overall']}"]
    if coverage["overall"] != "COMPLETE":
        lines.append("WARNING: Finding counts do not represent complete scan coverage.")
    if report.report_truncated:
        lines.append("WARNING: Report is truncated; totals exceed rendered items.")
    lines.extend(["", "Summary"])
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"  {severity.title()}: {counts['severity'][severity]}")
    if counts["total_findings"] == 0:
        lines.append("No findings detected in the analyzed coverage.")
    lines.extend(["", "Risk priorities"])
    for name, count in counts["risk_priority"].items():
        lines.append(f"  {name}: {count}")
    lines.extend(["", "Top deterministic findings"])
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = [f for f in view["findings"] if f["role"] not in {"supporting", "duplicate", "contextual"}]
    findings.sort(key=lambda f: (priority_rank.get(f["risk_priority"], 5),
                                 severity_rank.get(f["severity"], 5),
                                 confidence_rank.get(f["confidence"], 5),
                                 f["location"]["path"] or "", f["location"]["start_line"] or 0))
    for f in findings[:top]:
        where = f["location"]["path"] or "?"
        if f["location"]["start_line"]:
            where += f":{f['location']['start_line']}"
        lines.append(f"  [{f['severity']}/{f['confidence']}] {f['title']} — {where}")
        lines.append(f"    Category: {f['category']}  Rule: {f['rule_id']}  Priority: {f['risk_priority'] or 'unassessed'}")
        if f["cwe"] or f["cve"]:
            lines.append(f"    References: {', '.join(f['cwe'] + f['cve'])}")
        if f["ai_review"]:
            lines.append(f"    AI advisory: {f['ai_review']['verdict']} ({f['ai_review']['confidence']})")
        lines.append(f"    Remediation: {f['remediation']['recommendation'][:240]}")
    if len(findings) > top:
        lines.append(f"  ... {len(findings) - top} more rendered findings")
    lines.extend(["", f"Finding groups: {len(view['finding_groups'])}"])
    for group in view["finding_groups"][:10]:
        supporting = sum(m["role"] == "supporting" for m in group["members"])
        lines.append(f"  Primary {group['primary'][:16]}: {supporting} supporting signals")
    lines.extend(["", f"Attack path candidates: {len(view['attack_paths'])}"])
    for path in view["attack_paths"][:10]:
        lines.append(f"  {path['title']} ({path['confidence']})")
    lines.extend(["", f"AI advisory review: {view['summary']['ai_status'].upper()} — "
                  f"{coverage['ai_reviewed']}/{coverage['ai_eligible']} eligible subjects reviewed"])
    for diagnostic in view["diagnostics"]:
        if diagnostic["source"] == "ai":
            lines.append(f"  Reason: {diagnostic['message']}")
    dep = view["summary"]["dependency"]
    lines.append(f"Dependency data: {dep['packages']} packages, {dep['exact_versions']} exact, "
                 f"{dep['no_data']} without advisory data, {dep['matches']} matches")
    if view["scan"]["remediation_requested"]:
        remediation = view["summary"]["remediation"]
        lines.extend(["", "Remediation proposals (never applied)",
                      f"  Guidance: {remediation['proposals']}  Patches: {remediation['patches']}  "
                      f"AI requests: {remediation['ai_requests']}"])
        for proposal in view["remediation_proposals"][:20]:
            lines.append(f"  {proposal['title']}: {proposal['strategy']} / {proposal['status']}")
            lines.append("    Runtime tests: NOT_RUN  Human approval: REQUIRED")
            if verbose and proposal["patch_candidate"]:
                lines.append("    Public diff (display only):")
                lines.append(proposal["patch_candidate"]["unified_diff"][:1200])
        for code in remediation["diagnostics"][:20]:
            lines.append(f"  {code}")
    lines.extend(["", "Coverage warnings"])
    for reason in coverage["reasons"][:30]:
        lines.append(f"  {reason}")
    lines.append(f"  Skipped files: {coverage['skipped_files']}; budget limits hit: {coverage['budget_limits_hit']}")
    scope = view["discovery"]["scope"]
    lines.append(f"  Scope exclusions: {scope['excluded_directories']} directories, "
                 f"{scope['excluded_files']} files (intentional; not coverage failures)")
    lines.extend(["", f"Diagnostics: {len(view['diagnostics'])}"])
    if verbose:
        for diagnostic in view["diagnostics"][:50]:
            lines.append(f"  {diagnostic['source']}:{diagnostic['code']} {diagnostic['path'] or ''}")
    return "\n".join(lines) + "\n"
