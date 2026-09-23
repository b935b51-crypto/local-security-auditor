"""Single-file static HTML with escaped, sanitized content and no JavaScript."""

from __future__ import annotations

from html import escape

from .models import ScanReport
from .serialization import report_view

MAX_HTML_BYTES = 8 * 1024 * 1024


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def render(report: ScanReport) -> str:
    data = report_view(report)
    coverage = data["coverage"]
    counts = data["summary"]["counts"]
    out = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
           "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
           "style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">",
           "<title>Local Security Auditor report</title>",
           "<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:auto;padding:2rem;"
           "background:#111827;color:#f3f4f6}a{color:#93c5fd}header,.card,section{padding:1rem;"
           "margin:1rem 0;border:1px solid #4b5563;border-radius:.5rem}h1,h2{margin:.3rem 0 1rem}"
           ".coverage{font-size:1.25rem;font-weight:700;padding:1rem;background:#164e63}"
           ".incomplete{background:#78350f;color:white}.counts{display:flex;gap:1rem;flex-wrap:wrap}"
           ".counts span{padding:.6rem;border:1px solid #6b7280;border-radius:.3rem}"
           ".muted{color:#d1d5db}summary{cursor:pointer}code{overflow-wrap:anywhere}</style></head><body>",
           "<header><h1>Local Security Auditor</h1>",
           f"<p>Target: <code>{_e(data['scan']['target'])}</code></p>",
           f"<p>Profile: {_e(data['scan']['profile'])} · Offline: {_e(data['scan']['offline'])}</p></header>",
           f"<div class=\"coverage {'incomplete' if coverage['overall'] != 'COMPLETE' else ''}\">"
           f"Scan coverage: {_e(coverage['overall'])}</div>"]
    if coverage["overall"] != "COMPLETE":
        out.append("<p><strong>Finding counts do not represent complete scan coverage.</strong></p>")
    if data["report_truncated"]:
        out.append("<p><strong>Report truncated: total and rendered counts differ.</strong></p>")
    out.append("<section><h2>Summary</h2><div class=\"counts\">")
    for severity, count in counts["severity"].items():
        out.append(f"<span>{_e(severity.title())}: {_e(count)}</span>")
    out.append("</div>")
    if not counts["total_findings"]:
        out.append("<p>No findings detected in the analyzed coverage.</p>")
    out.append("<h3>Risk priorities</h3><p>" + ", ".join(
        f"{_e(k)}: {_e(v)}" for k, v in counts["risk_priority"].items()) + "</p></section>")
    out.append("<section><h2>Deterministic findings</h2>")
    for f in data["findings"]:
        loc = f["location"]
        where = (loc["path"] or "unknown") + (f":{loc['start_line']}" if loc["start_line"] else "")
        out.extend(["<article class=\"card\">", f"<h3>{_e(f['title'])}</h3>",
                    f"<p><strong>{_e(f['severity'])}</strong> · Confidence {_e(f['confidence'])} · "
                    f"Risk {_e(f['risk_priority'] or 'unassessed')} · {_e(f['role'])}</p>",
                    f"<p>{_e(f['category'])} · <code>{_e(where)}</code> · Rule {_e(f['rule_id'])}</p>",
                    f"<p>{_e(f['description'])}</p>",
                    f"<p>Evidence summary: {_e(f['evidence']['summary'])}</p>",
                    f"<p>CWE/CVE: {_e(', '.join(f['cwe'] + f['cve']) or 'none')}</p>",
                    f"<p>Remediation: {_e(f['remediation']['recommendation'])}</p>"])
        if f["ai_review"]:
            out.append(f"<p>AI advisory: {_e(f['ai_review']['verdict'])} "
                       f"({_e(f['ai_review']['confidence'])})</p>")
        out.append("</article>")
    out.append("</section><section><h2>Finding groups</h2>")
    for group in data["finding_groups"]:
        out.append(f"<p>Primary {_e(group['primary'])}: "
                   f"{_e(sum(m['role'] == 'supporting' for m in group['members']))} supporting signals</p>")
    out.append("</section><section><h2>Attack path candidates</h2>")
    for path in data["attack_paths"]:
        out.append(f"<details><summary>{_e(path['title'])} ({_e(path['confidence'])})</summary>"
                   f"<p>{_e(path['rationale'])}</p></details>")
    dep = data["summary"]["dependency"]
    out.append("</section><section><h2>Dependency vulnerabilities</h2>"
               f"<p>Packages: {_e(dep['packages'])}; exact versions: {_e(dep['exact_versions'])}; "
               f"no advisory data: {_e(dep['no_data'])}; matches: {_e(dep['matches'])}</p></section>")
    out.append(f"<section><h2>AI advisory reviews</h2><p>Status: {_e(data['summary']['ai_status'])}; "
               f"reviewed {_e(coverage['ai_reviewed'])}/{_e(coverage['ai_eligible'])} eligible subjects</p>")
    for review in data["ai_reviews"]:
        out.append(f"<details><summary>{_e(review['subject_type'])} {_e(review['subject_id'])}: "
                   f"{_e(review['verdict'])}</summary><p>{_e(review['summary'])}</p></details>")
    out.append("</section><section><h2>Remediation proposals</h2>"
               "<p>Proposals are not applied. Runtime tests were not run. Human approval is required.</p>")
    for proposal in data["remediation_proposals"]:
        out.append(f"<details><summary>{_e(proposal['title'])}: {_e(proposal['strategy'])} / "
                   f"{_e(proposal['status'])}</summary>")
        out.append(f"<p>{_e(proposal['summary'])}</p><ol>")
        for step in proposal["remediation_steps"]:
            out.append(f"<li>{_e(step)}</li>")
        out.append("</ol>")
        for assumption in proposal["assumptions"]:
            out.append(f"<p>Assumption: {_e(assumption)}</p>")
        if proposal["patch_candidate"]:
            patch = proposal["patch_candidate"]
            out.append(f"<p>File: {_e(patch['target_relative_path'])}; "
                       f"static validation: {_e(proposal['validation']['static_validation_status'])}</p>"
                       f"<pre>{_e(patch['unified_diff'])}</pre>")
        out.append("<p>Runtime tests: NOT_RUN. Human approval: REQUIRED.</p></details>")
    for code in data["summary"]["remediation"]["diagnostics"]:
        out.append(f"<p>{_e(code)}</p>")
    out.append("</section><section><h2>Coverage and diagnostics</h2>")
    out.append(f"<p>Skipped files: {_e(coverage['skipped_files'])}; "
               f"budget limits hit: {_e(coverage['budget_limits_hit'])}</p>")
    for item in coverage["components"]:
        out.append(f"<p>{_e(item['component'])}: {_e(item['status'])} "
                   f"{_e(', '.join(item['reasons']))}</p>")
    for diagnostic in data["diagnostics"]:
        out.append(f"<p>{_e(diagnostic['source'])}/{_e(diagnostic['code'])}: "
                   f"{_e(diagnostic['message'])} {_e(diagnostic['path'])}</p>")
    services = data["summary"]["external_services"]
    out.append("</section><section><h2>Privacy and external services</h2>"
               f"<p>OSV online used: {_e(services['osv'])}; Gemini used: {_e(services['gemini'])}. "
               "AI receives bounded redacted context only when explicitly enabled.</p></section>")
    out.append("</body></html>\n")
    rendered = "".join(out)
    if len(rendered.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("REPORT_SIZE_LIMIT")
    return rendered
