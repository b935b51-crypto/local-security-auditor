"""Single-file static zh-TW HTML; all report data stays escaped and redacted."""

from __future__ import annotations

from html import escape

from .i18n import HTML_LOCALE, diagnostic_message, display, message, scanner_label, scope_label
from .models import ScanReport
from .serialization import report_view

MAX_HTML_BYTES = 8 * 1024 * 1024


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _m(key: str) -> str:
    return _e(message(key))


def _v(value: object) -> str:
    return _e(display(value))


def render(report: ScanReport) -> str:
    data = report_view(report)
    coverage = data["coverage"]
    counts = data["summary"]["counts"]
    state = coverage["overall"]
    out = [f'<!doctype html><html lang="{HTML_LOCALE}"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
           'style-src &#39;unsafe-inline&#39;; img-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
           f"<title>{_m('title')}</title>",
           "<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:auto;padding:2rem;"
           "background:#111827;color:#f3f4f6}a{color:#93c5fd}header,.card,section{padding:1rem;"
           "margin:1rem 0;border:1px solid #4b5563;border-radius:.5rem}h1,h2{margin:.3rem 0 1rem}"
           ".coverage{font-size:1.25rem;font-weight:700;padding:1rem;background:#164e63}"
           ".incomplete{background:#78350f;color:white}.counts{display:flex;gap:1rem;flex-wrap:wrap}"
           ".counts span{padding:.6rem;border:1px solid #6b7280;border-radius:.3rem}"
           ".muted{color:#d1d5db}summary{cursor:pointer}code{overflow-wrap:anywhere}</style></head><body>",
           f"<header><h1>{_m('title')}</h1>",
           f"<p>{_m('target')}：<code>{_e(data['scan']['target'])}</code></p>",
           f"<p>{_m('profile')}：{_v(data['scan']['profile'])} · "
           f"{_m('offline')}：{_v(data['scan']['offline'])}</p></header>",
           f'<div class="coverage {"incomplete" if state != "COMPLETE" else ""}">'
           f"{_m('coverage')}：{_v(state)}</div>"]
    if state == "PARTIAL":
        out.append(f"<p><strong>{_m('partial_warning')}</strong></p>")
    elif state == "ABORTED":
        out.append(f"<p><strong>{_m('aborted_warning')}</strong></p>")
    elif state == "FAILED":
        out.append(f"<p><strong>{_m('failed_warning')}</strong></p>")
    else:
        out.append(f"<p>{_m('scope_complete')}</p>")
    if data["report_truncated"]:
        out.append(f"<p><strong>{_m('truncated_warning')}</strong> "
                   f"{_m('total')}：{_e(counts['total_findings'])}；"
                   f"{_m('rendered')}：{_e(counts['rendered_findings'])}</p>")
    out.append(f"<section><h2>{_m('summary')}</h2><div class=\"counts\">")
    for severity, count in counts["severity"].items():
        out.append(f"<span>{_v(severity)}：{_e(count)}</span>")
    out.append("</div>")
    if not counts["total_findings"]:
        out.append(f"<p>{_m('zero_findings')}</p>")
    out.append(f"<h3>{_m('risk_priorities')}</h3><p>" + "、".join(
        f"{_v(key)}：{_e(value)}" for key, value in counts["risk_priority"].items()) + "</p></section>")
    out.append(f"<section><h2>{_m('findings')}</h2>")
    for finding in data["findings"]:
        loc = finding["location"]
        where = (loc["path"] or "unknown") + (f":{loc['start_line']}" if loc["start_line"] else "")
        out.extend(['<article class="card">', f"<h3>{_e(finding['title'])}</h3>",
                    f"<p>{_m('severity')}：<strong>{_v(finding['severity'])}</strong> · "
                    f"{_m('confidence')}：{_v(finding['confidence'])} · "
                    f"{_m('risk_priority')}：{_v(finding['risk_priority'] or 'unassessed')} · "
                    f"{_v(finding['role'])}</p>",
                    f"<p>{_v(finding['category'])} · {_m('location')}：<code>{_e(where)}</code> · "
                    f"{_m('rule')}：<code>{_e(finding['rule_id'])}</code></p>",
                    f"<p>{_e(finding['description'])}</p>",
                    f"<p>{_m('evidence')}：{_e(finding['evidence']['summary'])}</p>",
                    f"<p>CWE/CVE：{_e(', '.join(finding['cwe'] + finding['cve']) or message('none'))}</p>",
                    f"<p>{_m('remediation')}：{_e(finding['remediation']['recommendation'])}</p>"])
        if finding["remediation_proposal_id"]:
            out.append(f"<p>{_m('related_proposal')}：{_e(finding['remediation_proposal_id'])}</p>")
        if finding["ai_review"]:
            out.append(f"<p>{_m('ai')}：{_v(finding['ai_review']['verdict'])} "
                       f"({_v(finding['ai_review']['confidence'])})</p>")
        out.append("</article>")
    out.append(f"</section><section><h2>{_m('groups')}</h2>")
    findings_by_fingerprint = {item["fingerprint"]: item for item in data["findings"]}
    attack_path_members = {fingerprint for path in data["attack_paths"]
                           for fingerprint in path["contributing_findings"]}
    for group in data["finding_groups"]:
        supporting = sum(member["role"] == "supporting" for member in group["members"])
        if not supporting and group["primary"] not in attack_path_members:
            continue
        primary = findings_by_fingerprint.get(group["primary"])
        if primary is None:
            continue
        location = primary["location"]
        where = (location["path"] or "") + (
            f":{location['start_line']}" if location["start_line"] else "")
        out.append(f"<p>{_m('primary')}：{_e(primary['title'])} "
                   f"<code>{_e(where)}</code>；{_e(supporting)} {_m('supporting')}</p>")
    out.append(f"</section><section><h2>{_m('attack_paths')}</h2>")
    for path in data["attack_paths"]:
        out.append(f"<details><summary>{_v(path['title'])} ({_v(path['confidence'])})</summary>"
                   f"<p>{_e(path['rationale'])}</p></details>")
    dependency = data["summary"]["dependency"]
    out.append(f"</section><section><h2>{_m('dependencies')}</h2>"
               f"<p>{_m('packages')}：{_e(dependency['packages'])}；"
               f"{_m('exact_versions')}：{_e(dependency['exact_versions'])}；"
               f"{_m('first_party_roots')}：{_e(dependency['first_party_roots'])}；"
               f"{_m('unresolved_third_party')}：{_e(dependency['unresolved_third_party'])}；"
               f"{_m('no_data')}：{_e(dependency['no_data'])}；"
               f"{_m('matches')}：{_e(dependency['matches'])}</p></section>")
    out.append(f"<section><h2>{_m('ai')}</h2><p>{_m('status')}：{_v(data['summary']['ai_status'])}；"
               f"{_m('reviewed')} {_e(coverage['ai_reviewed'])} / {_e(coverage['ai_eligible'])} "
               f"{_m('eligible')}</p><p>{_m('ai_advisory')}</p>")
    for review in data["ai_reviews"]:
        out.append(f"<details><summary>{_e(review['subject_type'])} "
                   f"<code>{_e(review['subject_id'])}</code>：{_v(review['verdict'])}</summary>"
                   f"<p>{_e(review['summary'])}</p></details>")
    out.append(f"</section><section><h2>{_m('remediation')}</h2>"
               f"<p>{_m('proposal_not_applied')} {_m('runtime_not_run')} "
               f"{_m('human_approval')}</p>")
    for proposal in data["remediation_proposals"]:
        out.append(f"<details><summary>{_e(proposal['title'])}：{_v(proposal['strategy'])} / "
                   f"{_v(proposal['status'])}</summary>")
        out.append(f"<p>{_e(proposal['summary'])}</p><ol>")
        for step in proposal["remediation_steps"]:
            out.append(f"<li>{_e(step)}</li>")
        out.append("</ol>")
        for assumption in proposal["assumptions"]:
            out.append(f"<p>{_m('assumption')}：{_e(assumption)}</p>")
        if proposal["patch_candidate"]:
            patch = proposal["patch_candidate"]
            out.append(f"<p>{_m('file')}：<code>{_e(patch['target_relative_path'])}</code>；"
                       f"{_m('static_validation')}：{_v(proposal['validation']['static_validation_status'])}</p>"
                       f"<pre>{_e(patch['unified_diff'])}</pre>")
        out.append(f"<p>{_m('runtime_tests')}：{_v('NOT_RUN')}。"
                   f"{_m('approval_required')}。</p></details>")
    for code in data["summary"]["remediation"]["diagnostics"]:
        out.append(f"<p><code>{_e(code)}</code></p>")
    out.append(f"</section><section><h2>{_m('coverage_diagnostics')}</h2>")
    out.append(f"<p>{_m('skipped')}：{_e(coverage['skipped_files'])}；"
               f"{_m('limits')}：{_e(coverage['budget_limits_hit'])}</p>")
    for item in coverage["components"]:
        out.append(f"<p>{_e(scanner_label(item['component']))}：{_v(item['status'])} "
                   f"<code>{_e(', '.join(item['reasons']))}</code></p>")
    for diagnostic in data["diagnostics"]:
        path = f"<code>{_e(diagnostic['path'])}</code>：" if diagnostic["path"] else ""
        out.append(f"<p>{path}<code>{_e(diagnostic['code'])}</code> — "
                   f"{_e(diagnostic_message(diagnostic['code'], diagnostic['message']))}</p>")
    scope = data["discovery"]["scope"]
    out.append(f"</section><section><h2>{_m('scope')}</h2><p>{_m('scope_note')}</p>"
               f"<p>{_m('default_exclusions')}：{_v(scope['default_exclusions_applied'])}；"
               f"{_m('excluded_directories')}：{_e(scope['excluded_directories'])}；"
               f"{_m('excluded_files')}：{_e(scope['excluded_files'])}</p><ul>")
    for entry in scope["entries"][:20]:
        out.append(f"<li><code>{_e(entry['path'])}</code> — "
                   f"{_e(scope_label(entry['class']))} "
                   f"<code>{_e(entry['reason'])}</code></li>")
    out.append("</ul>")
    remaining = scope["entries_omitted"] + max(0, len(scope["entries"]) - 20)
    if remaining:
        out.append(f"<p>{_m('scope_more')}：{_e(remaining)}</p>")
    if data["limitations"]:
        out.append(f"</section><section><h2>{_m('limitations')}</h2><ul>")
        for limitation in data["limitations"]:
            out.append(f"<li>{_e(limitation)}</li>")
        out.append("</ul>")
    services = data["summary"]["external_services"]
    out.append(f"</section><section><h2>{_m('privacy')}</h2>"
               f"<p>{_m('osv')}：{_v(services['osv'])}；"
               f"{_m('gemini')}：{_v(services['gemini'])}。</p><p>{_m('privacy_note')}</p>")
    if not services["gemini"]:
        out.append(f"<p>{_m('no_gemini')}</p>")
    out.append("</section></body></html>\n")
    rendered = "".join(out)
    if len(rendered.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("REPORT_SIZE_LIMIT")
    return rendered
