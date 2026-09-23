"""Local, read-only Tk interface over a public ScanReport and shared gate."""

from __future__ import annotations

from pathlib import Path
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any

from security_auditor.core.models import ScanProfile
from security_auditor.gate.service import GateReportError
from security_auditor.reporting import html, json_report, sarif
from security_auditor.reporting.output import ReportOutputError, write_text
from .controller import ApplicationController, ScanOptions
from .view_models import coverage_message, display_text, public_patch_text, visible_findings

_BG = "#eef2f6"
_SURFACE = "#ffffff"
_INK = "#172b3d"
_MUTED = "#52677a"
_NAV = "#152638"
_ACCENT = "#17669a"
_BORDER = "#cbd7e2"
_WARN = "#8c4e00"
_BLOCK = "#a32332"
_PASS = "#116346"
_VIEWS = ("Dashboard", "Findings", "Risks", "Secrets", "SAST", "Behaviors",
          "Dependencies", "AI Reviews", "Remediation", "Gate", "Diagnostics", "Reports", "Settings")


class AuditorApp:
    def __init__(self, root: tk.Tk, controller: ApplicationController | None = None) -> None:
        self.root = root
        self.controller = controller or ApplicationController()
        self.current_view = "Dashboard"
        self.rows: list[dict[str, Any]] = []
        self.root.title("Local Security Auditor")
        self.root.geometry("1180x760")
        self.root.minsize(840, 560)
        self.root.configure(bg=_BG)
        self._style()
        self._shell()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._poll)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background=_BG)
        style.configure("Surface.TFrame", background=_SURFACE)
        style.configure("App.TLabel", background=_BG, foreground=_INK, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=_BG, foreground=_INK, font=("Segoe UI Semibold", 20))
        style.configure("Section.TLabel", background=_SURFACE, foreground=_INK,
                        font=("Segoe UI Semibold", 12))
        style.configure("Body.TLabel", background=_SURFACE, foreground=_INK, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=_SURFACE, foreground=_MUTED, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 7))
        style.configure("Accent.TButton", background=_ACCENT, foreground="white", padding=(14, 8))
        style.map("Accent.TButton", background=[("active", "#104c73")])
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=28,
                        background=_SURFACE, fieldbackground=_SURFACE, foreground=_INK)
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10),
                        background="#e2eaf1", foreground=_INK)
        style.map("Treeview", background=[("selected", "#d5e8f4")],
                  foreground=[("selected", _INK)])

    def _shell(self) -> None:
        header = ttk.Frame(self.root, style="App.TFrame", padding=(20, 16))
        header.pack(fill="x")
        ttk.Label(header, text="Local Security Auditor", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Scan folder", style="Accent.TButton",
                   command=self._scan_dialog).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Open report", command=self._open_report).pack(side="right")
        self.cancel_button = ttk.Button(header, text="Cancel scan", command=self.controller.cancel,
                                        state="disabled")
        self.cancel_button.pack(side="right", padx=(0, 8))

        body = ttk.Frame(self.root, style="App.TFrame")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        nav = tk.Frame(body, bg=_NAV, width=180)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Label(nav, text="Explore", bg=_NAV, fg="#a5c7dd",
                 font=("Segoe UI Semibold", 11), anchor="w", padx=16, pady=18).pack(fill="x")
        self.nav = tk.Listbox(nav, bg=_NAV, fg="#e8f0f5", selectbackground=_ACCENT,
                              selectforeground="white", relief="flat", bd=0,
                              highlightthickness=0, font=("Segoe UI", 11),
                              activestyle="none", exportselection=False)
        self.nav.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        for view in _VIEWS:
            self.nav.insert("end", view)
        self.nav.selection_set(0)
        self.nav.bind("<<ListboxSelect>>", self._navigate)

        content = ttk.Frame(body, style="App.TFrame")
        content.pack(side="left", fill="both", expand=True, padx=(16, 0))
        self.status_var = tk.StringVar(value="Ready. Select a folder or open a JSON report.")
        self.status = ttk.Label(content, textvariable=self.status_var, style="App.TLabel")
        self.status.pack(fill="x", pady=(0, 8))
        self.banner = tk.Label(content, text="No scan loaded", anchor="w", padx=14,
                               pady=10, bg="#dfe9f2", fg=_INK, font=("Segoe UI Semibold", 11))
        self.banner.pack(fill="x", pady=(0, 12))
        self.main = ttk.Frame(content, style="Surface.TFrame", padding=16)
        self.main.pack(fill="both", expand=True)
        self._render()

    def _clear_main(self) -> None:
        for child in self.main.winfo_children():
            child.destroy()

    def _text_panel(self, text: str, *, parent: tk.Widget | None = None) -> tk.Text:
        holder = parent or self.main
        box = tk.Text(holder, wrap="word", bg=_SURFACE, fg=_INK, relief="flat",
                      font=("Segoe UI", 10), padx=8, pady=8, borderwidth=0)
        box.insert("1.0", display_text(text, limit=40000))
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)
        return box

    def _heading(self, title: str, subtitle: str = "") -> None:
        ttk.Label(self.main, text=title, style="Section.TLabel").pack(anchor="w", pady=(0, 4))
        if subtitle:
            ttk.Label(self.main, text=display_text(subtitle), style="Muted.TLabel").pack(
                anchor="w", pady=(0, 12))

    def _navigate(self, _event: object = None) -> None:
        selection = self.nav.curselection()
        if selection:
            self.current_view = _VIEWS[selection[0]]
            self._render()

    def _render(self) -> None:
        self._clear_main()
        report = self.controller.public_report
        if report is None:
            self._heading(self.current_view)
            self._text_panel("Choose Scan folder to analyze a local folder, or Open report to view an existing JSON report.\n\nScanned project code is read as data and never executed. AI and online lookups are off by default.")
            return
        if self.current_view == "Dashboard":
            self._dashboard(report)
        elif self.current_view in {"Findings", "Secrets", "SAST", "Behaviors", "Dependencies"}:
            self._findings(report)
        elif self.current_view == "Risks":
            self._risks(report)
        elif self.current_view == "AI Reviews":
            self._ai(report)
        elif self.current_view == "Remediation":
            self._remediation(report)
        elif self.current_view == "Gate":
            self._gate(report)
        elif self.current_view == "Diagnostics":
            self._diagnostics(report)
        elif self.current_view == "Reports":
            self._reports(report)
        else:
            self._settings(report)

    def _dashboard(self, report: dict[str, Any]) -> None:
        gate = self.controller.gate
        coverage = report["coverage"]
        counts = report["summary"]["counts"]
        self._heading("Scan overview", coverage_message(report))
        severity = counts["severity"]
        priorities = counts["risk_priority"]
        services = report["summary"]["external_services"]
        primary = visible_findings(report)[:8]
        lines = [
            f"Target: {report['scan'].get('target', '')}",
            f"Profile: {report['scan']['profile']}     Coverage: {coverage['overall']}     "
            f"Gate: {gate.status.value if gate else 'unavailable'}     "
            f"Mode: {'OFFLINE MODE' if report['scan']['offline'] else 'ONLINE SERVICES SELECTED'}",
            f"Files admitted: {report.get('discovery', {}).get('admitted_files', 0)}     "
            f"Skipped: {coverage['skipped_files']}     Unsupported: {coverage['unsupported_files']}",
            "Severity: " + "   ".join(f"{key}: {value}" for key, value in severity.items()),
            "Risk priority: " + "   ".join(f"{key}: {value}" for key, value in priorities.items()),
            f"Attack path candidates: {len(report['attack_paths'])}     "
            f"Remediation proposals: {len(report['remediation_proposals'])}",
            f"AI reviews: {len(report['ai_reviews'])} / {coverage.get('ai_eligible', 0)} eligible",
            f"Diagnostics: {len(report['diagnostics'])}",
            "External services: " + ", ".join(f"{name} {'used' if used else 'not used'}"
                                              for name, used in services.items()),
            "", "Top primary findings:",
        ]
        lines.extend(f"• {f['severity']}  {f['title']}  ({f['location']['path']}:{f['location']['start_line']})"
                     for f in primary)
        if not primary:
            lines.append("No primary findings in the analyzed coverage.")
        if coverage["reasons"]:
            lines.extend(("", "Coverage reasons: " + ", ".join(coverage["reasons"])))
        if gate:
            lines.extend(("", "Gate reasons: " + ", ".join(gate.reasons or ("none",))))
        self._text_panel("\n".join(lines))

    def _findings(self, report: dict[str, Any]) -> None:
        subset = self.current_view
        subtitle = "Deterministic results. AI advice is shown separately."
        if subset == "Dependencies":
            summary = report["summary"]["dependency"]
            subtitle = (f"Exact versions: {summary['exact_versions']}  |  Matches: {summary['matches']}  |  "
                        f"NO_DATA / OFFLINE_NO_CACHE / QUERY_FAILED: {summary['no_data']}. "
                        "Missing advisory data never means no vulnerability.")
        self._heading(subset, subtitle)
        filters = ttk.Frame(self.main, style="Surface.TFrame")
        filters.pack(fill="x", pady=(0, 8))
        self.search_var = tk.StringVar()
        entry = ttk.Entry(filters, textvariable=self.search_var, width=25)
        entry.pack(side="left", padx=(0, 8))
        self.search_var.trace_add("write", lambda *_: self._fill_findings(report))
        self.severity_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.severity_var, width=12, state="readonly",
                     values=("All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")).pack(side="left", padx=(0, 8))
        self.severity_var.trace_add("write", lambda *_: self._fill_findings(report))
        self.priority_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.priority_var, width=12, state="readonly",
                     values=("All", "critical", "high", "medium", "low", "info", "None")).pack(side="left", padx=(0, 8))
        self.priority_var.trace_add("write", lambda *_: self._fill_findings(report))
        self.category_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.category_var, width=13, state="readonly",
                     values=("All", *sorted({f["category"] for f in report["findings"]}))).pack(
                         side="left", padx=(0, 8))
        self.category_var.trace_add("write", lambda *_: self._fill_findings(report))
        self.ai_verdict_var = tk.StringVar(value="All")
        ttk.Combobox(filters, textvariable=self.ai_verdict_var, width=18, state="readonly",
                     values=("All", "CONFIRMED", "LIKELY_VALID", "LIKELY_FALSE_POSITIVE",
                             "UNCERTAIN", "None")).pack(side="left", padx=(0, 8))
        self.ai_verdict_var.trace_add("write", lambda *_: self._fill_findings(report))
        self.supporting_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters, text="Include supporting", variable=self.supporting_var,
                        command=lambda: self._fill_findings(report)).pack(side="left")
        frame = ttk.Frame(self.main, style="Surface.TFrame")
        frame.pack(fill="both", expand=True)
        columns = ("severity", "priority", "confidence", "category", "title", "file", "line", "ai")
        self.table = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        widths = (90, 90, 90, 110, 330, 180, 55, 110)
        for col, width in zip(columns, widths):
            self.table.heading(col, text=col.title(), command=lambda c=col: self._sort_table(c))
            self.table.column(col, width=width, minwidth=50, stretch=col in {"title", "file"})
        self.table.pack(fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self._show_finding)
        detail = ttk.Frame(self.main, style="Surface.TFrame")
        detail.pack(fill="both", expand=True, pady=(8, 0))
        self.detail = tk.Text(detail, height=10, wrap="word", bg="#f8fafc", fg=_INK,
                              relief="flat", padx=10, pady=8, font=("Segoe UI", 10))
        self.detail.pack(fill="both", expand=True)
        self._fill_findings(report)

    def _fill_findings(self, report: dict[str, Any]) -> None:
        if not hasattr(self, "table") or not self.table.winfo_exists():
            return
        for item in self.table.get_children():
            self.table.delete(item)
        category = {"Secrets": "secret", "SAST": "vulnerability", "Behaviors": "behavior",
                    "Dependencies": "dependency"}.get(self.current_view, self.category_var.get())
        self.rows = visible_findings(report, search=self.search_var.get(), category=category,
                                     severity=self.severity_var.get(), priority=self.priority_var.get(),
                                     ai_verdict=self.ai_verdict_var.get(),
                                     include_supporting=self.supporting_var.get())
        for index, finding in enumerate(self.rows):
            location = finding["location"]
            review = finding.get("ai_review") or {}
            self.table.insert("", "end", iid=str(index), values=tuple(display_text(value, limit=350)
                for value in (finding["severity"], finding["risk_priority"] or "—",
                              finding["confidence"], finding["category"], finding["title"],
                              location["path"] or "", location["start_line"] or "",
                              review.get("verdict", "—"))))
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", f"{len(self.rows)} matching findings. Select one for details.")
        self.detail.configure(state="disabled")

    def _sort_table(self, column: str) -> None:
        if not hasattr(self, "table"):
            return
        items = list(self.table.get_children(""))
        items.sort(key=lambda item: str(self.table.set(item, column)).casefold())
        for index, item in enumerate(items):
            self.table.move(item, "", index)

    def _show_finding(self, _event: object = None) -> None:
        selected = self.table.selection()
        if not selected:
            return
        finding = self.rows[int(selected[0])]
        report = self.controller.public_report or {}
        group = next((g for g in report.get("finding_groups", [])
                      if finding["fingerprint"] in {m["fingerprint"] for m in g["members"]}), None)
        reviews = [r for r in report.get("ai_reviews", []) if r["subject_id"] == finding["fingerprint"]]
        proposals = [p for p in report.get("remediation_proposals", [])
                     if p["proposal_id"] == finding.get("remediation_proposal_id")]
        lines = [f"DETERMINISTIC FINDING   {finding['severity']} / {finding['confidence']}",
                 finding["title"], f"{finding['location']['path']}:{finding['location']['start_line']}",
                 f"Rule: {finding['rule_id']}     Role: {finding['role']}",
                 f"CWE: {', '.join(finding.get('cwe', [])) or '—'}     CVE: {', '.join(finding.get('cve', [])) or '—'}",
                 "", "Overview", finding.get("description", ""), "", "Rationale", finding.get("rationale", ""),
                 "", "Evidence", finding.get("evidence", {}).get("summary", ""),
                 f"Source: {finding.get('source') or '—'}     Sink: {finding.get('sink') or '—'}"]
        if group:
            lines.extend(("", "Relationships", "Group: " + group["id"],
                          "Members: " + ", ".join(m["role"] + ": " + m["fingerprint"]
                                                  for m in group["members"])))
        dependency = finding.get("dependency")
        if dependency:
            vulnerability = finding.get("vulnerability") or {}
            lines.extend(("", "Dependency and advisory",
                          f"Ecosystem: {dependency.get('ecosystem') or '—'}",
                          f"Package: {dependency.get('name') or '—'}  Version: {dependency.get('version') or '—'}",
                          f"Direct: {dependency.get('direct')}",
                          f"Advisory: {vulnerability.get('id') or '—'}  Provider: {vulnerability.get('source') or '—'}",
                          "Provider reported fixed versions: " +
                          (", ".join(vulnerability.get("fixed_versions") or []) or "not reported")))
        if reviews:
            review = reviews[0]
            lines.extend(("", "AI ADVISORY — never changes the deterministic finding",
                          f"{review['verdict']} / {review['confidence']}", review["summary"],
                          "Limitations: " + "; ".join(review.get("limitations", []))))
        if proposals:
            proposal = proposals[0]
            lines.extend(("", "Remediation proposal — HUMAN APPROVAL REQUIRED",
                          f"{proposal['strategy']} / {proposal['status']}",
                          proposal["summary"], "Runtime tests: NOT RUN"))
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", display_text("\n".join(lines), limit=16000))
        self.detail.configure(state="disabled")

    def _risks(self, report: dict[str, Any]) -> None:
        self._heading("Risk relationships", "Groups and attack paths are static inferences, not exploit proof.")
        lines = []
        for group in report["finding_groups"]:
            lines.append(f"Group {group['id']}  |  Primary {group['primary']}")
            lines.extend(f"  {member['role']}: {member['fingerprint']}" for member in group["members"])
        for assessment in report["risk_assessments"]:
            lines.extend(("", f"Priority {assessment['priority']}  |  {assessment['subject']}",
                          assessment["rationale"]))
        for path in report["attack_paths"]:
            lines.extend(("", "Potential attack path: " + path["title"],
                          f"Confidence: {path['confidence']}", path["rationale"],
                          "Contributors: " + ", ".join(path["contributing_findings"]),
                          "Limitations: " + "; ".join(path["limitations"])))
        self._text_panel("\n".join(lines) if lines else "No risk relationships in the analyzed coverage.")

    def _ai(self, report: dict[str, Any]) -> None:
        coverage = report["coverage"]
        self._heading("AI reviews", "Advisory only. Deterministic findings and gate status remain authoritative.")
        lines = [f"Reviewed {coverage.get('ai_reviewed', 0)} / {coverage.get('ai_eligible', 0)} eligible",
                 f"Status: {report['summary']['ai_status']}", ""]
        for review in report["ai_reviews"]:
            lines.extend((f"{review['verdict']} / {review['confidence']}  |  {review['subject_id']}",
                          review["summary"], "Rationale: " + "; ".join(review["rationale"]),
                          "Supporting evidence: " + "; ".join(review["supporting_evidence"]),
                          "Contradictory evidence: " + "; ".join(review["contradictory_evidence"]),
                          "Missing context: " + "; ".join(review["missing_context"]),
                          "Suggested remediation: " + "; ".join(review["remediation"]),
                          "Limitations: " + "; ".join(review["limitations"]), ""))
        self._text_panel("\n".join(lines))

    def _remediation(self, report: dict[str, Any]) -> None:
        self._heading("Remediation proposals", "Proposal only. Every change needs human approval; runtime tests are NOT RUN.")
        proposals = report["remediation_proposals"]
        if not proposals:
            self._text_panel("No proposals in this report. Enable Propose fixes when scanning to produce guidance.")
            return
        chooser = ttk.Frame(self.main, style="Surface.TFrame")
        chooser.pack(fill="x", pady=(0, 8))
        self.proposal_var = tk.StringVar(value="0")
        labels = [f"{i + 1}. {display_text(p['title'], limit=80)}" for i, p in enumerate(proposals)]
        combo = ttk.Combobox(chooser, values=labels, state="readonly", width=65)
        combo.current(0)
        combo.pack(side="left", fill="x", expand=True)
        ttk.Button(chooser, text="Copy public proposal", command=lambda: self._copy_proposal(proposals[combo.current()])).pack(
            side="right", padx=(8, 0))
        text = tk.Text(self.main, wrap="word", bg=_SURFACE, fg=_INK, relief="flat",
                       font=("Segoe UI", 10), padx=8, pady=8)
        text.pack(fill="both", expand=True)

        def update(_event: object = None) -> None:
            proposal = proposals[combo.current()]
            validation = proposal.get("validation") or {}
            patch = proposal.get("patch_candidate") or {}
            lines = ["HUMAN APPROVAL REQUIRED", f"{proposal['strategy']} / {proposal['status']}",
                     proposal["summary"], "", "Guidance:", *proposal["remediation_steps"],
                     "", "Assumptions:", *proposal["assumptions"], "", "External actions:",
                     *proposal["external_actions_required"], "", "Patch provenance: " +
                     str(patch.get("provenance") or proposal.get("provenance") or "none"),
                     "Static validation: " +
                     validation.get("static_validation_status", "not available"),
                     "Validation diagnostics: " + ", ".join(validation.get("diagnostics") or []),
                     "Runtime tests: NOT RUN", "", "Public redacted patch:", public_patch_text(proposal)]
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", display_text("\n".join(lines), limit=40000))
            text.configure(state="disabled")

        combo.bind("<<ComboboxSelected>>", update)
        update()

    def _copy_proposal(self, proposal: dict[str, Any]) -> None:
        value = public_patch_text(proposal)
        if value == "[PATCH DIFF OMITTED]" or value.startswith("No patch available"):
            messagebox.showwarning("No copyable patch", "Only a public redacted patch can be copied.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set("Public redacted proposal copied. Review it before any manual change.")

    def _gate(self, report: dict[str, Any]) -> None:
        gate = self.controller.gate
        self._heading("Security gate", "The same evaluator powers this view and the gate command.")
        if gate is None:
            self._text_panel("Gate unavailable.")
            return
        lines = [f"Status: {gate.status.value}", f"Policy: {gate.policy_version}",
                 f"Coverage: {gate.coverage_status}", "", "Reasons:",
                 *(gate.reasons or ("none",)), "", "Blocking primary finding fingerprints:",
                 *(gate.blocking_findings or ("none",)), "", "Warnings:",
                 *(gate.warning_findings or ("none",)), "", "Diagnostics:",
                 *(gate.diagnostics or ("none",)), "", "AI advice never overrides this gate."]
        self._text_panel("\n".join(lines))

    def _diagnostics(self, report: dict[str, Any]) -> None:
        self._heading("Diagnostics", "Fixed codes and safe paths. No raw exception or source content.")
        lines = [f"{d['source']} / {d['code']} / {d.get('path') or '—'} / count {d['count']}\n{d['message']}"
                 for d in report["diagnostics"]]
        self._text_panel("\n\n".join(lines) if lines else "No diagnostics in this report.")

    def _reports(self, report: dict[str, Any]) -> None:
        self._heading("Export report", "Existing safe reporters create JSON, SARIF, and static HTML.")
        if self.controller.report is None:
            self._text_panel("This report was loaded from JSON. To export another format, run a fresh scan. Loading a report never triggers network lookups.")
            return
        bar = ttk.Frame(self.main, style="Surface.TFrame")
        bar.pack(fill="x", pady=(0, 16))
        for fmt in ("json", "sarif", "html"):
            ttk.Button(bar, text=f"Export {fmt.upper()}",
                       command=lambda f=fmt: self._export(f)).pack(side="left", padx=(0, 8))
        self._text_panel("Files are written only to a path you choose. Existing files are never silently overwritten.\n\nHTML is static, escaped, and contains no active scanned content.")

    def _settings(self, report: dict[str, Any]) -> None:
        self._heading("Session settings", "No scan history or API key is stored by this interface.")
        self._text_panel(f"Profile: {report['scan']['profile']}\nOffline: {report['scan']['offline']}\nAI status: {report['summary']['ai_status']}\n\nScanning options are selected per scan. Online use and AI remediation require explicit selection. The Gemini key is loaded only by the existing trusted provider when needed; this screen never displays it.")

    def _scan_dialog(self) -> None:
        if self.controller.running:
            return
        target = filedialog.askdirectory(title="Choose folder to scan", mustexist=True)
        if not target:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Scan options")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        form = ttk.Frame(dialog, padding=18)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="Folder selected", font=("Segoe UI Semibold", 11)).pack(anchor="w")
        ttk.Label(form, text=display_text(Path(target).name, limit=150)).pack(anchor="w", pady=(0, 10))
        profile = tk.StringVar(value="standard")
        ttk.Label(form, text="Profile").pack(anchor="w")
        ttk.Combobox(form, textvariable=profile, values=("quick", "standard", "deep"),
                     state="readonly", width=18).pack(anchor="w", pady=(2, 8))
        offline = tk.BooleanVar(value=True)
        ai = tk.BooleanVar(value=False)
        osv = tk.BooleanVar(value=False)
        fixes = tk.BooleanVar(value=False)
        ai_fix = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Offline mode (recommended)", variable=offline).pack(anchor="w")
        ttk.Checkbutton(form, text="OSV live advisory lookup (online)", variable=osv).pack(anchor="w")
        ttk.Checkbutton(form, text="Gemini AI review (online, advisory)", variable=ai).pack(anchor="w")
        ttk.Checkbutton(form, text="Propose remediation; never apply", variable=fixes).pack(anchor="w")
        ttk.Checkbutton(form, text="Gemini patch proposal (separate online grant)", variable=ai_fix).pack(anchor="w")
        ttk.Label(form, text="Online services run only when individually selected.\nAI sends bounded redacted context only when selected.",
                  foreground=_MUTED).pack(anchor="w", pady=(8, 12))

        def start() -> None:
            try:
                options = ScanOptions(ScanProfile(profile.get()), offline.get(), ai.get(),
                                      fixes.get(), ai_fix.get(), osv.get())
            except ValueError:
                messagebox.showerror("Scan options", "Choose offline mode or select an online service. AI remediation also requires proposals.", parent=dialog)
                return
            dialog.destroy()
            try:
                self.controller.start_scan(Path(target), options)
            except ValueError:
                messagebox.showerror("Scan", "A scan is already running.")
                return
            self.cancel_button.configure(state="normal")
            self.status_var.set("Discovering")
            self.banner.configure(text="SCAN IN PROGRESS", bg="#dceaf4", fg=_INK)

        ttk.Button(form, text="Start scan", style="Accent.TButton", command=start).pack(anchor="e")

    def _open_report(self) -> None:
        if self.controller.running:
            return
        selected = filedialog.askopenfilename(title="Open ScanReport JSON", filetypes=[("JSON", "*.json")])
        if not selected:
            return
        try:
            self.controller.open_report(Path(selected))
        except GateReportError as error:
            messagebox.showerror("Invalid report", f"Report rejected: {error.code}")
        except Exception:
            messagebox.showerror("Invalid report", "Report could not be opened safely.")

    def _export(self, fmt: str) -> None:
        report = self.controller.report
        if report is None:
            return
        selected = filedialog.asksaveasfilename(title=f"Export {fmt.upper()} report",
                                                defaultextension="." + ("html" if fmt == "html" else fmt),
                                                filetypes=[(fmt.upper(), "*." + fmt)])
        if not selected:
            return
        try:
            rendered = {"json": json_report.render, "sarif": sarif.render,
                        "html": html.render}[fmt](report)
            write_text(Path(selected), rendered, force=False)
        except ReportOutputError as error:
            messagebox.showerror("Export failed", f"Report was not written: {error.code}")
        except Exception:
            messagebox.showerror("Export failed", "Report was not written.")
        else:
            self.status_var.set("Report exported to the selected path.")

    def _poll(self) -> None:
        for event in self.controller.poll():
            if event.kind == "progress":
                self.status_var.set(display_text(event.value, limit=100))
            elif event.kind == "complete":
                self.cancel_button.configure(state="disabled")
                report = self.controller.public_report
                gate = self.controller.gate
                if report and gate:
                    coverage = report["coverage"]["overall"]
                    color = _BLOCK if coverage in {"FAILED", "ABORTED", "PARTIAL"} else \
                            _PASS if gate.status.value == "PASS" else _WARN if gate.status.value == "WARN" else _BLOCK
                    mode = "   |   OFFLINE MODE" if report["scan"]["offline"] else ""
                    self.banner.configure(text=f"COVERAGE {coverage}   |   SECURITY GATE {gate.status.value}{mode}",
                                          bg="#f5e6e8" if color == _BLOCK else "#e7f2ed" if color == _PASS else "#fff0d9",
                                          fg=color)
                    self.status_var.set(coverage_message(report))
                    self._render()
            elif event.kind == "error":
                self.cancel_button.configure(state="disabled")
                self.status_var.set("Scan failed: GUI_SCAN_FAILED")
                messagebox.showerror("Scan failed", "The scan could not complete. Diagnostic: GUI_SCAN_FAILED")
        self.root.after(100, self._poll)

    def _close(self) -> None:
        self.controller.cancel()
        self.root.destroy()


def run_gui() -> int:
    try:
        root = tk.Tk()
    except tk.TclError:
        print("GUI unavailable: desktop session could not be opened", file=sys.stderr)
        return 3
    AuditorApp(root)
    root.mainloop()
    return 0
