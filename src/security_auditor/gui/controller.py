"""Thread-safe GUI application controller over the existing orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any

from security_auditor.core.config import AuditConfig
from security_auditor.core.models import ScanProfile
from security_auditor.gate import evaluate_gate, load_report
from security_auditor.gate.service import SecurityGateResult
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting.models import ScanReport
from security_auditor.reporting.serialization import report_view


@dataclass(frozen=True, slots=True)
class ScanOptions:
    profile: ScanProfile = ScanProfile.STANDARD
    offline: bool = True
    ai_review: bool = False
    propose_fixes: bool = False
    ai_remediation: bool = False
    osv_online: bool = False

    def __post_init__(self) -> None:
        if self.ai_remediation and not self.propose_fixes:
            raise ValueError("AI remediation requires proposals")
        if self.offline and (self.ai_review or self.ai_remediation or self.osv_online):
            raise ValueError("online services require explicit online mode")
        if not self.offline and not (self.ai_review or self.ai_remediation or self.osv_online):
            raise ValueError("select an online service")


@dataclass(frozen=True, slots=True)
class ControllerEvent:
    kind: str
    value: str = ""


class ApplicationController:
    """Worker owns scans; the UI thread owns all widget updates and polls events."""

    def __init__(self, orchestrator: ScanOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or ScanOrchestrator()
        self.events: Queue[ControllerEvent] = Queue()
        self.cancel_event = Event()
        self.worker: Thread | None = None
        self.report: ScanReport | None = None
        self.public_report: dict[str, Any] | None = None
        self.gate: SecurityGateResult | None = None

    @property
    def running(self) -> bool:
        return self.worker is not None and self.worker.is_alive()

    def start_scan(self, target: Path, options: ScanOptions) -> None:
        if self.running:
            raise ValueError("scan already running")
        self.poll()
        self.cancel_event = Event()
        self.report = None
        self.public_report = None
        self.gate = None
        # Gemini-only grants never silently enable OSV. The orchestrator has a
        # separate AI-only online path when offline=None and config.offline=True.
        offline_choice = False if options.osv_online else True if options.offline else None
        request = ScanRequest(target=target, config=AuditConfig(), profile=options.profile,
                              offline=offline_choice, ai_requested=options.ai_review,
                              propose_fixes=options.propose_fixes,
                              ai_remediation_requested=options.ai_remediation,
                              cancel_event=self.cancel_event,
                              progress=lambda name: self.events.put(ControllerEvent("progress", name)))
        self.worker = Thread(target=self._scan_worker, args=(request,), daemon=True,
                             name="security-auditor-scan")
        self.worker.start()

    def _scan_worker(self, request: ScanRequest) -> None:
        try:
            report = self.orchestrator.run_scan(request)
            public = report_view(report)
            gate = evaluate_gate(public)
            self.report, self.public_report, self.gate = report, public, gate
            self.events.put(ControllerEvent("complete", report.coverage.overall.value))
        except Exception:
            self.events.put(ControllerEvent("error", "GUI_SCAN_FAILED"))

    def cancel(self) -> None:
        if self.running:
            self.cancel_event.set()
            self.events.put(ControllerEvent("progress", "Cancelling after current bounded phase"))

    def open_report(self, path: Path) -> None:
        if self.running:
            raise ValueError("scan still running")
        self.poll()
        public = load_report(path)
        gate = evaluate_gate(public)
        self.report = None
        self.public_report = public
        self.gate = gate
        self.events.put(ControllerEvent("complete", public["coverage"]["overall"]))

    def poll(self) -> tuple[ControllerEvent, ...]:
        items: list[ControllerEvent] = []
        while True:
            try:
                items.append(self.events.get_nowait())
            except Empty:
                return tuple(items)
