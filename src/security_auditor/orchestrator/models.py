"""Operator-owned request, independent of argparse and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable

from security_auditor.core.config import AuditConfig
from security_auditor.core.models import ScanProfile


@dataclass(frozen=True, slots=True)
class ScanRequest:
    target: Path
    config: AuditConfig = AuditConfig()
    profile: ScanProfile | None = None
    offline: bool | None = None
    ai_requested: bool = False
    ai_disabled: bool = False
    propose_fixes: bool = False
    ai_remediation_requested: bool = False
    cancel_event: Event | None = None
    progress: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        if self.ai_requested and self.ai_disabled:
            raise ValueError("conflicting AI choices")
        if self.ai_remediation_requested and not self.propose_fixes:
            raise ValueError("AI remediation requires remediation proposals")
