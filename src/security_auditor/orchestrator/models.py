"""Operator-owned request, independent of argparse and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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

    def __post_init__(self) -> None:
        if self.ai_requested and self.ai_disabled:
            raise ValueError("conflicting AI choices")
