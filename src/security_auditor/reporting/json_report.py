"""Canonical, deterministic UTF-8 JSON view."""

from __future__ import annotations

import json

from .models import ScanReport
from .serialization import report_view


def render(report: ScanReport) -> str:
    return json.dumps(report_view(report), ensure_ascii=False, sort_keys=True,
                      allow_nan=False, separators=(",", ":")) + "\n"
