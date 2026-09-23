"""Narrow provider boundary; implementations receive sanitized context only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from security_auditor.ai.models import AIUsage


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    text: str
    usage: AIUsage = AIUsage()
    request_id: str | None = None


class ProviderFailure(Exception):
    """Fixed diagnostic code only; never capture request, key, or SDK message."""

    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class AIProvider(Protocol):
    provider_id: str
    model: str

    def review(self, context: str, *, api_key: str, thinking_level: str,
               max_output_tokens: int, timeout_seconds: float) -> ProviderResponse:
        ...
