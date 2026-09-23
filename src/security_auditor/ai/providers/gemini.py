"""Google Gen AI SDK Interactions adapter; no built-in tools or stored state."""

from __future__ import annotations

import re
from typing import Callable

from security_auditor.ai.models import AIUsage
from security_auditor.ai.prompts import RESPONSE_SCHEMA, SYSTEM_INSTRUCTION
from .base import ProviderFailure, ProviderResponse


_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _count(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 10_000_000 else None


class GeminiProvider:
    provider_id = "gemini"

    def __init__(self, client_factory: Callable[[str], object] | None = None,
                 model: str = "gemini-3.8-flash"):
        if model not in {"gemini-3.8-flash", "gemini-3.7-flash"}:
            raise ValueError("unsupported Gemini model")
        self.model = model
        self._client_factory = client_factory

    def _client(self, api_key: str):
        if self._client_factory:
            return self._client_factory(api_key)
        try:
            from google import genai  # optional official SDK; imported only after opt-in
        except ImportError:
            raise ProviderFailure("AI_PROVIDER_UNAVAILABLE") from None
        # Passing the key explicitly prevents GOOGLE_API_KEY precedence surprises.
        return genai.Client(api_key=api_key)

    def review(self, context: str, *, api_key: str, thinking_level: str,
               max_output_tokens: int, timeout_seconds: float) -> ProviderResponse:
        return self._structured(context, api_key=api_key, thinking_level=thinking_level,
                                max_output_tokens=max_output_tokens, timeout_seconds=timeout_seconds,
                                system_instruction=SYSTEM_INSTRUCTION, schema=RESPONSE_SCHEMA)

    def propose_patch(self, context: str, *, api_key: str, thinking_level: str,
                      max_output_tokens: int, timeout_seconds: float) -> ProviderResponse:
        from security_auditor.remediation.prompts import PATCH_RESPONSE_SCHEMA, PATCH_SYSTEM_INSTRUCTION
        return self._structured(context, api_key=api_key, thinking_level=thinking_level,
                                max_output_tokens=max_output_tokens, timeout_seconds=timeout_seconds,
                                system_instruction=PATCH_SYSTEM_INSTRUCTION,
                                schema=PATCH_RESPONSE_SCHEMA)

    def _structured(self, context: str, *, api_key: str, thinking_level: str,
                    max_output_tokens: int, timeout_seconds: float,
                    system_instruction: str, schema: dict) -> ProviderResponse:
        client = None
        try:
            client = self._client(api_key)
            interaction = client.interactions.create(
                model=self.model,
                input=context,
                system_instruction=system_instruction,
                response_format=[{"type": "text", "mime_type": "application/json",
                                  "schema": schema}],
                generation_config={"thinking_level": thinking_level,
                                   "max_output_tokens": max_output_tokens},
                tools=[], store=False, background=False, stream=False,
                timeout=timeout_seconds,
            )
            status = getattr(interaction, "status", "completed")
            if status != "completed":
                raise ProviderFailure("AI_RESPONSE_INVALID")
            output = getattr(interaction, "output_text", None)
            if not isinstance(output, str) or not output or len(output) > 32768:
                raise ProviderFailure("AI_RESPONSE_INVALID")
            raw_usage = getattr(interaction, "usage", None)
            usage = AIUsage(
                _count(getattr(raw_usage, "total_input_tokens", None)),
                _count(getattr(raw_usage, "total_output_tokens", None)),
                _count(getattr(raw_usage, "total_tokens", None)),
            )
            identifier = getattr(interaction, "id", None)
            if not isinstance(identifier, str) or not _REQUEST_ID.fullmatch(identifier):
                identifier = None
            return ProviderResponse(output, usage, identifier)
        except ProviderFailure:
            raise
        except Exception as error:
            status = getattr(error, "status_code", getattr(error, "code", None))
            if status in {401, 403}:
                raise ProviderFailure("AI_PROVIDER_AUTH_FAILED") from None
            if status == 429:
                raise ProviderFailure("AI_PROVIDER_RATE_LIMITED") from None
            if isinstance(error, TimeoutError) or type(error).__name__ in {
                    "ReadTimeout", "ConnectTimeout", "TimeoutException"}:
                raise ProviderFailure("AI_PROVIDER_TIMEOUT", retryable=True) from None
            if status in {500, 502, 503, 504}:
                raise ProviderFailure("AI_PROVIDER_ERROR", retryable=True) from None
            raise ProviderFailure("AI_PROVIDER_ERROR") from None
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass  # no SDK exception text is exposed
