"""Optional Gemini patch egress and strict response parsing; source is hostile data."""

from __future__ import annotations

import json

from security_auditor.ai.redaction import redact_text, safe_output
from security_auditor.ai.providers.base import ProviderFailure, ProviderResponse
from security_auditor.core.models import Finding
from .patching import LineEdit, PatchRejected
from .prompts import PATCH_PROMPT_VERSION


def patch_context(finding: Finding, path: str, source: str, *, max_chars: int,
                  api_key: str) -> str:
    line = finding.location.start_line or 1
    start = max(1, line - 8)
    numbered = [{"line": n, "text": redact_text(text, source=True)[:240]}
                for n, text in enumerate(source.splitlines()[start - 1:line + 8], start)]
    payload = {"prompt_version": PATCH_PROMPT_VERSION, "allowed_file": path,
               "finding_rule": finding.rule_id, "finding_line": line,
               "finding_title": finding.title,
               "finding_recommendation": finding.remediation.recommendation,
               "source_is_untrusted_data": True,
               "runtime_tests": "NOT_RUN", "context_lines": numbered}
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    serialized = redact_text(serialized).replace(api_key, "[REDACTED]")
    if len(serialized) > max_chars or api_key in serialized:
        raise PatchRejected("PATCH_TOO_LARGE")
    return serialized


def _no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def parse_patch_response(response: ProviderResponse, *, allowed_file: str,
                         api_key: str) -> tuple[bool, tuple[LineEdit, ...],
                                                tuple[str, ...], tuple[str, ...]]:
    if not isinstance(response.text, str) or len(response.text) > 32768 or api_key in response.text:
        raise PatchRejected("PATCH_AI_RESPONSE_INVALID")
    try:
        data = json.loads(response.text, object_pairs_hook=_no_duplicate_keys)
        expected = {"can_propose_patch", "target_file", "assumptions", "replacements", "rationale", "limitations"}
        if not isinstance(data, dict) or set(data) != expected or type(data["can_propose_patch"]) is not bool:
            raise ValueError()
        if data["target_file"] != allowed_file:
            raise PatchRejected("PATCH_SCOPE_VIOLATION")
        for key in ("assumptions", "rationale", "limitations"):
            values = data[key]
            if (not isinstance(values, list) or len(values) > 8 or
                    any(not isinstance(x, str) or len(x) > 500 for x in values)):
                raise ValueError()
        items = data["replacements"]
        if not isinstance(items, list) or len(items) > 5:
            raise ValueError()
        edits = []
        for item in items:
            if (not isinstance(item, dict) or set(item) != {"start_line", "end_line", "replacement"}
                    or type(item["start_line"]) is not int or type(item["end_line"]) is not int
                    or not isinstance(item["replacement"], str) or len(item["replacement"]) > 10000):
                raise ValueError()
            edits.append(LineEdit(item["start_line"], item["end_line"], item["replacement"]))
        if data["can_propose_patch"] and not edits or not data["can_propose_patch"] and edits:
            raise ValueError()
        assumptions = tuple(safe_output(x, limit=500) for x in data["assumptions"])
        limitations = tuple(safe_output(x, limit=500) for x in data["limitations"])
        return data["can_propose_patch"], tuple(edits), assumptions, limitations
    except PatchRejected:
        raise
    except (ValueError, TypeError, KeyError):
        raise PatchRejected("PATCH_AI_RESPONSE_INVALID") from None


def provider_code(error: ProviderFailure) -> str:
    return {"AI_PROVIDER_UNAVAILABLE": "PATCH_AI_UNAVAILABLE",
            "AI_PROVIDER_AUTH_FAILED": "PATCH_AI_UNAVAILABLE",
            "AI_PROVIDER_RATE_LIMITED": "PATCH_AI_RATE_LIMITED",
            "AI_PROVIDER_TIMEOUT": "PATCH_AI_UNAVAILABLE",
            "AI_RESPONSE_INVALID": "PATCH_AI_RESPONSE_INVALID"}.get(error.code, "PATCH_AI_UNAVAILABLE")
