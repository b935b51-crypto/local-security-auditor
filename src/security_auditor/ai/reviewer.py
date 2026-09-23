"""Advisory-only review orchestration with explicit egress and cost grants."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from time import monotonic
from typing import Sequence

from security_auditor.core.config import AISettings
from security_auditor.core.models import Confidence, Finding, ScanSession, ScannerResult
from security_auditor.correlation.models import CorrelationResult
from security_auditor.discovery.models import DiscoveryResult
from .context import AIContextBuilder, ContextBuildError
from .credentials import gemini_api_key
from .models import (AIDiagnostic, AIReviewBatch, AIReviewResult, AIReviewStatus,
                     AIReviewSummary, AIVerdict, AIUsage)
from .prompts import PROMPT_VERSION, RESPONSE_SCHEMA_VERSION
from .providers import AIProvider, GeminiProvider, ProviderFailure, ProviderResponse
from .redaction import safe_output
from .selection import AIReviewSelector


_FIELDS = frozenset({"verdict", "confidence", "summary", "rationale",
                     "supporting_evidence", "contradictory_evidence",
                     "missing_context", "remediation", "limitations"})
_LIST_FIELDS = ("rationale", "supporting_evidence", "contradictory_evidence",
                "missing_context", "remediation", "limitations")
_PROVIDER_CODES = frozenset({"AI_PROVIDER_UNAVAILABLE", "AI_PROVIDER_AUTH_FAILED",
                             "AI_PROVIDER_RATE_LIMITED", "AI_PROVIDER_TIMEOUT",
                             "AI_PROVIDER_ERROR", "AI_RESPONSE_INVALID"})


def _parse_response(response: ProviderResponse, api_key: str) -> dict[str, object]:
    if not isinstance(response.text, str) or len(response.text) > 32768:
        raise ProviderFailure("AI_RESPONSE_INVALID")
    try:
        payload = json.loads(response.text)
        if not isinstance(payload, dict) or set(payload) != _FIELDS:
            raise ValueError()
        verdict = AIVerdict(payload["verdict"])
        confidence = Confidence(payload["confidence"])
        summary = payload["summary"]
        if not isinstance(summary, str) or not 1 <= len(summary) <= 500:
            raise ValueError()
        result: dict[str, object] = {
            "verdict": verdict, "confidence": confidence,
            "summary": safe_output(summary.replace(api_key, "[REDACTED]"), limit=500),
        }
        for name in _LIST_FIELDS:
            values = payload[name]
            if (not isinstance(values, list) or len(values) > 8 or
                    any(not isinstance(text, str) or len(text) > 500 for text in values)):
                raise ValueError()
            result[name] = tuple(safe_output(text.replace(api_key, "[REDACTED]"), limit=500)
                                 for text in values)
        return result
    except (ValueError, TypeError, KeyError):
        raise ProviderFailure("AI_RESPONSE_INVALID") from None


class AIReviewer:
    def __init__(self, settings: AISettings | None = None,
                 provider: AIProvider | None = None):
        self.settings = settings or AISettings()
        self.provider = provider or GeminiProvider(model=self.settings.model)
        self.selector = AIReviewSelector()
        self.builder = AIContextBuilder(self.settings)

    def review(self, session: ScanSession, results: Sequence[ScannerResult],
               correlation: CorrelationResult | None = None,
               discovery: DiscoveryResult | None = None, *,
               allow_online_ai: bool = False,
               tool_config_dir: Path | None = None) -> AIReviewBatch:
        notes: Counter[str] = Counter()

        def finish(status: AIReviewStatus, selected: int, reviews=(), requests=0,
                   estimate=0, output=0) -> AIReviewBatch:
            summary = AIReviewSummary(status, selected, len(reviews), requests, estimate,
                                      output, tuple(AIDiagnostic(k, v) for k, v in sorted(notes.items())))
            return AIReviewBatch(tuple(sorted(reviews, key=lambda r: (r.subject_type.value,
                                                                      r.subject_id))), summary)

        if not self.settings.enabled or not allow_online_ai:
            notes["AI_DISABLED"] += 1
            return finish(AIReviewStatus.DISABLED, 0)
        if session.offline:
            notes["AI_OFFLINE"] += 1
            return finish(AIReviewStatus.DISABLED, 0)
        if self.provider.provider_id != self.settings.provider or self.provider.model != self.settings.model:
            notes["AI_PROVIDER_ERROR"] += 1
            return finish(AIReviewStatus.FAILED, 0)
        findings = {finding.fingerprint: finding for result in results for finding in result.findings}
        selected, available = self.selector.select(tuple(findings.values()), correlation,
                                                    self.settings.max_reviews)
        if available > len(selected):
            notes["AI_REVIEW_LIMIT_REACHED"] += 1
        if not selected:
            return finish(AIReviewStatus.COMPLETE, 0)
        # A trusted tool directory is distinct from the target root. If scanning
        # this tool itself, the target .env is never treated as a credential.
        directory = tool_config_dir or Path(__file__).resolve().parents[3]
        key = gemini_api_key(session.target.root, directory)
        if key is None:
            notes["AI_API_KEY_MISSING"] += 1
            return finish(AIReviewStatus.FAILED, len(selected))
        start = monotonic()
        reviews: list[AIReviewResult] = []
        request_count = estimate_total = sum_context = output_total = reserved_output = 0
        aborted = False
        for subject in selected:
            remaining = self.settings.max_seconds - (monotonic() - start)
            if remaining <= 0 or request_count >= self.settings.max_requests:
                notes["AI_REQUEST_LIMIT_REACHED" if remaining > 0 else "AI_PROVIDER_TIMEOUT"] += 1
                aborted = True
                break
            try:
                context = self.builder.build(subject, findings, correlation, session, discovery)
                sanitized = context.serialized.replace(key, "[REDACTED]")
                if key in sanitized:
                    raise ContextBuildError("AI_EGRESS_REDACTION_FAILED")
                # Redaction can change context identity; hash only the final payload.
                fingerprint = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()
                estimate = len(sanitized)
                if (estimate_total + estimate > self.settings.max_estimated_input_tokens or
                        sum_context + estimate > self.settings.max_total_context_chars):
                    notes["AI_TOKEN_BUDGET_REACHED"] += 1
                    aborted = True
                    break
                if reserved_output + self.settings.max_output_tokens > self.settings.max_total_output_tokens:
                    notes["AI_TOKEN_BUDGET_REACHED"] += 1
                    aborted = True
                    break
            except ContextBuildError as error:
                notes[error.code] += 1
                continue
            except (ValueError, TypeError, AttributeError):
                notes["AI_PROMPT_BUILD_FAILED"] += 1
                continue
            estimate_total += estimate
            sum_context += estimate
            reserved_output += self.settings.max_output_tokens
            parsed = None
            response = None
            for attempt in range(self.settings.max_retries + 1):
                remaining = self.settings.max_seconds - (monotonic() - start)
                if remaining <= 0 or request_count >= self.settings.max_requests:
                    notes["AI_PROVIDER_TIMEOUT" if remaining <= 0 else "AI_REQUEST_LIMIT_REACHED"] += 1
                    aborted = True
                    break
                request_count += 1
                try:
                    response = self.provider.review(
                        sanitized, api_key=key,
                        thinking_level=self.settings.thinking_level,
                        max_output_tokens=self.settings.max_output_tokens,
                        timeout_seconds=min(float(self.settings.timeout_seconds), remaining),
                    )
                    parsed = _parse_response(response, key)
                    break
                except ProviderFailure as error:
                    if error.retryable and attempt < self.settings.max_retries:
                        continue
                    notes[error.code if error.code in _PROVIDER_CODES else "AI_PROVIDER_ERROR"] += 1
                    break
                except Exception:
                    notes["AI_PROVIDER_ERROR"] += 1
                    break
            if aborted:
                break
            if parsed is None or response is None:
                continue
            if context.status.value == "stale" and parsed["confidence"] is Confidence.HIGH:
                parsed["confidence"] = Confidence.MEDIUM
            usage = response.usage if isinstance(response.usage, AIUsage) else AIUsage()
            if usage.output_tokens is not None:
                output_total += usage.output_tokens
            review_id = hashlib.sha256(
                f"{subject.kind.value}:{subject.id}:{PROMPT_VERSION}:{self.settings.model}:{fingerprint}".encode()
            ).hexdigest()[:24]
            request_id = response.request_id
            if not isinstance(request_id, str) or not request_id.isascii() or not request_id.replace("_", "").replace("-", "").isalnum() or len(request_id) > 128 or key in request_id:
                request_id = None
            reviews.append(AIReviewResult(
                review_id, self.provider.provider_id, self.provider.model,
                subject.kind, subject.id, parsed["verdict"], parsed["confidence"],
                parsed["summary"], parsed["rationale"], parsed["supporting_evidence"],
                parsed["contradictory_evidence"], parsed["missing_context"],
                parsed["remediation"], parsed["limitations"], PROMPT_VERSION,
                RESPONSE_SCHEMA_VERSION, datetime.now(timezone.utc), usage,
                context.status, fingerprint, request_id,
            ))
        status = (AIReviewStatus.ABORTED if aborted else
                  AIReviewStatus.COMPLETE if len(reviews) == len(selected) and not notes else
                  AIReviewStatus.PARTIAL if reviews else AIReviewStatus.FAILED)
        return finish(status, len(selected), reviews, request_count,
                      estimate_total, output_total)
