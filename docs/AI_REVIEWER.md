# Optional AI Security Reviewer (Phase 6)

The deterministic Phase 1–5 results remain authoritative. `AIReviewer` returns separate immutable `AIReviewResult` annotations for a Finding, FindingGroup, AttackPathCandidate, or RiskAssessment. AI cannot delete or suppress a Finding, rewrite severity/confidence/CVSS/risk priority, apply a patch, or run target code. Verdicts are `CONFIRMED`, `LIKELY_VALID`, `UNCERTAIN`, `LIKELY_FALSE_POSITIVE`, and `INSUFFICIENT_CONTEXT`. Even `CONFIRMED` refers only to supplied static evidence, never runtime exploitation. AI confidence is independent of Finding confidence.

## Activation and credential boundary

AI is disabled by default. A caller must supply trusted `AISettings(enabled=True)`, `allow_online_ai=True`, and an online `ScanSession`; any missing grant prevents provider calls. `offline=True` wins over AI settings. Phase 7's CLI grants AI only with explicit `--ai`; it never takes authority from target repository configuration, `.env`, comments, or README text. See [CLI](CLI.md).

Only `GEMINI_API_KEY` is accepted. Process environment wins over a trusted tool-project `.env`; a tool directory inside the scanned root is refused as a key source. The loader reads at most 8 KiB of a regular, non-reparse `.env`, accepts simple `KEY=value` and quoted values, and performs no expansion, shell substitution, or evaluation. `.env` and `.env.*` are Git ignored while `.env.example` contains an empty placeholder. The key is passed explicitly to the SDK client and is not put in request input, output records, diagnostics, status, or logs. The tool never reads a scanned target `.env` to authenticate.

## Provider and data flow

```text
Normalized Findings + CorrelationResult
  -> deterministic priority selector
  -> bounded AIContextBuilder
  -> second egress redaction
  -> optional AIProvider / GeminiProvider
  -> strict response validation
  -> immutable AIReviewResult
```

`AIProvider` is replaceable. V1 implements `GeminiProvider` through Google's optional `google-genai>=2.25.0,<3.0.0` SDK extra. The default model is `gemini-3.8-flash`; trusted configuration can select the allowlisted `gemini-3.7-flash`. Thinking defaults to `medium` and allows `low`/`high`; `minimal` is rejected. The official SDK is preferred to a custom HTTP client for authentication, timeouts, and structured Interactions support. The SDK extra is not installed by the default environment and is imported only on an enabled provider call. No target dependencies are installed. The SDK's transitive dependencies increase supply-chain review surface, so the extra is opt-in and major-version bounded.

Each request is independent: one subject, no previous interaction, `store=false`, no background mode, `tools=[]`, no Search, URL Context, Code Execution, Computer Use, File Search, Maps, or function tools. A fixed system instruction treats all target material as untrusted data. The prompt input is bounded JSON with a separate `untrusted_source_context` field. The provider receives only the sanitized string; it never reads target files itself. Phase 6 does not provide any function-calling callback. Official API behavior was checked against Google's [Gemini 3.8 Flash model page](https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash), [Interactions API](https://ai.google.dev/gemini-api/docs/interactions-overview), [structured output guide](https://ai.google.dev/gemini-api/docs/structured-output), [thinking guide](https://ai.google.dev/gemini-api/docs/thinking), and [Python SDK documentation](https://googleapis.github.io/python-genai/). One gated live request with SDK 2.25.0 validated authentication, structured response handling, and usage extraction for a synthetic Finding; broader provider behavior remains unverified.

## Minimal context and freshness

Selection favors CRITICAL/HIGH findings, MEDIUM-confidence SAST, attack-path candidates, and high-priority correlation assessments/groups. Stable ordering and `max_reviews` prevent INFO behavior floods. Finding context includes rule ID, severity, confidence, safe relative location, a small allowlist of structured evidence, and bounded remediation. Titles, free-text descriptions, raw scanner evidence, entire repositories, and whole files are omitted.

Source is **off by default**. When trusted `include_source=true` and an admitted `DiscoveryResult` are supplied, the builder reopens only a regular text source/script artifact through `read_admitted_artifact`, bounded by file bytes and line count. It checks root identity and artifact hash when available. If an artifact changed, it omits source and marks context `STALE`; if unavailable, `UNAVAILABLE`. Secret findings never reopen source. Source lines lose comments, long opaque tokens, credential patterns, URLs, and quoted literals before serialization. Truncation drops source and marks `[CONTEXT TRUNCATED]`. The final payload is checked again for the known API key and hashed only after redaction. Novel secrets may evade pattern redaction; leaving source disabled is the safer default.

## Output and limits

The Interactions request uses `response_format` with JSON Schema, and local code independently requires exact fields/enums and bounds every string/list. Unexpected, oversized, or malformed output becomes `AI_RESPONSE_INVALID`; SDK exception messages and raw output are never placed in diagnostics. AI text is redacted and treated as untrusted display data for future reporters. No AI response cache is implemented. Usage counts are kept only when the provider returns valid values; missing counts remain unknown.

Trusted config has hard-capped limits for reviews, requests including retries, per-review and total context, estimated input tokens, per-request and total reserved output tokens, source lines/file bytes, elapsed time, request timeout, and retries. The character count is a conservative token reservation, not exact billing. No concurrency. Only timeout or server errors receive bounded retry; authentication, quota, schema, and policy failures do not. `DISABLED`, `COMPLETE`, `PARTIAL`, `ABORTED`, and `FAILED` remain separate. Diagnostics are fixed codes such as `AI_OFFLINE`, `AI_API_KEY_MISSING`, `AI_PROVIDER_RATE_LIMITED`, `AI_PROVIDER_TIMEOUT`, `AI_RESPONSE_INVALID`, `AI_CONTEXT_LIMIT_REACHED`, `AI_REQUEST_LIMIT_REACHED`, and `AI_TOKEN_BUDGET_REACHED`.

## Validation and residual risk

Default tests use fake providers and an injected fake SDK client, with no network or real key. The optional `tests/live/test_gemini.py` makes at most one small synthetic request only when `SECURITY_AUDITOR_LIVE_GEMINI_TEST=1` and the existing safe credential loader finds a trusted key in the process environment or tool `.env`; it is otherwise skipped. It uses `medium` thinking and zero retries, checks one request and schema-valid review, and asserts the key is absent from captured output and serialized results. The full offline suite now passes under uv-managed Python 3.12.11; Gemini live validation on that interpreter was not repeated in this hardening. SDK/network timeouts are best effort and cannot forcibly preempt a blocking SDK call. Provider data quality, model hallucination, residual prompt injection, and novel secret formats remain review risks. Phase 7's report serializers escape and re-redact AI text; see [Reporting](REPORTING.md).
