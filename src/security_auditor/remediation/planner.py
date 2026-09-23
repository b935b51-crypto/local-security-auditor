"""Bounded remediation planning from normalized findings and admitted artifacts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from time import monotonic

from security_auditor.ai.credentials import gemini_api_key
from security_auditor.ai.models import AIVerdict
from security_auditor.ai.providers.base import ProviderFailure
from security_auditor.ai.providers.gemini import GeminiProvider
from security_auditor.core.config import RemediationSettings, SASTLimits
from security_auditor.core.models import Confidence, Finding, Severity
from security_auditor.reporting.models import ScanReport
from .ai import parse_patch_response, patch_context, provider_code
from .guidance import guidance_for
from .models import (RemediationBatch, RemediationProposal, RemediationStrategy,
                     ProposalStatus)
from .patching import (PatchRejected, allowed_artifact, read_source, tls_edit,
                       validate_patch)
from .prompts import PATCH_PROMPT_VERSION


class RemediationPlanner:
    def __init__(self, settings: RemediationSettings, sast_limits: SASTLimits, *,
                 ai_provider=None, tool_config_dir: Path | None = None):
        self.settings = settings
        self.sast_limits = sast_limits
        self.ai_provider = ai_provider
        self.tool_config_dir = tool_config_dir

    def plan(self, report: ScanReport, *, ai_remediation: bool = False) -> RemediationBatch:
        if not self.settings.enabled:
            return RemediationBatch()
        started = monotonic()
        notes: set[str] = set()
        proposals: list[RemediationProposal] = []
        artifacts = {a.path: a for a in report.discovery.artifacts}
        roles = dict(report.roles)
        priorities = {a.subject: a.priority.value for a in report.risk_assessments}
        priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        severity_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                         Severity.LOW: 3, Severity.INFO: 4}
        findings = sorted((f for f in report.findings if roles.get(f.fingerprint, "primary") == "primary"),
                          key=lambda f: (priority_rank.get(priorities.get(f.fingerprint), 5),
                                         severity_rank[f.severity], f.location.path,
                                         f.location.start_line or 0, f.fingerprint))
        ai_requested = ai_remediation and not report.offline
        provider = self.ai_provider or GeminiProvider(model=self.settings.ai.model)
        key = None
        if ai_remediation and report.offline:
            notes.add("PATCH_AI_UNAVAILABLE")
        requests = tokens = patches = 0
        for finding in findings[:self.settings.max_proposals]:
            if monotonic() - started >= self.settings.max_patch_seconds:
                notes.add("PATCH_VALIDATION_PARTIAL")
                break
            steps, external, rationale = guidance_for(finding)
            proposal_id = hashlib.sha256(("remediation-v1:" + finding.fingerprint).encode()).hexdigest()[:24]
            proposal = RemediationProposal(proposal_id, finding.id,
                RemediationStrategy.GUIDANCE_ONLY, ProposalStatus.GUIDANCE_ONLY,
                finding.title, "Review the recommended remediation before editing.",
                rationale, ("Confirm this finding applies to the deployed code.",),
                steps, external, limitations=("Runtime tests were not run.",),
                provider_reported_fixed_versions=(finding.vulnerability.fixed_versions[:10]
                    if finding.vulnerability and not finding.vulnerability.withdrawn else ()))
            artifact = artifacts.get(finding.location.path)
            if (finding.rule_id == "SAST.PYTHON.TLS_VERIFY_DISABLED" and artifact is not None
                    and patches < self.settings.max_patch_proposals):
                if allowed_artifact(artifact, finding, report.discovery.root):
                    try:
                        _, source = read_source(report.discovery.root, artifact, self.settings)
                        edits = tls_edit(source, finding.location.start_line or 0, self.sast_limits)
                        candidate, validation = validate_patch(report.discovery.root, artifact,
                            finding, edits, RemediationStrategy.DETERMINISTIC,
                            self.settings, self.sast_limits, provenance="DETERMINISTIC_RULE",
                            generated_by="tls-verify-true-v1", confidence=Confidence.HIGH)
                        if candidate:
                            patches += 1
                            proposal = replace(proposal, strategy=RemediationStrategy.DETERMINISTIC,
                                status=validation.static_validation_status,
                                summary="Proposes changing the exact verify=False literal to verify=True.",
                                patch_candidate=candidate, validation_result=validation)
                        else:
                            notes.update(validation.diagnostics)
                    except PatchRejected as error:
                        notes.add(error.code)
                else:
                    notes.add("PATCH_FORBIDDEN_TARGET")
            false_positive = any(r.subject_id == finding.fingerprint and
                                 r.verdict is AIVerdict.LIKELY_FALSE_POSITIVE
                                 for r in report.ai_reviews)
            if false_positive:
                proposal = replace(proposal, limitations=proposal.limitations +
                                   ("AI review suggests a possible false positive; confirm before editing.",))
            can_ai = (ai_requested and not false_positive and proposal.patch_candidate is None
                      and finding.scanner_id == "sast.python" and artifact is not None
                      and finding.rule_id != "SAST.PYTHON.TLS_VERIFY_DISABLED"
                      and allowed_artifact(artifact, finding, report.discovery.root) and
                      patches < self.settings.max_patch_proposals and
                      requests < self.settings.ai.max_requests and
                      hasattr(provider, "propose_patch") and
                      provider.provider_id == "gemini" and provider.model == self.settings.ai.model)
            if can_ai:
                try:
                    _, source = read_source(report.discovery.root, artifact, self.settings)
                    if key is None:
                        directory = self.tool_config_dir or Path(__file__).resolve().parents[3]
                        key = gemini_api_key(report.discovery.root, directory)
                    if key is None:
                        raise PatchRejected("PATCH_AI_UNAVAILABLE")
                    context = patch_context(finding, artifact.path, source,
                                            max_chars=self.settings.ai.max_context_chars,
                                            api_key=key)
                    estimated = len(context) // 4 + self.settings.ai.max_output_tokens
                    if tokens + estimated > self.settings.ai.max_total_tokens_estimate:
                        raise PatchRejected("PATCH_TOO_LARGE")
                    tokens += estimated
                    requests += 1
                    response = provider.propose_patch(context, api_key=key,
                        thinking_level=self.settings.ai.thinking_level,
                        max_output_tokens=self.settings.ai.max_output_tokens,
                        timeout_seconds=min(20, self.settings.max_patch_seconds))
                    possible, edits, assumptions, limitations = parse_patch_response(
                        response, allowed_file=artifact.path, api_key=key)
                    if possible:
                        candidate, validation = validate_patch(report.discovery.root, artifact,
                            finding, edits, RemediationStrategy.AI_ASSISTED,
                            self.settings, self.sast_limits, provenance="GEMINI_AI",
                            generated_by=f"gemini:{provider.model}:{PATCH_PROMPT_VERSION}",
                            confidence=Confidence.LOW, provider="gemini", model=provider.model,
                            prompt_version=PATCH_PROMPT_VERSION)
                        if candidate:
                            patches += 1
                            proposal = replace(proposal, strategy=RemediationStrategy.AI_ASSISTED,
                                status=ProposalStatus.PARTIAL_VALIDATION if assumptions else validation.static_validation_status,
                                summary="AI proposed a single-file edit; deterministic checks found no supported regression.",
                                patch_candidate=candidate, validation_result=validation,
                                provenance="GEMINI_AI", assumptions=assumptions,
                                limitations=proposal.limitations + limitations)
                        else:
                            notes.update(validation.diagnostics)
                except ProviderFailure as error:
                    notes.add(provider_code(error))
                except PatchRejected as error:
                    notes.add(error.code)
                except Exception:
                    notes.add("PATCH_AI_UNAVAILABLE")
            proposals.append(proposal)
        if len(findings) > self.settings.max_proposals:
            notes.add("REMEDIATION_LIMIT_REACHED")
        if ai_requested and requests >= self.settings.ai.max_requests and len(findings) > requests:
            notes.add("PATCH_AI_REQUEST_LIMIT_REACHED")
        return RemediationBatch(tuple(proposals), tuple(sorted(notes)), len(findings), requests)
