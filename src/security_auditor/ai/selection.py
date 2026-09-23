"""Stable, deterministic selection; no INFO behavior flood."""

from __future__ import annotations

from typing import Sequence
import re

from security_auditor.core.models import Confidence, Finding, Severity
from security_auditor.correlation.models import CorrelationResult, RiskPriority
from .models import ReviewSubject, SubjectType


class AIReviewSelector:
    def select(self, findings: Sequence[Finding],
               correlation: CorrelationResult | None,
               max_reviews: int) -> tuple[tuple[ReviewSubject, ...], int]:
        candidates: dict[tuple[SubjectType, str], ReviewSubject] = {}
        for item in findings:
            if not isinstance(item.fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", item.fingerprint) is None:
                continue
            if item.severity in {Severity.CRITICAL, Severity.HIGH}:
                rank = 0 if item.severity is Severity.CRITICAL else 1
            elif item.scanner_id == "sast" and item.confidence is Confidence.MEDIUM:
                rank = 3
            else:
                continue
            subject = ReviewSubject(SubjectType.FINDING, item.fingerprint, rank)
            candidates[(subject.kind, subject.id)] = subject
        if correlation:
            for item in correlation.attack_paths:
                subject = ReviewSubject(SubjectType.ATTACK_PATH, item.id, 2)
                candidates[(subject.kind, subject.id)] = subject
            for item in correlation.assessments:
                if item.priority in {RiskPriority.CRITICAL, RiskPriority.HIGH}:
                    subject = ReviewSubject(SubjectType.RISK_ASSESSMENT, item.id, 2)
                    candidates[(subject.kind, subject.id)] = subject
            high_groups = {item.subject for item in correlation.assessments
                           if item.priority in {RiskPriority.CRITICAL, RiskPriority.HIGH}}
            for item in correlation.groups:
                if item.id in high_groups and len(item.members) > 1:
                    subject = ReviewSubject(SubjectType.FINDING_GROUP, item.id, 3)
                    candidates[(subject.kind, subject.id)] = subject
        ordered = tuple(sorted(candidates.values(), key=lambda x: (x.priority_rank,
                                                                     x.kind.value, x.id)))
        return ordered[:max_reviews], len(ordered)
