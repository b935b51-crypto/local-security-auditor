"""Stable, immutable metadata for the native Phase 2 rule set."""

from __future__ import annotations

from dataclasses import dataclass

from security_auditor.core.models import Confidence, RuleReference, Severity


@dataclass(frozen=True, slots=True)
class SecretRuleMetadata:
    rule_id: str
    title: str
    provider: str | None
    default_severity: Severity
    default_confidence: Confidence
    confidence_behavior: str
    tags: tuple[str, ...]
    description: str = "Credential-like material was found by bounded static analysis; validity is unknown."
    category: str = "secret"
    reference: str = "https://cwe.mitre.org/data/definitions/798.html"

    def to_reference(self) -> RuleReference:
        return RuleReference(self.rule_id, self.title, self.reference)


RULES: tuple[SecretRuleMetadata, ...] = (
    SecretRuleMetadata("SECRET.PRIVATE_KEY.PEM", "Private key material embedded in source", None,
                       Severity.HIGH, Confidence.HIGH, "private-key begin marker", ("private_key",)),
    SecretRuleMetadata("SECRET.GITHUB.TOKEN", "Hardcoded GitHub token-like credential", "github",
                       Severity.HIGH, Confidence.HIGH, "structured token shape", ("provider", "token")),
    SecretRuleMetadata("SECRET.AWS.ACCESS_KEY", "AWS access key ID-like value", "aws",
                       Severity.LOW, Confidence.MEDIUM, "raise with nearby secret access key", ("provider", "identifier")),
    SecretRuleMetadata("SECRET.STRIPE.SECRET_KEY", "Hardcoded Stripe secret-key-like credential", "stripe",
                       Severity.HIGH, Confidence.HIGH, "structured token shape", ("provider", "token")),
    SecretRuleMetadata("SECRET.SLACK.TOKEN", "Hardcoded Slack token-like credential", "slack",
                       Severity.HIGH, Confidence.HIGH, "structured token shape", ("provider", "token")),
    SecretRuleMetadata("SECRET.GITLAB.TOKEN", "Hardcoded GitLab token-like credential", "gitlab",
                       Severity.HIGH, Confidence.HIGH, "structured token shape", ("provider", "token")),
    SecretRuleMetadata("SECRET.CONNECTION_STRING", "Credential embedded in connection string", None,
                       Severity.HIGH, Confidence.HIGH, "password-bearing URL structure", ("connection",)),
    SecretRuleMetadata("SECRET.JWT", "JWT-like credential embedded in source", None,
                       Severity.MEDIUM, Confidence.MEDIUM, "bounded header and payload JSON shape", ("jwt",)),
    SecretRuleMetadata("SECRET.GENERIC.ASSIGNMENT", "Hardcoded credential-like assignment", None,
                       Severity.MEDIUM, Confidence.MEDIUM, "value length, classes, entropy, context", ("assignment",)),
    SecretRuleMetadata("SECRET.GENERIC.ENTROPY", "Contextual high-entropy credential-like value", None,
                       Severity.LOW, Confidence.LOW, "entropy only after secret context gate", ("entropy",)),
)
RULE_BY_ID = {rule.rule_id: rule for rule in RULES}
