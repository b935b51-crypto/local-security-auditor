"""Conservative fixed guidance keyed to existing scanner rule IDs."""

from __future__ import annotations

from security_auditor.core.models import Finding


_RULE_STEPS: dict[str, tuple[str, ...]] = {
    "SAST.PYTHON.COMMAND_INJECTION": ("Use a fixed executable and separate argv values.", "Disable shell execution and validate allowed actions."),
    "SAST.PYTHON.SQL_INJECTION": ("Use parameters supported by the identified database driver.", "Review query construction and driver placeholder semantics."),
    "SAST.PYTHON.PATH_TRAVERSAL": ("Resolve input against a trusted base directory.", "Reject absolute paths and paths escaping that base."),
    "SAST.PYTHON.UNSAFE_DESERIALIZATION": ("Replace object deserialization with a data-only format and schema validation.",),
    "SAST.PYTHON.DYNAMIC_CODE_EXEC": ("Replace dynamic execution with explicit dispatch or a data parser.",),
    "SAST.PYTHON.TLS_VERIFY_DISABLED": ("Enable TLS certificate verification and configure trusted CA material if needed.",),
    "SAST.PYTHON.UNSAFE_YAML_LOAD": ("Verify the imported YAML library and use a safe data loader.",),
    "SAST.PYTHON.INSECURE_TEMP_FILE": ("Use an atomic temporary file API with restrictive permissions and cleanup.",),
}
_SECRET_STEPS = ("Remove the hardcoded credential from source.",
                 "Load it through a trusted runtime secret channel.",
                 "If real, rotate or revoke it and inspect access logs.",
                 "Review Git history and deployment secret injection.")
_BEHAVIOR_STEPS = ("Review whether the observed operation is necessary and authorized.",
                   "If a correlated vulnerability exists, follow its primary remediation.")
_DEPENDENCY_STEPS = ("Review provider-reported fixed versions and compatibility.",
                     "Upgrade the direct dependency or parent of a transitive dependency.",
                     "Regenerate the lockfile and test in a separate trusted workflow.")


def guidance_for(finding: Finding) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    if finding.scanner_id.startswith("secrets") or finding.category.lower() in {"secret", "secrets"}:
        return _SECRET_STEPS, ("ROTATE_CREDENTIAL", "REVIEW_ACCESS_LOGS", "PURGE_GIT_HISTORY"), "Credential handling requires operator action."
    if finding.dependency or finding.vulnerability:
        return _DEPENDENCY_STEPS, ("UPGRADE_DEPENDENCY", "REGENERATE_LOCKFILE"), "Advisory matching does not establish exploitability."
    if finding.rule_id in _RULE_STEPS:
        return _RULE_STEPS[finding.rule_id], (), "Review applicability and behavior before any manual edit."
    if finding.scanner_id.startswith("behavior"):
        return _BEHAVIOR_STEPS, (), "A behavior signal alone does not prove a vulnerability."
    return ("Review the finding and its existing recommendation in context.",), (), "No rule-specific automated patch is supported."
