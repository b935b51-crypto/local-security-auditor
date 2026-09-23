"""Neutral, stable sensitive-behavior rule metadata."""

from security_auditor.core.models import Confidence, Severity
from security_auditor.scanners._common import StaticRule


def _rule(name: str, title: str, detail: str, severity: Severity = Severity.INFO,
          confidence: Confidence = Confidence.HIGH) -> StaticRule:
    return StaticRule(f"BEHAVIOR.{name}", title, detail, "behavior", severity, confidence,
                      "A recognized static operation may perform the stated behavior when executed.",
                      "Review whether this operation is expected and restrict its inputs and privileges.",
                      tags=("behavior", name.lower()))


RULES = (
    _rule("PROCESS_EXEC", "External process execution", "Code invokes an external process API."),
    _rule("SHELL_EXEC", "Shell execution", "Code invokes a shell or shell-like command interpreter.", Severity.MEDIUM),
    _rule("POWERSHELL_EXEC", "PowerShell invocation", "Code invokes PowerShell or a PowerShell command.", Severity.MEDIUM),
    _rule("CMD_EXEC", "CMD invocation", "Code invokes Windows CMD.", Severity.MEDIUM),
    _rule("ENCODED_COMMAND", "Encoded PowerShell command invocation", "Code uses an encoded PowerShell command flag.", Severity.MEDIUM),
    _rule("DYNAMIC_CODE", "Dynamic code execution", "Code invokes a dynamic code evaluation API.", Severity.MEDIUM),
    _rule("NETWORK_REQUEST", "Network request or download", "Code invokes a network request API."),
    _rule("FILE_DELETE", "File deletion", "Code invokes a file deletion API.", Severity.LOW),
    _rule("RECURSIVE_DELETE", "Recursive file deletion", "Code invokes a recursive deletion API.", Severity.MEDIUM),
    _rule("REGISTRY_WRITE", "Registry modification", "Code invokes a registry write API.", Severity.MEDIUM),
    _rule("STARTUP_PERSISTENCE", "Startup persistence-related modification", "Code modifies a recognized startup location.", Severity.MEDIUM),
    _rule("SCHEDULED_TASK", "Scheduled task modification", "Code invokes scheduled task tooling.", Severity.MEDIUM),
    _rule("SERVICE_MODIFICATION", "Service modification", "Code invokes service creation or control tooling.", Severity.MEDIUM),
    _rule("CREDENTIAL_ACCESS", "Credential-sensitive file or API access", "Code references a credential-sensitive path or API.", Severity.LOW),
    _rule("ENVIRONMENT_READ", "Environment variable access", "Code reads process environment variables."),
    _rule("DLL_LOAD", "Dynamic library load", "Code invokes a dynamic library loading API.", Severity.LOW),
    _rule("PROCESS_TERMINATION", "Process termination", "Code invokes process termination tooling.", Severity.LOW),
    _rule("SECURITY_CONTROL", "Security or firewall configuration change", "Code invokes security-control configuration tooling.", Severity.MEDIUM),
    _rule("HIDDEN_PROCESS", "Hidden process window configuration", "Code configures a hidden process window.", Severity.LOW),
    _rule("DOWNLOAD_EXECUTE", "Download-and-execute behavior pattern", "A local download is written to a file and the same file is later launched.", Severity.MEDIUM, Confidence.MEDIUM),
    _rule("WINDOWS_TOOL", "Windows system utility invocation", "Code invokes a Windows system utility.", Severity.LOW),
)
RULE_BY_ID = {rule.id: rule for rule in RULES}
