"""Conservative bounded line heuristics for non-Python behavior."""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO
import re

from security_auditor.core.models import Confidence
from .models import BehaviorHit


def _compile(items: tuple[tuple[str, str], ...]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((rule, re.compile(pattern, re.I)) for rule, pattern in items)


_RULES = {
    "powershell": _compile((
        ("NETWORK_REQUEST", r"\b(?:Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"),
        ("PROCESS_EXEC", r"\bStart-Process\b"),
        ("DYNAMIC_CODE", r"\b(?:Invoke-Expression|iex)\b"),
        ("SHELL_EXEC", r"\b(?:Invoke-Expression|iex)\b"),
        ("FILE_DELETE", r"\bRemove-Item\b"),
        ("REGISTRY_WRITE", r"\b(?:Set-ItemProperty|New-ItemProperty)\b.*\b(?:HKLM|HKCU|Registry:)"),
        ("SCHEDULED_TASK", r"\b(?:Register-ScheduledTask|New-ScheduledTask|schtasks)\b"),
        ("SERVICE_MODIFICATION", r"\b(?:New-Service|Set-Service)\b"),
        ("SECURITY_CONTROL", r"\b(?:Set-MpPreference|Add-MpPreference)\b"),
        ("ENVIRONMENT_READ", r"\$env:[A-Za-z_][A-Za-z0-9_]*"),
        ("ENCODED_COMMAND", r"(?<!\w)-(?:EncodedCommand|enc)\b"),
    )),
    "batch": _compile((
        ("POWERSHELL_EXEC", r"\b(?:powershell|pwsh)(?:\.exe)?\b"),
        ("PROCESS_EXEC", r"\b(?:powershell|pwsh|cmd|certutil|bitsadmin|mshta|rundll32|regsvr32|wmic)(?:\.exe)?\b"),
        ("SHELL_EXEC", r"\bcmd(?:\.exe)?\s+/c\b"),
        ("CMD_EXEC", r"\bcmd(?:\.exe)?\s+/c\b"),
        ("WINDOWS_TOOL", r"\b(?:certutil|bitsadmin|mshta|rundll32|regsvr32|wmic)(?:\.exe)?\b"),
        ("NETWORK_REQUEST", r"\b(?:certutil\s+-urlcache|bitsadmin\s+/transfer)\b"),
        ("REGISTRY_WRITE", r"\breg(?:\.exe)?\s+add\b"),
        ("SCHEDULED_TASK", r"\bschtasks(?:\.exe)?\s+/(?:create|change|delete)\b"),
        ("SERVICE_MODIFICATION", r"\bsc(?:\.exe)?\s+(?:create|config|delete|start|stop)\b"),
        ("FILE_DELETE", r"\b(?:del|erase|rmdir|rd)\b"),
        ("RECURSIVE_DELETE", r"\b(?:del|rmdir|rd)\s+/(?:s|q)\b"),
        ("PROCESS_TERMINATION", r"\btaskkill(?:\.exe)?\b"),
        ("SECURITY_CONTROL", r"\bnetsh(?:\.exe)?\s+(?:advfirewall|firewall)\b"),
        ("ENCODED_COMMAND", r"(?<!\w)-(?:EncodedCommand|enc)\b"),
    )),
    "shell": _compile((
        ("NETWORK_REQUEST", r"\b(?:curl|wget)\b"),
        ("PROCESS_EXEC", r"\b(?:sh|bash)\s+-c\b"),
        ("SHELL_EXEC", r"\b(?:sh|bash)\s+-c\b"),
        ("RECURSIVE_DELETE", r"\brm\s+-[A-Za-z]*r[A-Za-z]*f\b|\brm\s+-[A-Za-z]*f[A-Za-z]*r\b"),
        ("DYNAMIC_CODE", r"\beval\s+"),
    )),
    "javascript": _compile((
        ("PROCESS_EXEC", r"\bchild_process\.(?:exec|spawn|execSync|spawnSync)\s*\("),
        ("SHELL_EXEC", r"\bchild_process\.(?:exec|execSync)\s*\("),
        ("DYNAMIC_CODE", r"\b(?:eval|Function)\s*\("),
        ("NETWORK_REQUEST", r"\b(?:fetch|axios\.(?:get|post|request))\s*\("),
        ("FILE_DELETE", r"\bfs\.(?:rm|rmdir|unlink)(?:Sync)?\s*\("),
        ("ENVIRONMENT_READ", r"\bprocess\.env\.[A-Za-z_][A-Za-z0-9_]*"),
    )),
}

_OUTFILE = re.compile(r"(?<!\w)-OutFile\s+[\"']?(?P<path>[A-Za-z0-9._/-]{1,128})", re.I)
_STARTFILE = re.compile(r"\bStart-Process\s+[\"']?(?P<path>[A-Za-z0-9._/-]{1,128})", re.I)


@dataclass(frozen=True, slots=True)
class TextAnalysis:
    hits: tuple[BehaviorHit, ...]
    long_line: bool
    limit_reached: bool


def analyze_text(source: str, *, language: str, encoding: str,
                 max_line_bytes: int, max_matches: int) -> TextAnalysis:
    group = "javascript" if language in {"javascript", "typescript", "jsx", "tsx"} else language
    rules = _RULES.get(group, ())
    hits: list[BehaviorHit] = []
    long_line = False
    limit_reached = False
    downloaded: set[str] = set()
    for number, line in enumerate(StringIO(source), 1):
        if len(line.encode(encoding)) > max_line_bytes:
            long_line = True
            continue
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", "//", "REM ", "rem ", "::")):
            continue
        lower_confidence = Confidence.LOW if ("\"" in line or "'" in line) else Confidence.MEDIUM
        for rule_id, pattern in rules:
            for match in pattern.finditer(line):
                if len(hits) >= max_matches:
                    limit_reached = True
                    break
                hits.append(BehaviorHit("BEHAVIOR." + rule_id, number, match.start() + 1,
                                        group, lower_confidence))
            if limit_reached:
                break
        if limit_reached:
            break
        if group == "powershell":
            output = _OUTFILE.search(line)
            started = _STARTFILE.search(line)
            if output and "Invoke-WebRequest" in line:
                downloaded.add(output.group("path"))
            if started and started.group("path") in downloaded:
                if len(hits) >= max_matches:
                    limit_reached = True
                    break
                hits.append(BehaviorHit("BEHAVIOR.DOWNLOAD_EXECUTE", number,
                                        started.start() + 1, "same_local_file", Confidence.MEDIUM))
    unique = {(hit.rule_id, hit.line, hit.column): hit for hit in hits}
    return TextAnalysis(tuple(sorted(unique.values(), key=lambda hit: (hit.line, hit.column, hit.rule_id))),
                        long_line, limit_reached)
