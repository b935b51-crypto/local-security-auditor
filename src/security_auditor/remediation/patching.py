"""Bounded, in-memory single-file edits and static checks. No filesystem writes."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import hashlib
from pathlib import Path
import re
from time import monotonic

from security_auditor.ai.redaction import redact_text
from security_auditor.core.config import RemediationSettings, SASTLimits
from security_auditor.core.models import ArtifactKind, ContentKind, FileArtifact, Finding, Severity
from security_auditor.discovery.content import ArtifactReadError, read_admitted_artifact
from security_auditor.discovery.path_safety import unsafe_component
from security_auditor.scanners.sast.python.engine import PythonTaintAnalyzer
from security_auditor.scanners.sast.python.frontend import ASTBudgetError, PythonParseError, parse_python
from security_auditor.scanners.sast.python.rules import RULE_BY_ID
from .models import (PatchCandidate, PatchValidationResult, ProposalStatus,
                     RemediationStrategy, SyntaxStatus)

_SUPPRESSION = re.compile(r"(?i)(#\s*(?:nosec|noqa|type:\s*ignore)|security-auditor.{0,30}(?:ignore|exclude)|disable.{0,20}rule)")
_DANGEROUS = re.compile(r"(?i)\b(?:eval|exec|os\.system)\s*\(|shell\s*=\s*True\b|verify\s*=\s*False\b|\bsubprocess\b|(?:pip|npm|uv)\s+install\b")
_URL = re.compile(r"(?i)\b(?:https?|ftp)://")
_DESTRUCTIVE = re.compile(r"(?m)^\s*(?:pass|return\s+None|raise\s+NotImplementedError)\b")


@dataclass(frozen=True, slots=True)
class LineEdit:
    start_line: int
    end_line: int
    replacement: str


@dataclass(frozen=True, slots=True)
class VirtualFileArtifact:
    """Internal-only in-memory source; never put this object in a report."""

    original: FileArtifact
    proposed_content: str
    is_virtual: bool = True


class PatchRejected(Exception):
    """Fixed safe reason only; raw source must not enter exception text."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def allowed_artifact(artifact: FileArtifact, finding: Finding, root: Path | None = None) -> bool:
    path = artifact.path
    parts = path.replace("\\", "/").split("/")
    if (path != finding.location.path or not parts or any(unsafe_component(p) for p in parts)
            or artifact.filesystem_type != "regular" or artifact.is_reparse_point
            or artifact.content_kind is not ContentKind.TEXT or artifact.encoding not in {"utf-8", "utf-8-sig"}
            or artifact.kind not in {ArtifactKind.SOURCE_CODE, ArtifactKind.SCRIPT}):
        return False
    folded = [p.casefold() for p in parts]
    name = folded[-1]
    if (".git" in folded or ".github" in folded and len(folded) > 1 and folded[1] == "workflows"
            or name in {".env", "agents.md", "project_status.md", "handoff.md", "security-auditor.toml"}
            or name.startswith(".env.") or name.endswith((".pem", ".key", ".p12", ".pfx"))):
        return False
    if root is not None:
        try:
            (root / artifact.path).resolve(strict=False).relative_to(Path(__file__).resolve().parents[1])
        except ValueError:
            pass
        except (OSError, RuntimeError):
            return False
        else:
            return False  # installed auditor code inside a scanned target
    return True


def read_source(root: Path, artifact: FileArtifact, limits: RemediationSettings) -> tuple[bytes, str]:
    if artifact.size_bytes > limits.max_patch_file_bytes:
        raise PatchRejected("PATCH_TOO_LARGE")
    try:
        raw = read_admitted_artifact(root, artifact, max_bytes=limits.max_patch_file_bytes)
        if artifact.sha256 and hashlib.sha256(raw).hexdigest() != artifact.sha256:
            raise PatchRejected("PATCH_SOURCE_STALE")
        return raw, raw.decode(artifact.encoding or "utf-8", errors="strict")
    except ArtifactReadError:
        raise PatchRejected("PATCH_SOURCE_STALE") from None
    except UnicodeError:
        raise PatchRejected("PATCH_APPLY_FAILED") from None


def tls_edit(source: str, line: int, limits: SASTLimits) -> tuple[LineEdit, ...]:
    try:
        tree = parse_python(source, max_nodes=limits.max_ast_nodes, max_depth=limits.max_ast_depth).tree
    except (PythonParseError, ASTBudgetError):
        raise PatchRejected("PATCH_SYNTAX_INVALID") from None
    lines = source.splitlines(keepends=True)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != line:
            continue
        for keyword in node.keywords:
            value = keyword.value
            if (keyword.arg != "verify" or not isinstance(value, ast.Constant) or value.value is not False
                    or value.lineno != value.end_lineno or value.lineno != line
                    or ast.get_source_segment(source, value) != "False"):
                continue
            old = lines[line - 1]
            try:
                offset = len(old.encode("utf-8")[:value.col_offset].decode("utf-8"))
            except UnicodeError:
                continue
            if old[offset:offset + 5] == "False":
                return (LineEdit(line, line, old[:offset] + "True" + old[offset + 5:]),)
    raise PatchRejected("REMEDIATION_NOT_SUPPORTED")


def _apply(source: str, edits: tuple[LineEdit, ...], limits: RemediationSettings) -> tuple[str, int, int]:
    if not 1 <= len(edits) <= limits.max_hunks:
        raise PatchRejected("PATCH_TOO_LARGE")
    lines = source.splitlines(keepends=True)
    ordered = sorted(edits, key=lambda e: e.start_line)
    for index, edit in enumerate(ordered):
        if (type(edit.start_line) is not int or type(edit.end_line) is not int
                or not 1 <= edit.start_line <= edit.end_line <= len(lines)
                or index and edit.start_line <= ordered[index - 1].end_line):
            raise PatchRejected("PATCH_OVERLAPPING_EDITS")
        if (not isinstance(edit.replacement, str) or len(edit.replacement) > 10000
                or "\x00" in edit.replacement):
            raise PatchRejected("PATCH_APPLY_FAILED")
    newline = "\r\n" if "\r\n" in source else "\n"
    if "\r\n" in source and source.replace("\r\n", "").find("\n") >= 0:
        raise PatchRejected("PATCH_APPLY_FAILED")
    changed = 0
    result = lines[:]
    for edit in reversed(ordered):
        old = lines[edit.start_line - 1:edit.end_line]
        replacement = edit.replacement.replace("\r\n", "\n")
        if "\r" in replacement:
            raise PatchRejected("PATCH_APPLY_FAILED")
        replacement = replacement.replace("\n", newline)
        if old[-1].endswith(("\r\n", "\n")) and not replacement.endswith(newline):
            replacement += newline
        new_lines = replacement.splitlines(keepends=True)
        changed += len(old) + len(new_lines)
        result[edit.start_line - 1:edit.end_line] = new_lines
    if changed > limits.max_changed_lines:
        raise PatchRejected("PATCH_TOO_LARGE")
    patched = "".join(result)
    if patched == source or len(patched.encode("utf-8")) > limits.max_patch_file_bytes:
        raise PatchRejected("PATCH_TOO_LARGE")
    return patched, changed, len(ordered)


def _added_removed(source: str, patched: str) -> tuple[str, str]:
    before, after = source.splitlines(), patched.splitlines()
    removed: list[str] = []
    added: list[str] = []
    for tag, i, j, x, y in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
        if tag != "equal":
            removed.extend(before[i:j])
            added.extend(after[x:y])
    return "\n".join(removed), "\n".join(added)


def _guard(source: str, patched: str, edits: tuple[LineEdit, ...]) -> None:
    removed, added = _added_removed(source, patched)
    if removed.strip() and not added.strip():
        raise PatchRejected("PATCH_DESTRUCTIVE_CHANGE")
    if _SUPPRESSION.search(added) and not _SUPPRESSION.search(removed):
        raise PatchRejected("PATCH_SECURITY_SUPPRESSION_DETECTED")
    if (_DANGEROUS.search(added) and not _DANGEROUS.search(removed)) or (_URL.search(added) and not _URL.search(removed)):
        raise PatchRejected("PATCH_NEW_HIGH_FINDING")
    if _DESTRUCTIVE.search(added) and not _DESTRUCTIVE.search(removed):
        raise PatchRejected("PATCH_DESTRUCTIVE_CHANGE")
    if removed.count("\n") > 10 and len(added) < len(removed) // 2:
        raise PatchRejected("PATCH_DESTRUCTIVE_CHANGE")
    if any(line.lstrip().startswith("#") for line in added.splitlines()) and not any(
            line.lstrip().startswith("#") for line in removed.splitlines()):
        raise PatchRejected("PATCH_DESTRUCTIVE_CHANGE")
    # A changed line containing a recognized credential is unsuitable for a public diff.
    if any(redact_text(line) != line for line in (*removed.splitlines(), *added.splitlines())):
        raise PatchRejected("PATCH_SECRET_EXPOSURE")


def _hits(source: str, limits: SASTLimits, deadline: float):
    try:
        parsed = parse_python(source, max_nodes=limits.max_ast_nodes, max_depth=limits.max_ast_depth)
    except (PythonParseError, ASTBudgetError):
        raise PatchRejected("PATCH_SYNTAX_INVALID") from None
    analyzed = PythonTaintAnalyzer(max_function_nodes=limits.max_function_nodes,
                                   max_hits=limits.max_findings_per_file,
                                   deadline=deadline).analyze(parsed.tree)
    if analyzed.diagnostics or monotonic() >= deadline:
        raise PatchRejected("PATCH_VALIDATION_PARTIAL")
    return parsed.tree, analyzed.hits


def validate_patch(root: Path, artifact: FileArtifact, finding: Finding,
                   edits: tuple[LineEdit, ...], strategy: RemediationStrategy,
                   settings: RemediationSettings, sast_limits: SASTLimits,
                   *, provenance: str, generated_by: str, confidence,
                   provider: str | None = None, model: str | None = None,
                   prompt_version: str | None = None) -> tuple[PatchCandidate | None, PatchValidationResult]:
    deadline = monotonic() + settings.max_patch_seconds
    def rejected(code: str, *, fresh: bool = False, scope: bool = False,
                 syntax: SyntaxStatus = SyntaxStatus.NOT_RUN) -> tuple[None, PatchValidationResult]:
        return None, PatchValidationResult(False, fresh, scope, syntax, True, None, False,
                                           diagnostics=(code,), limitations=("Runtime tests were not run.",))
    if not allowed_artifact(artifact, finding, root):
        return rejected("PATCH_FORBIDDEN_TARGET")
    try:
        raw, source = read_source(root, artifact, settings)
    except PatchRejected as error:
        return rejected(error.code)
    if artifact.language.language != "python":
        return rejected("REMEDIATION_NOT_SUPPORTED", fresh=True, scope=True,
                        syntax=SyntaxStatus.NOT_AVAILABLE)
    try:
        if finding.location.start_line is None or any(
                abs(edit.start_line - finding.location.start_line) > 12 or
                abs(edit.end_line - finding.location.start_line) > 12 for edit in edits):
            raise PatchRejected("PATCH_SCOPE_VIOLATION")
        patched, changed, hunks = _apply(source, edits, settings)
        _guard(source, patched, edits)
        before_tree, before_hits = _hits(source, sast_limits, deadline)
        virtual = VirtualFileArtifact(artifact, patched)
        after_tree, after_hits = _hits(virtual.proposed_content, sast_limits, deadline)
        if monotonic() >= deadline:
            raise PatchRejected("PATCH_VALIDATION_PARTIAL")
        # Function/class removal and broad statement deletion are not remediation.
        def declarations(tree):
            return Counter((type(n).__name__, getattr(n, "name", "")) for n in ast.walk(tree)
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        if declarations(before_tree) - declarations(after_tree):
            raise PatchRejected("PATCH_DESTRUCTIVE_CHANGE")
        before = Counter(hit.rule_id for hit in before_hits)
        after = Counter(hit.rule_id for hit in after_hits)
        before_locations = Counter((hit.rule_id, hit.line, hit.column) for hit in before_hits)
        after_locations = Counter((hit.rule_id, hit.line, hit.column) for hit in after_hits)
        target_before = any(hit.rule_id == finding.rule_id and hit.line == finding.location.start_line
                            for hit in before_hits)
        if not target_before:
            raise PatchRejected("PATCH_SOURCE_STALE")
        target_after = after[finding.rule_id] >= before[finding.rule_id]
        new = tuple(sorted(rule for rule, _, _ in (after_locations - before_locations).elements()))
        new_high = tuple(x for x in new if RULE_BY_ID[x].severity in {Severity.CRITICAL, Severity.HIGH})
        removed = tuple(sorted(rule for rule, _, _ in (before_locations - after_locations).elements()))
        changed_findings = tuple(sorted(set(new) & set(removed)))
        if new_high:
            raise PatchRejected("PATCH_NEW_HIGH_FINDING")
        if target_after:
            raise PatchRejected("PATCH_TARGET_FINDING_REMAINS")
        raw_diff = "".join(difflib.unified_diff(source.splitlines(keepends=True),
            patched.splitlines(keepends=True), fromfile=f"a/{artifact.path}",
            tofile=f"b/{artifact.path}", n=0))
        public_diff = "".join(redact_text(line.removesuffix("\n").removesuffix("\r")) +
                              ("\n" if line.endswith("\n") else "")
                              for line in raw_diff.splitlines(keepends=True))
        if public_diff != raw_diff.replace("\r\n", "\n"):
            raise PatchRejected("PATCH_SECRET_EXPOSURE")
        if len(public_diff.encode("utf-8")) > settings.max_patch_output_bytes:
            raise PatchRejected("PATCH_TOO_LARGE")
        original_hash = hashlib.sha256(raw).hexdigest()
        proposed_hash = hashlib.sha256(patched.encode(artifact.encoding or "utf-8")).hexdigest()
        patch_id = hashlib.sha256((finding.fingerprint + proposed_hash).encode()).hexdigest()[:24]
        candidate = PatchCandidate(patch_id, finding.id, strategy, artifact.path,
                                   original_hash, proposed_hash, public_diff,
                                   hunks, changed, provenance, generated_by,
                                   datetime.now(timezone.utc).isoformat(), True, confidence,
                                   provider, model, prompt_version)
        status = ProposalStatus.VALIDATED_STATICALLY if not new else ProposalStatus.PARTIAL_VALIDATION
        validation = PatchValidationResult(True, True, True, SyntaxStatus.VALID,
                                           True, False, True, new, new_high, removed, changed_findings, status,
                                           limitations=("Runtime tests were not run.",
                                                        "Static finding removal does not prove runtime correctness."))
        return candidate, validation
    except PatchRejected as error:
        return rejected(error.code, fresh=True, scope=error.code != "PATCH_SCOPE_VIOLATION",
                        syntax=SyntaxStatus.INVALID if error.code == "PATCH_SYNTAX_INVALID" else SyntaxStatus.NOT_RUN)
