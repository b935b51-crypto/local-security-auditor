"""Bounded JS/TS source-literal evidence for generic Secret rules.

This is a lexical aid, not JavaScript execution or a general-purpose parser.
Only source characters inside string/template literal spans can become generic
credential material. Uncertain expressions are not certified as safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterator


JS_LANGUAGES = frozenset({"javascript", "jsx", "typescript", "tsx"})
_ENV_PARAMETER = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:Partial\s*<\s*)?NodeJS\.ProcessEnv\s*>?"
)
_FUNCTION_ARGS = re.compile(r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(([^)]{0,512})\)")
_DIRECT_ENV = re.compile(
    r"(?:process\.env|[A-Za-z_$][\w$]*)"
    r"(?:\.[A-Za-z_$][\w$]*|\[\s*['\"][A-Za-z_$][\w$]*['\"]\s*\])"
    r"(?:\?\.trim\(\)|\.trim\(\))?"
)
_PENDING = re.compile(
    r"(?<![\w-])(?P<key>aws_secret_access_key|api[_-]?key|api[_-]?token|"
    r"client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|"
    r"private[_-]?key|connection[_-]?string|secret|token)"
    r"[\"']?\s*(?::|=)\s*$", re.I,
)


@dataclass(frozen=True)
class SourceLiteral:
    start: int  # first character of literal material, excluding quote
    end: int
    value: str


def proven_environment_parameters(source: str) -> frozenset[str]:
    """Recognize only explicitly typed function parameters in bounded JS/TS.

    This is static declaration evidence, not proof of the runtime caller. It is
    never used to suppress a source literal or a provider-specific match.
    """
    if len(source) > 128 * 1024:
        return frozenset()
    names: set[str] = set()
    for function in _FUNCTION_ARGS.finditer(source):
        for match in _ENV_PARAMETER.finditer(function.group(1)):
            names.add(match.group(1))
    return frozenset(names)


def expression_source(expression: str, proven_environment: frozenset[str] = frozenset()) -> str:
    """Classify one bounded RHS without assuming unknown objects are trusted."""
    expression = expression.strip().rstrip(";,").strip()
    if _DIRECT_ENV.fullmatch(expression):
        root = expression.split(".", 1)[0].split("[", 1)[0]
        if root == "process" or root in proven_environment:
            return "ENV_REFERENCE"
    literals = tuple(source_literals(expression))
    if literals:
        return "SOURCE_LITERAL" if (len(literals) == 1 and
                                    expression in {f"'{literals[0].value}'",
                                                   f'"{literals[0].value}"',
                                                   f"`{literals[0].value}`"}) else "MIXED"
    return "RUNTIME_REFERENCE"


def pending_assignment_prefix(line: str) -> str | None:
    """One-line bounded continuation for `apiKey =` followed by a RHS."""
    match = _PENDING.search(line.rstrip("\r\n"))
    return f"{match.group('key')} = " if match is not None else None


def source_literals(text: str, *, _depth: int = 0) -> Iterator[SourceLiteral]:
    """Yield source literal material spans; never yield expression identifiers.

    Handles quoted JS strings and bounded static template segments. Escaped
    delimiters stay within the literal. An interpolation is skipped rather than
    being treated as hardcoded text. The caller's line/window is already bound.
    """
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            return
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = length if end < 0 else end + 2
            continue
        quote = text[i]
        if quote not in {"'", '"', "`"}:
            i += 1
            continue
        i += 1
        segment_start = i
        while i < length:
            if text[i] == "\\":
                i = min(length, i + 2)
                continue
            if quote == "`" and text.startswith("${", i):
                if i > segment_start:
                    yield SourceLiteral(segment_start, i, text[segment_start:i])
                i += 2
                expression_start = i
                depth = 1
                while i < length and depth:
                    if text[i] == "\\":
                        i = min(length, i + 2)
                        continue
                    if text[i] in {"'", '"', "`"}:
                        nested_quote = text[i]
                        i += 1
                        while i < length and text[i] != nested_quote:
                            i = min(length, i + 2) if text[i] == "\\" else i + 1
                        i = min(length, i + 1)
                        continue
                    if text[i] == "{":
                        depth += 1
                    elif text[i] == "}":
                        depth -= 1
                    i += 1
                if depth == 0 and _depth < 3:
                    for nested in source_literals(text[expression_start:i - 1],
                                                  _depth=_depth + 1):
                        yield SourceLiteral(expression_start + nested.start,
                                            expression_start + nested.end, nested.value)
                segment_start = i
                continue
            if text[i] == quote:
                if i > segment_start:
                    yield SourceLiteral(segment_start, i, text[segment_start:i])
                i += 1
                break
            i += 1
        else:
            return
