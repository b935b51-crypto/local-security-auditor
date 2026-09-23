"""Bounded Python AST frontend; target modules are never imported or executed."""

from __future__ import annotations

import ast
from dataclasses import dataclass


class PythonParseError(Exception):
    pass


class ASTBudgetError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ParsedPython:
    tree: ast.Module
    node_count: int


def parse_python(text: str, *, max_nodes: int, max_depth: int) -> ParsedPython:
    try:
        tree = ast.parse(text, mode="exec", type_comments=False)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise PythonParseError("SAST_PARSE_FAILED") from None
    count = 0
    pending: list[tuple[ast.AST, int]] = [(tree, 0)]
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            raise ASTBudgetError("SAST_AST_NODE_LIMIT_REACHED")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return ParsedPython(tree, count)


def import_aliases(statements: list[ast.stmt], inherited: dict[str, str] | None = None) -> dict[str, str]:
    aliases = dict(inherited or {})
    for stmt in statements:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.level == 0:
            for alias in stmt.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{stmt.module}.{alias.name}"
    return aliases


def qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = qualified_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    return None


def literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    return next((keyword.value for keyword in node.keywords if keyword.arg == name), None)
