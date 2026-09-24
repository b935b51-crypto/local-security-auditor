"""Small flow-sensitive intraprocedural taint values and expression evaluator."""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace

from .frontend import qualified_name
from .sanitizers import guard_kind
from .sources import SourceCategory, direct_source


MAX_TRACE = 12


@dataclass(frozen=True, slots=True)
class Taint:
    category: SourceCategory
    source_line: int
    trace: tuple[tuple[str, int], ...]
    transformed: bool = False
    guards: frozenset[str] = frozenset()
    remote_origin: bool = False

    def step(self, label: str, line: int, *, transformed: bool = False,
             guard: str | None = None) -> Taint:
        steps = (self.trace + ((label, line),))[-MAX_TRACE:]
        return replace(self, trace=steps, transformed=self.transformed or transformed,
                       guards=self.guards | ({guard} if guard else set()))


def merge(left: Taint | None, right: Taint | None, line: int) -> Taint | None:
    if left is None:
        return right
    if right is None:
        return left
    preferred = left if (left.source_line, left.category.value) <= (right.source_line, right.category.value) else right
    return replace(preferred, transformed=left.transformed or right.transformed,
                   guards=left.guards & right.guards,
                   remote_origin=(left.remote_origin or right.remote_origin or
                                  left.category in {SourceCategory.HTTP_INPUT, SourceCategory.NETWORK_INPUT} or
                                  right.category in {SourceCategory.HTTP_INPUT, SourceCategory.NETWORK_INPUT}),
                   trace=(preferred.trace + (("merge", line),))[-MAX_TRACE:])


def expression_taint(node: ast.AST | None, env: dict[str, Taint],
                     aliases: dict[str, str]) -> Taint | None:
    if node is None:
        return None
    source = direct_source(node, aliases)
    if source is not None:
        line = getattr(node, "lineno", 1)
        return Taint(source, line, ((source.value, line),))
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        base = node.value
        result = expression_taint(base, env, aliases)
        if result and isinstance(node, ast.Attribute) and node.attr == "name":
            return result.step("path.name", getattr(node, "lineno", 1), guard="path_component")
        return result
    if isinstance(node, ast.Call):
        guard = guard_kind(node, aliases)
        name = qualified_name(node.func, aliases)
        if name in {"requests.get", "requests.post", "httpx.get", "httpx.post",
                    "urllib.request.urlopen"}:
            line = getattr(node, "lineno", 1)
            return Taint(SourceCategory.NETWORK_INPUT, line, (("NETWORK_INPUT", line),))
        if name and name.endswith(".read") and isinstance(node.func, ast.Attribute):
            origin = expression_taint(node.func.value, env, aliases)
            if origin:
                return origin.step("read", getattr(node, "lineno", 1))
        if name and name.endswith(".get") and isinstance(node.func, ast.Attribute):
            origin = expression_taint(node.func.value, env, aliases)
            if origin:
                return origin.step("mapping.get", getattr(node, "lineno", 1))
        items = [expression_taint(arg, env, aliases) for arg in node.args]
        items.extend(expression_taint(kw.value, env, aliases) for kw in node.keywords)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "format", "resolve", "absolute", "joinpath", "with_name", "with_suffix",
        }:
            items.append(expression_taint(node.func.value, env, aliases))
        result = None
        for item in items:
            result = merge(result, item, getattr(node, "lineno", 1))
        if result and guard:
            return result.step(guard, getattr(node, "lineno", 1), guard=guard)
        formatted = isinstance(node.func, ast.Attribute) and node.func.attr == "format"
        if result and (name in {"str", "bytes", "pathlib.Path", "Path", "os.path.join",
                                "os.path.abspath", "os.path.realpath"}
                       or formatted
                       or (isinstance(node.func, ast.Attribute) and node.func.attr in {
                           "resolve", "absolute", "joinpath", "with_name", "with_suffix",
                       })):
            return result.step("expression", getattr(node, "lineno", 1),
                               transformed=formatted)
        return None
    if isinstance(node, ast.BinOp):
        result = merge(expression_taint(node.left, env, aliases),
                       expression_taint(node.right, env, aliases), node.lineno)
        return result.step("expression", node.lineno, transformed=True) if result else None
    if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.List, ast.Tuple, ast.Set,
                         ast.Dict, ast.BoolOp, ast.IfExp, ast.UnaryOp, ast.Compare)):
        result = None
        for child in ast.iter_child_nodes(node):
            result = merge(result, expression_taint(child, env, aliases), getattr(node, "lineno", 1))
        if result and isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            return result.step("interpolation", getattr(node, "lineno", 1), transformed=True)
        return result
    return None
