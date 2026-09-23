"""Bounded intraprocedural Python taint engine. No target evaluation occurs."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from time import monotonic

from security_auditor.core.models import Confidence
from .frontend import import_aliases, keyword_value, qualified_name
from .sinks import COMMAND, SinkKind, sink_kind
from .sources import SourceCategory
from .taint import Taint, expression_taint, merge


@dataclass(frozen=True, slots=True)
class SASTHit:
    rule_id: str
    line: int
    column: int
    anchor: str
    sink: str
    taint: Taint | None = None
    confidence: Confidence | None = None


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    hits: tuple[SASTHit, ...]
    diagnostics: tuple[str, ...]


class _LimitReached(Exception):
    pass


class PythonTaintAnalyzer:
    def __init__(self, *, max_function_nodes: int, max_hits: int, deadline: float):
        self.max_function_nodes = max_function_nodes
        self.max_hits = max_hits
        self.deadline = deadline
        self.hits: list[SASTHit] = []
        self.diagnostics: set[str] = set()

    def analyze(self, tree: ast.Module) -> AnalysisResult:
        aliases = import_aliases(tree.body)
        self._block(tree.body, {}, aliases)
        return AnalysisResult(tuple(self.hits), tuple(sorted(self.diagnostics)))

    def _emit(self, rule_id: str, call: ast.Call, kind: SinkKind, taint: Taint | None = None,
              confidence: Confidence | None = None) -> None:
        if len(self.hits) >= self.max_hits:
            raise _LimitReached()
        self.hits.append(SASTHit(rule_id, call.lineno, call.col_offset + 1,
                                 kind.value, kind.value, taint, confidence))

    def _check_call(self, call: ast.Call, env: dict[str, Taint], aliases: dict[str, str]) -> None:
        kind = sink_kind(call, aliases)
        if kind is None:
            return
        name = qualified_name(call.func, aliases)
        first = call.args[0] if call.args else None
        argument = first
        if kind is SinkKind.PATH and isinstance(call.func, ast.Attribute) and name not in {
            "open", "builtins.open", "io.open", "os.remove", "os.unlink", "os.rename",
            "os.replace", "shutil.rmtree",
        }:
            argument = call.func.value
        taint = expression_taint(argument, env, aliases)
        if kind is SinkKind.COMMAND and taint:
            shell = keyword_value(call, "shell")
            uses_shell = name in {"os.system", "os.popen"} or (
                isinstance(shell, ast.Constant) and shell.value is True
            )
            if uses_shell and "shell_quote" not in taint.guards:
                confidence = Confidence.MEDIUM if taint.category is SourceCategory.ENVIRONMENT else None
                self._emit("SAST.PYTHON.COMMAND_INJECTION", call, kind, taint, confidence)
        elif kind is SinkKind.SQL and taint and taint.transformed:
            # A separate parameters argument cannot undo interpolation already
            # performed while constructing the SQL string.
            self._emit("SAST.PYTHON.SQL_INJECTION", call, kind, taint)
        elif kind is SinkKind.PATH and taint:
            if "path_boundary" not in taint.guards:
                confidence = Confidence.LOW if "path_component" in taint.guards else None
                if taint.category is SourceCategory.ENVIRONMENT:
                    confidence = Confidence.LOW
                self._emit("SAST.PYTHON.PATH_TRAVERSAL", call, kind, taint, confidence)
        elif kind is SinkKind.DESERIALIZATION and taint:
            self._emit("SAST.PYTHON.UNSAFE_DESERIALIZATION", call, kind, taint)
        elif kind is SinkKind.DYNAMIC_CODE and taint:
            self._emit("SAST.PYTHON.DYNAMIC_CODE_EXEC", call, kind, taint)
        elif kind is SinkKind.TLS_CONFIG:
            verify = keyword_value(call, "verify")
            if isinstance(verify, ast.Constant) and verify.value is False:
                self._emit("SAST.PYTHON.TLS_VERIFY_DISABLED", call, kind)
        elif kind is SinkKind.YAML:
            loader = keyword_value(call, "Loader")
            safe = qualified_name(loader, aliases) if loader else None
            if (safe not in {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"}
                    and name == "yaml.load"):
                self._emit("SAST.PYTHON.UNSAFE_YAML_LOAD", call, kind, taint)
        elif kind is SinkKind.TEMP_FILE:
            self._emit("SAST.PYTHON.INSECURE_TEMP_FILE", call, kind)

    def _scan_expr(self, expr: ast.AST | None, env: dict[str, Taint], aliases: dict[str, str]) -> None:
        if expr is None:
            return
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                try:
                    self._check_call(node, env, aliases)
                except _LimitReached:
                    raise
                except Exception:
                    self.diagnostics.add("SAST_RULE_ERROR")

    @staticmethod
    def _bind(target: ast.AST, taint: Taint | None, env: dict[str, Taint], line: int) -> None:
        if isinstance(target, ast.Name):
            if taint:
                env[target.id] = taint.step("assignment", line)
            else:
                env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                PythonTaintAnalyzer._bind(item, taint, env, line)

    @staticmethod
    def _merge_env(left: dict[str, Taint], right: dict[str, Taint], line: int) -> dict[str, Taint]:
        output: dict[str, Taint] = {}
        for key in sorted(left.keys() | right.keys()):
            value = merge(left.get(key), right.get(key), line)
            if value:
                output[key] = value
        return output

    def _function(self, stmt: ast.FunctionDef | ast.AsyncFunctionDef,
                  aliases: dict[str, str]) -> None:
        count = 0
        for _ in ast.walk(stmt):
            count += 1
            if count > self.max_function_nodes:
                self.diagnostics.add("SAST_FUNCTION_LIMIT_REACHED")
                return
        local_aliases = import_aliases(stmt.body, aliases)
        env: dict[str, Taint] = {}
        route = any(isinstance(decorator, (ast.Call, ast.Attribute)) and
                    (getattr(decorator.func, "attr", None) if isinstance(decorator, ast.Call)
                     else getattr(decorator, "attr", None)) in {"get", "post", "put", "delete", "patch", "route"}
                    for decorator in stmt.decorator_list)
        if route:
            for arg in (*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs):
                if arg.arg not in {"self", "cls", "request"}:
                    env[arg.arg] = Taint(SourceCategory.HTTP_INPUT, arg.lineno,
                                         (("HTTP_INPUT", arg.lineno),))
        self._block(stmt.body, env, local_aliases)

    def _block(self, statements: list[ast.stmt], env: dict[str, Taint],
               aliases: dict[str, str]) -> None:
        for stmt in statements:
            if monotonic() >= self.deadline:
                self.diagnostics.add("SAST_ANALYSIS_TIMEOUT")
                return
            try:
                self._statement(stmt, env, aliases)
            except _LimitReached:
                self.diagnostics.add("SAST_FINDING_LIMIT_REACHED")
                return
            except Exception:
                self.diagnostics.add("SAST_RULE_ERROR")

    def _statement(self, stmt: ast.stmt, env: dict[str, Taint], aliases: dict[str, str]) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function(stmt, aliases)
            return
        if isinstance(stmt, ast.ClassDef):
            self._block(stmt.body, {}, dict(aliases))
            return
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            aliases.update(import_aliases([stmt], aliases))
            return
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = stmt.value
            self._scan_expr(value, env, aliases)
            taint = expression_taint(value, env, aliases)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                self._bind(target, taint, env, stmt.lineno)
                if isinstance(target, ast.Name):
                    aliases.pop(target.id, None)
            return
        if isinstance(stmt, ast.AugAssign):
            self._scan_expr(stmt.value, env, aliases)
            current = expression_taint(stmt.target, env, aliases)
            added = expression_taint(stmt.value, env, aliases)
            value = merge(current, added, stmt.lineno)
            self._bind(stmt.target, value.step("augmented_assignment", stmt.lineno, transformed=True) if value else None,
                       env, stmt.lineno)
            return
        if isinstance(stmt, ast.If):
            self._scan_expr(stmt.test, env, aliases)
            left, right = dict(env), dict(env)
            self._block(stmt.body, left, dict(aliases))
            self._block(stmt.orelse, right, dict(aliases))
            env.clear()
            env.update(self._merge_env(left, right, stmt.lineno))
            return
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                self._scan_expr(stmt.iter, env, aliases)
                body_env = dict(env)
                self._bind(stmt.target, expression_taint(stmt.iter, env, aliases), body_env, stmt.lineno)
            else:
                self._scan_expr(stmt.test, env, aliases)
                body_env = dict(env)
            self._block(stmt.body, body_env, dict(aliases))
            env.update(self._merge_env(env, body_env, stmt.lineno))
            self._block(stmt.orelse, env, dict(aliases))
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self._scan_expr(item.context_expr, env, aliases)
                if item.optional_vars:
                    self._bind(item.optional_vars, expression_taint(item.context_expr, env, aliases), env, stmt.lineno)
            self._block(stmt.body, env, aliases)
            return
        if isinstance(stmt, ast.Try):
            base = dict(env)
            self._block(stmt.body, base, dict(aliases))
            for handler in stmt.handlers:
                branch = dict(env)
                self._block(handler.body, branch, dict(aliases))
                base = self._merge_env(base, branch, stmt.lineno)
            self._block(stmt.orelse, base, dict(aliases))
            self._block(stmt.finalbody, base, dict(aliases))
            env.clear()
            env.update(base)
            return
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._scan_expr(child, env, aliases)
