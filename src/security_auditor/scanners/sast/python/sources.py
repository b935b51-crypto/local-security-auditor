"""Conservative Python source taxonomy; recognition is AST-only."""

from __future__ import annotations

import ast
from enum import StrEnum

from .frontend import qualified_name


class SourceCategory(StrEnum):
    USER_INPUT = "USER_INPUT"
    HTTP_INPUT = "HTTP_INPUT"
    CLI_INPUT = "CLI_INPUT"
    ENVIRONMENT = "ENVIRONMENT"
    FILE_INPUT = "FILE_INPUT"
    NETWORK_INPUT = "NETWORK_INPUT"


def direct_source(node: ast.AST, aliases: dict[str, str]) -> SourceCategory | None:
    name = qualified_name(node, aliases)
    if name in {"sys.argv", "sys.stdin", "sys.stdin.buffer"}:
        return SourceCategory.CLI_INPUT
    if name in {"os.environ"}:
        return SourceCategory.ENVIRONMENT
    if name in {"request.args", "request.form", "request.json", "request.values",
                "request.GET", "request.POST", "request.query_params", "request.data"}:
        return SourceCategory.HTTP_INPUT
    if name and name.startswith("flask.request.") and name.rsplit(".", 1)[-1] in {
        "args", "form", "json", "values", "data",
    }:
        return SourceCategory.HTTP_INPUT
    if isinstance(node, ast.Call):
        call = qualified_name(node.func, aliases)
        if call in {"input", "builtins.input"}:
            return SourceCategory.USER_INPUT
        if call in {"os.getenv", "os.environ.get"}:
            return SourceCategory.ENVIRONMENT
        if call in {"request.get_json", "request.get_data", "flask.request.get_json", "flask.request.get_data"}:
            return SourceCategory.HTTP_INPUT
        if call and call.endswith(".parse_args"):
            return SourceCategory.CLI_INPUT
    return None
