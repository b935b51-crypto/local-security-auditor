"""Narrow guard signals; none is a general proof of safety."""

from __future__ import annotations

import ast

from .frontend import qualified_name


def guard_kind(node: ast.Call, aliases: dict[str, str]) -> str | None:
    name = qualified_name(node.func, aliases)
    if name == "shlex.quote":
        return "shell_quote"
    if name in {"os.path.basename", "pathlib.Path.name"}:
        return "path_component"
    if name and name.endswith(".relative_to"):
        return "path_boundary"
    return None
