"""Known Python sink taxonomy. Classification alone never makes a vulnerability."""

from __future__ import annotations

import ast
from enum import StrEnum

from .frontend import qualified_name


class SinkKind(StrEnum):
    COMMAND = "command"
    SQL = "sql"
    PATH = "path"
    DESERIALIZATION = "deserialization"
    DYNAMIC_CODE = "dynamic_code"
    TLS_CONFIG = "tls_config"
    TEMP_FILE = "temp_file"
    YAML = "yaml"


COMMAND = {"os.system", "os.popen", "subprocess.run", "subprocess.call",
           "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
DESERIALIZATION = {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load"}
DYNAMIC_CODE = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
NETWORK_TLS = {"requests.get", "requests.post", "requests.put", "requests.patch",
               "requests.delete", "requests.request", "httpx.get", "httpx.post",
               "httpx.put", "httpx.delete"}
PATH = {"open", "builtins.open", "io.open", "os.remove", "os.unlink", "os.rename",
        "os.replace", "shutil.rmtree"}


def sink_kind(call: ast.Call, aliases: dict[str, str]) -> SinkKind | None:
    name = qualified_name(call.func, aliases)
    if name in COMMAND:
        return SinkKind.COMMAND
    if name in DESERIALIZATION:
        return SinkKind.DESERIALIZATION
    if name in DYNAMIC_CODE:
        return SinkKind.DYNAMIC_CODE
    if name == "yaml.load":
        return SinkKind.YAML
    if name in NETWORK_TLS:
        return SinkKind.TLS_CONFIG
    if name == "tempfile.mktemp":
        return SinkKind.TEMP_FILE
    if name in PATH or (isinstance(call.func, ast.Attribute) and call.func.attr in {
        "open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink",
    }):
        return SinkKind.PATH
    if name and name.rsplit(".", 1)[-1] in {"execute", "executemany", "raw"}:
        return SinkKind.SQL
    return None
