"""Neutral Python AST behavior signals; no call or payload is executed."""

from __future__ import annotations

import ast

from security_auditor.core.models import Confidence
from security_auditor.scanners.sast.python.frontend import import_aliases, literal_string, qualified_name, keyword_value
from .models import BehaviorHit, LocalCorrelation


PROCESS = {"os.system", "os.popen", "os.startfile", "subprocess.run", "subprocess.call",
           "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
NETWORK = {"requests.get", "requests.post", "requests.put", "requests.request",
           "httpx.get", "httpx.post", "urllib.request.urlopen", "urllib.request.urlretrieve"}
DELETE = {"os.remove", "os.unlink", "pathlib.Path.unlink", "shutil.rmtree"}
REGISTRY = {"winreg.SetValue", "winreg.SetValueEx", "winreg.CreateKey", "winreg.CreateKeyEx",
            "winreg.DeleteValue", "winreg.DeleteKey"}
DLL = {"ctypes.CDLL", "ctypes.WinDLL", "ctypes.OleDLL", "ctypes.PyDLL"}
DYNAMIC = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
WINDOWS_TOOLS = {"certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "wmic"}
_CREDENTIAL_PATHS = ("/.aws/credentials", "/.ssh/id_", "/login data", "/local state",
                     "/appdata/local/google/chrome/user data", "/appdata/roaming/mozilla/firefox")


def _tool(command: str | None) -> str | None:
    if not command:
        return None
    first = command.strip().strip('"\'').replace("\\", "/").split(" ", 1)[0]
    return first.rsplit("/", 1)[-1].lower().removesuffix(".exe")


def _command_literal(call: ast.Call) -> str | None:
    if not call.args:
        return None
    arg = call.args[0]
    if isinstance(arg, (ast.List, ast.Tuple)) and arg.elts:
        return literal_string(arg.elts[0])
    return literal_string(arg)


def _sensitive_path(value: str) -> bool:
    normalized = value.replace("\\", "/").lower()
    return any(part in normalized for part in _CREDENTIAL_PATHS)


def _download_write(call: ast.Call, downloaded: set[str]) -> str | None:
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "write" and call.args):
        return None
    receiver = call.func.value
    if not (isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "open" and len(receiver.args) >= 2):
        return None
    path = literal_string(receiver.args[0])
    mode = literal_string(receiver.args[1])
    value = call.args[0]
    if (path and mode and "w" in mode and isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name) and value.value.id in downloaded
            and value.attr in {"content", "text"}):
        return path
    return None


def scan_python_behavior(tree: ast.Module) -> tuple[BehaviorHit, ...]:
    hits: list[BehaviorHit] = []

    def emit(rule: str, node: ast.AST, detail: str = "python_ast",
             confidence: Confidence = Confidence.HIGH) -> None:
        hits.append(BehaviorHit(f"BEHAVIOR.{rule}", getattr(node, "lineno", 1),
                                getattr(node, "col_offset", 0) + 1, detail, confidence))

    def scope(statements: list[ast.stmt], inherited: dict[str, str]) -> None:
        aliases = import_aliases(statements, inherited)
        nodes: list[ast.AST] = []
        nested: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
        parents: dict[int, ast.AST] = {}
        stack: list[ast.AST] = list(reversed(statements))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                nested.append(node)
                continue
            nodes.append(node)
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node
                stack.append(child)
        calls = sorted((node for node in nodes if isinstance(node, ast.Call)),
                       key=lambda item: (item.lineno, item.col_offset))
        local = LocalCorrelation()
        for node in nodes:
            if isinstance(node, ast.Attribute) and qualified_name(node, aliases) == "os.environ":
                emit("ENVIRONMENT_READ", node)
        for call in calls:
            name = qualified_name(call.func, aliases)
            if name in PROCESS:
                emit("PROCESS_EXEC", call)
                if name in {"os.system", "os.popen"} or (
                    isinstance(keyword_value(call, "shell"), ast.Constant)
                    and keyword_value(call, "shell").value is True
                ):
                    emit("SHELL_EXEC", call)
                command = _command_literal(call)
                tool = _tool(command)
                if tool in {"powershell", "pwsh"}:
                    emit("POWERSHELL_EXEC", call, "powershell")
                    flags = [literal_string(item) for item in call.args[0].elts] if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)) else [command]
                    if any(item and (item.lower() in {"-enc", "-encodedcommand"}
                                     or "-enc " in item.lower() or "-encodedcommand " in item.lower())
                           for item in flags):
                        emit("ENCODED_COMMAND", call, "powershell")
                elif tool == "cmd":
                    emit("CMD_EXEC", call, "cmd")
                elif tool in WINDOWS_TOOLS:
                    emit("WINDOWS_TOOL", call, tool)
                if tool == "schtasks" and command and any(flag in command.lower() for flag in ("/create", "/change", "/delete")):
                    emit("SCHEDULED_TASK", call, "schtasks")
                if tool == "sc" and command and any(flag in command.lower() for flag in ("create", "config", "delete", "start", "stop")):
                    emit("SERVICE_MODIFICATION", call, "service_tool")
                if tool == "reg" and command and " add " in command.lower():
                    emit("REGISTRY_WRITE", call, "registry_tool")
                if tool == "taskkill":
                    emit("PROCESS_TERMINATION", call, "taskkill")
                if tool == "netsh" and command and ("firewall" in command.lower() or "advfirewall" in command.lower()):
                    emit("SECURITY_CONTROL", call, "firewall_tool")
                launched = _command_literal(call)
                if launched and launched in local.written_paths:
                    emit("DOWNLOAD_EXECUTE", call, "same_local_file", Confidence.MEDIUM)
                flags = keyword_value(call, "creationflags")
                if flags and any(isinstance(part, ast.Name) and part.id == "CREATE_NO_WINDOW"
                                 for part in ast.walk(flags)):
                    emit("HIDDEN_PROCESS", call)
            if name in DYNAMIC:
                emit("DYNAMIC_CODE", call)
            if name in NETWORK or (name and name.endswith(".connect") and name.startswith("socket")):
                emit("NETWORK_REQUEST", call)
                parent = parents.get(id(call))
                if isinstance(parent, ast.Assign) and parent.value is call:
                    local.downloaded_names.update(target.id for target in parent.targets if isinstance(target, ast.Name))
            written = _download_write(call, local.downloaded_names)
            if written:
                local.written_paths.add(written)
            if name in DELETE or (isinstance(call.func, ast.Attribute) and call.func.attr in {"unlink", "rmtree"}):
                emit("RECURSIVE_DELETE" if name == "shutil.rmtree" or name and name.endswith(".rmtree") else "FILE_DELETE", call)
            if name in REGISTRY:
                emit("REGISTRY_WRITE", call)
                if any(isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                       and ("runonce" in arg.value.lower() or "currentversion\\run" in arg.value.lower())
                       for arg in call.args):
                    emit("STARTUP_PERSISTENCE", call)
            if name in DLL:
                emit("DLL_LOAD", call)
            if name in {"os.kill", "os.killpg", "psutil.Process.kill", "psutil.Process.terminate"}:
                emit("PROCESS_TERMINATION", call)
            if name in {"os.getenv", "os.environ.get"}:
                emit("ENVIRONMENT_READ", call)
            if name in {"win32cred.CredRead", "win32crypt.CryptUnprotectData"}:
                emit("CREDENTIAL_ACCESS", call)
            if name in {"open", "builtins.open", "pathlib.Path", "Path"} and call.args:
                path = literal_string(call.args[0])
                if path and _sensitive_path(path):
                    emit("CREDENTIAL_ACCESS", call)
        for item in nested:
            scope(item.body, aliases)

    scope(tree.body, {})
    unique = {(hit.rule_id, hit.line, hit.column): hit for hit in hits}
    return tuple(sorted(unique.values(), key=lambda hit: (hit.line, hit.column, hit.rule_id)))
