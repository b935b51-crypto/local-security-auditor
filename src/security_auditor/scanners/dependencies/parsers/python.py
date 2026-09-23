"""Static Python dependency manifests and TOML/JSON lockfiles."""

from __future__ import annotations

import json
import re
import tomllib

from security_auditor.scanners.dependencies.models import DependencyGroup as G, Directness as D, VersionKind as V
from .common import IncludeRef, ParseError, ParseResult, append_record, record, version_kind


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.*)$")


def _requirement(text: str, path: str, line: int | None, group: G = G.RUNTIME):
    text = text.split(";", 1)[0].strip()
    if " @ " in text:
        name, target = text.split(" @ ", 1)
        kind = V.VCS if target.lower().startswith(("git+", "git@")) else V.URL if target.lower().startswith(("https://", "http://")) else V.LOCAL_PATH
        return record("PyPI", name.strip(), None, kind, D.DIRECT, group, path, line=line, source=kind.value)
    match = _REQ.fullmatch(text)
    if match is None:
        return None
    name, spec = match.groups()
    version, kind = version_kind(spec, "PyPI")
    return record("PyPI", name, version, kind, D.DIRECT, group, path, line=line,
                  constraint=spec if spec else None)


def _toml(data: bytes):
    try:
        value = tomllib.loads(data.decode("utf-8-sig"))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (UnicodeError, tomllib.TOMLDecodeError, ValueError):
        raise ParseError("DEPENDENCY_PARSE_FAILED") from None


def parse_python(name: str, path: str, data: bytes) -> ParseResult:
    lower = name.lower()
    records = []
    includes = []
    diagnostics = []
    if lower.startswith("requirements") and lower.endswith(".txt"):
        try:
            lines = data.decode("utf-8-sig").splitlines()
        except UnicodeError:
            raise ParseError("DEPENDENCY_PARSE_FAILED") from None
        for line_no, line in enumerate(lines, 1):
            if len(line) > 8192:
                diagnostics.append("DEPENDENCY_ENTRY_LIMIT_REACHED")
                continue
            value = (line.strip() if "#egg=" in line else line.partition("#")[0].strip())
            if not value:
                continue
            if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
                includes.append(IncludeRef(value.split(None, 1)[1].strip(), value.startswith(("-c ", "--constraint "))))
                continue
            if value.startswith(("-r", "-c")) and len(value) > 2 and not value[2].isspace():
                includes.append(IncludeRef(value[2:].strip(), value.startswith("-c")))
                continue
            if value.startswith("-e ") or value.startswith("--editable "):
                # Editable targets are local/VCS and never sent to a registry lookup.
                target = value.split(None, 1)[1]
                egg = target.rpartition("#egg=")[2]
                if egg:
                    item = record("PyPI", egg, None, V.VCS if "git" in target[:8] else V.LOCAL_PATH,
                                  D.DIRECT, G.RUNTIME, path, line=line_no, source="editable")
                    append_record(records, diagnostics, item)
                else:
                    diagnostics.append("DEPENDENCY_UNRESOLVED_VERSION")
                continue
            if value.startswith("-"):
                diagnostics.append("DEPENDENCY_UNSUPPORTED_FORMAT")
                continue
            item = _requirement(value, path, line_no)
            append_record(records, diagnostics, item)
        return ParseResult(tuple(records), tuple(includes), tuple(diagnostics))
    if lower in {"pyproject.toml", "pipfile", "uv.lock", "poetry.lock"}:
        obj = _toml(data)
        if lower == "pyproject.toml":
            project = obj.get("project", {})
            if not isinstance(project, dict):
                raise ParseError("DEPENDENCY_PARSE_FAILED")
            for value in project.get("dependencies", []):
                if not isinstance(value, str):
                    diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                item = _requirement(value, path, None)
                append_record(records, diagnostics, item)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    if not isinstance(values, list):
                        diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                    for value in values:
                        if isinstance(value, str):
                            item = _requirement(value, path, None, G.OPTIONAL)
                            append_record(records, diagnostics, item)
            poetry = obj.get("tool", {}).get("poetry", {}) if isinstance(obj.get("tool", {}), dict) else {}
            if isinstance(poetry, dict):
                for name, spec in poetry.get("dependencies", {}).items():
                    if name.lower() == "python": continue
                    if isinstance(spec, dict):
                        if "path" in spec or "git" in spec or "url" in spec:
                            kind = V.LOCAL_PATH if "path" in spec else V.VCS if "git" in spec else V.URL
                            item = record("PyPI", name, None, kind, D.DIRECT, G.RUNTIME, path, source=kind.value)
                        else:
                            raw = spec.get("version", "")
                            ver, kind = version_kind(raw, "PyPI") if isinstance(raw, str) else (None, V.UNRESOLVED)
                            item = record("PyPI", name, ver, kind, D.DIRECT, G.RUNTIME, path, constraint=raw if isinstance(raw,str) else None)
                    elif isinstance(spec, str):
                        ver, kind = version_kind(spec, "PyPI")
                        item = record("PyPI", name, ver, kind, D.DIRECT, G.RUNTIME, path, constraint=spec)
                    else: item = None
                    append_record(records, diagnostics, item)
        elif lower == "pipfile":
            for section, group in (("packages", G.RUNTIME), ("dev-packages", G.DEV)):
                values = obj.get(section, {})
                if not isinstance(values, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
                for name, spec in values.items():
                    if isinstance(spec, dict):
                        if "git" in spec or "path" in spec or "file" in spec:
                            kind = V.VCS if "git" in spec else V.LOCAL_PATH if "path" in spec else V.URL
                            ver = None
                        else:
                            raw = spec.get("version", "")
                            ver, kind = version_kind(raw, "PyPI") if isinstance(raw, str) else (None, V.UNRESOLVED)
                    else:
                        ver, kind = version_kind(spec, "PyPI") if isinstance(spec, str) else (None, V.UNRESOLVED)
                    item = record("PyPI", name, ver, kind, D.DIRECT, group, path,
                                  constraint=spec if isinstance(spec, str) else None,
                                  source="registry" if kind in {V.EXACT, V.CONSTRAINT, V.UNRESOLVED} else kind.value)
                    append_record(records, diagnostics, item)
        else:
            values = obj.get("package", [])
            if not isinstance(values, list): raise ParseError("DEPENDENCY_PARSE_FAILED")
            for package in values:
                if not isinstance(package, dict):
                    diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                name, ver = package.get("name"), package.get("version")
                if not isinstance(name, str) or not isinstance(ver, str):
                    diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                source = package.get("source", {})
                source_type = source.get("type") if isinstance(source, dict) else None
                nonregistry = isinstance(source, dict) and ("git" in source or "path" in source or "editable" in source or "url" in source
                                                              or source_type in {"git", "directory", "file", "url"})
                kind = (V.VCS if nonregistry and ("git" in source or source_type == "git") else
                        V.LOCAL_PATH if nonregistry and ("path" in source or "editable" in source or source_type in {"directory", "file"}) else
                        V.URL if nonregistry else V.EXACT)
                item = record("PyPI", name, ver if kind is V.EXACT else None, kind, D.UNKNOWN, G.UNKNOWN,
                              path, source="registry" if kind is V.EXACT else kind.value, resolved=kind is V.EXACT)
                append_record(records, diagnostics, item)
        return ParseResult(tuple(records), (), tuple(diagnostics))
    if lower == "pipfile.lock":
        try: obj = json.loads(data)
        except (ValueError, UnicodeError): raise ParseError("DEPENDENCY_PARSE_FAILED") from None
        if not isinstance(obj, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
        for section, group in (("default", G.RUNTIME), ("develop", G.DEV)):
            values = obj.get(section, {})
            if not isinstance(values, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
            for name, spec in values.items():
                if not isinstance(spec, dict): continue
                raw = spec.get("version")
                ver, kind = version_kind(raw, "PyPI") if isinstance(raw, str) else (None, V.UNRESOLVED)
                if "git" in spec or "path" in spec or "file" in spec:
                    kind = V.VCS if "git" in spec else V.LOCAL_PATH if "path" in spec else V.URL
                    ver = None
                item = record("PyPI", name, ver, kind, D.UNKNOWN, group, path,
                              source="registry" if kind in {V.EXACT, V.CONSTRAINT, V.UNRESOLVED} else kind.value,
                              resolved=kind is V.EXACT)
                append_record(records, diagnostics, item)
        return ParseResult(tuple(records))
    raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")
