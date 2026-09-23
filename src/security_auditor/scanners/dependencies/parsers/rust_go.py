"""Cargo TOML and bounded go.mod text extraction; no resolver calls."""

from __future__ import annotations

import re
import tomllib

from security_auditor.scanners.dependencies.models import DependencyGroup as G, Directness as D, VersionKind as V
from .common import ParseError, ParseResult, append_record, record, version_kind


def _toml(data: bytes) -> dict:
    try: obj = tomllib.loads(data.decode("utf-8-sig"))
    except (UnicodeError, tomllib.TOMLDecodeError): raise ParseError("DEPENDENCY_PARSE_FAILED") from None
    if not isinstance(obj, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
    return obj


def parse_rust_go(name: str, path: str, data: bytes) -> ParseResult:
    lower = name.lower()
    records = []
    diagnostics = []
    if lower == "cargo.toml":
        obj = _toml(data)
        for section, group in (("dependencies", G.RUNTIME), ("dev-dependencies", G.DEV), ("build-dependencies", G.BUILD)):
            values = obj.get(section, {})
            if not isinstance(values, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
            for package, spec in values.items():
                source = "registry"
                if isinstance(spec, dict):
                    package = spec.get("package", package)
                    if "path" in spec: source, kind, ver = "local_path", V.LOCAL_PATH, None
                    elif "git" in spec: source, kind, ver = "vcs", V.VCS, None
                    else:
                        raw = spec.get("version", "")
                        ver, kind = version_kind(raw, "crates.io") if isinstance(raw, str) else (None, V.UNRESOLVED)
                elif isinstance(spec, str):
                    ver, kind = version_kind(spec, "crates.io")
                else:
                    diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                item = record("crates.io", package, ver, kind, D.DIRECT, group, path, source=source,
                              constraint=spec if isinstance(spec, str) else None)
                append_record(records, diagnostics, item)
    elif lower == "cargo.lock":
        obj = _toml(data)
        packages = obj.get("package", [])
        if not isinstance(packages, list): raise ParseError("DEPENDENCY_PARSE_FAILED")
        for package in packages:
            if not isinstance(package, dict):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            name_, ver, source = package.get("name"), package.get("version"), package.get("source", "")
            if not isinstance(name_, str) or not isinstance(ver, str):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            if source and not isinstance(source, str):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            if source.startswith("registry+") and "crates.io" in source:
                kind, registry = V.EXACT, "registry"
            elif source.startswith("git+"):
                kind, registry = V.VCS, "vcs"
            else:
                kind, registry = V.LOCAL_PATH, "local_path"
            item = record("crates.io", name_, ver if kind is V.EXACT else None, kind,
                          D.UNKNOWN, G.UNKNOWN, path, source=registry, resolved=kind is V.EXACT)
            append_record(records, diagnostics, item)
    elif lower == "go.mod":
        try: lines = data.decode("utf-8-sig").splitlines()
        except UnicodeError: raise ParseError("DEPENDENCY_PARSE_FAILED") from None
        mode = ""
        replacements: set[str] = set()
        temporary = []
        for line_no, line in enumerate(lines, 1):
            if len(line) > 8192:
                diagnostics.append("DEPENDENCY_ENTRY_LIMIT_REACHED"); continue
            indirect = "// indirect" in line
            value = line.split("//", 1)[0].strip()
            if not value: continue
            if value in {"require (", "replace ("}:
                mode = value.split()[0]; continue
            if value == ")": mode = ""; continue
            kind = mode
            if value.startswith("require "): kind, value = "require", value[8:].strip()
            elif value.startswith("replace "): kind, value = "replace", value[8:].strip()
            if kind == "replace" and "=>" in value:
                replacements.add(value.split("=>", 1)[0].split()[0])
            if kind == "require":
                parts = value.split()
                if len(parts) >= 2:
                    temporary.append((parts[0], parts[1], line_no, indirect))
        for package, version, line_no, indirect in temporary:
            directness = D.TRANSITIVE if indirect else D.DIRECT
            if package in replacements:
                item = record("Go", package, None, V.LOCAL_PATH, directness, G.UNKNOWN,
                              path, line=line_no, source="replacement")
            else:
                ver, kind = version_kind(version, "Go")
                item = record("Go", package, ver, kind, directness, G.RUNTIME,
                              path, line=line_no, resolved=kind is V.EXACT)
            append_record(records, diagnostics, item)
    else:
        raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")
    return ParseResult(tuple(records), (), tuple(diagnostics))
