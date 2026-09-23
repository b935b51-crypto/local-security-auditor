"""Static package.json and package-lock v1/v2/v3 extraction."""

from __future__ import annotations

import json

from security_auditor.scanners.dependencies.models import DependencyGroup as G, Directness as D, VersionKind as V
from .common import ParseError, ParseResult, append_record, record, version_kind


_GROUPS = (("dependencies", G.RUNTIME), ("devDependencies", G.DEV),
           ("optionalDependencies", G.OPTIONAL), ("peerDependencies", G.PEER))


def _load(data: bytes) -> dict:
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeError):
        raise ParseError("DEPENDENCY_PARSE_FAILED") from None
    if not isinstance(obj, dict):
        raise ParseError("DEPENDENCY_PARSE_FAILED")
    return obj


def _package_name(logical_path: str) -> str | None:
    if "node_modules/" not in logical_path:
        return None
    return logical_path.rsplit("node_modules/", 1)[-1]


def parse_npm(name: str, path: str, data: bytes) -> ParseResult:
    if name.lower() not in {"package.json", "package-lock.json"}:
        raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")
    obj = _load(data)
    records = []
    diagnostics = []
    if name.lower() == "package.json":
        for section, group in _GROUPS:
            values = obj.get(section, {})
            if not isinstance(values, dict):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            for package, spec in values.items():
                if not isinstance(spec, str):
                    diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
                ver, kind = version_kind(spec, "npm")
                item = record("npm", package, ver, kind, D.DIRECT, group, path, constraint=spec)
                append_record(records, diagnostics, item)
        return ParseResult(tuple(records), (), tuple(diagnostics))
    if name.lower() != "package-lock.json":
        raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")
    lock_version = obj.get("lockfileVersion")
    if type(lock_version) is not int or lock_version not in (1, 2, 3):
        raise ParseError("DEPENDENCY_UNSUPPORTED_FORMAT")
    packages = obj.get("packages")
    if isinstance(packages, dict):
        root = packages.get("", {})
        direct_names = set()
        if isinstance(root, dict):
            for section, _ in _GROUPS:
                values = root.get(section, {})
                if isinstance(values, dict): direct_names.update(values)
        for logical_path, entry in packages.items():
            if not isinstance(logical_path, str) or not isinstance(entry, dict) or not logical_path:
                continue
            package = _package_name(logical_path)
            if package is None:
                diagnostics.append("DEPENDENCY_UNSUPPORTED_FORMAT"); continue
            raw = entry.get("version")
            if not isinstance(raw, str):
                diagnostics.append("DEPENDENCY_UNRESOLVED_VERSION"); continue
            resolved_url = entry.get("resolved", "")
            if not isinstance(resolved_url, str):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            if entry.get("link") is True or raw.startswith(("file:", "link:")) or resolved_url.startswith(("file:", "link:")):
                kind, version = V.LOCAL_PATH, None
            elif raw.startswith(("git+", "git://", "github:")) or resolved_url.startswith(("git+", "git://", "github:")):
                kind, version = V.VCS, None
            elif raw.startswith(("http://", "https://")) or (resolved_url.startswith(("http://", "https://"))
                 and not resolved_url.startswith("https://registry.npmjs.org/")):
                kind, version = V.URL, None
            else:
                kind, version = V.EXACT, raw
            direct = (D.DIRECT if logical_path == f"node_modules/{package}" and package in direct_names else
                      D.UNKNOWN if logical_path == f"node_modules/{package}" else D.TRANSITIVE)
            group = G.DEV if entry.get("dev") is True else G.OPTIONAL if entry.get("optional") is True else G.UNKNOWN
            item = record("npm", package, version, kind, direct, group, path,
                          source="registry" if kind is V.EXACT else kind.value,
                          logical_path=logical_path, resolved=kind is V.EXACT)
            append_record(records, diagnostics, item)
    elif lock_version == 1:
        root = obj.get("dependencies", {})
        if not isinstance(root, dict): raise ParseError("DEPENDENCY_PARSE_FAILED")
        stack = [(package, entry, f"node_modules/{package}", D.DIRECT) for package, entry in root.items()]
        seen = 0
        while stack:
            package, entry, logical_path, direct = stack.pop()
            seen += 1
            if seen > 20000:
                diagnostics.append("DEPENDENCY_ENTRY_LIMIT_REACHED"); break
            if not isinstance(entry, dict):
                diagnostics.append("DEPENDENCY_PARSE_FAILED"); continue
            raw = entry.get("version")
            if isinstance(raw, str):
                version, kind = version_kind(raw, "npm")
                item = record("npm", package, version, kind, direct,
                              G.DEV if entry.get("dev") else G.UNKNOWN, path, logical_path=logical_path,
                              source="registry" if kind in {V.EXACT, V.CONSTRAINT, V.UNRESOLVED} else kind.value,
                              resolved=kind is V.EXACT)
                append_record(records, diagnostics, item)
            children = entry.get("dependencies", {})
            if isinstance(children, dict):
                for child, child_entry in children.items():
                    stack.append((child, child_entry, logical_path + "/node_modules/" + child, D.TRANSITIVE))
    else:
        raise ParseError("DEPENDENCY_PARSE_FAILED")
    return ParseResult(tuple(records), (), tuple(diagnostics))
