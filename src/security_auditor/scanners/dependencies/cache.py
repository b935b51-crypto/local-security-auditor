"""Tool-local JSON cache of normalized advisory lookups only."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from security_auditor.core.models import Severity
from security_auditor.scanners._common import safe_finding_path
from .models import LookupResult, LookupStatus, Vulnerability, safe_exact_version
from .providers import _safe_reference


SCHEMA = "osv-normalized-v1"
MAX_ENTRY_BYTES = 128 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class CacheError(Exception):
    pass


def default_cache_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA") if os.name == "nt" else None
    base = Path(local) if local else Path.home() / ".cache"
    return base / "local-security-auditor" / "vulnerability"


class VulnerabilityCache:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or default_cache_dir()

    def validate_outside(self, root: Path) -> None:
        try:
            if self.directory.resolve().is_relative_to(root.resolve()):
                raise CacheError("DEPENDENCY_CACHE_WRITE_FAILED")
            if self.directory.exists() and self.directory.is_symlink():
                raise CacheError("DEPENDENCY_CACHE_WRITE_FAILED")
        except (OSError, RuntimeError, ValueError):
            raise CacheError("DEPENDENCY_CACHE_WRITE_FAILED") from None

    def _path(self, key: tuple[str, str, str]) -> Path:
        raw = json.dumps([SCHEMA, *key], separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return self.directory / (hashlib.sha256(raw).hexdigest() + ".json")

    def read(self, key: tuple[str, str, str], ttl_seconds: int) -> LookupResult | None:
        path = self._path(key)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise CacheError("DEPENDENCY_CACHE_READ_FAILED") from None
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ENTRY_BYTES:
            raise CacheError("DEPENDENCY_CACHE_CORRUPT")
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)):
                    raise ValueError()
                raw = stream.read(MAX_ENTRY_BYTES + 1)
            if len(raw) > MAX_ENTRY_BYTES:
                raise ValueError()
            obj = json.loads(raw)
            if not isinstance(obj, dict) or obj.get("schema") != SCHEMA or obj.get("key") != list(key):
                raise ValueError()
            fetched = obj.get("fetched_at")
            if type(fetched) not in (int, float) or fetched < 0 or fetched > time.time() + 300:
                raise ValueError()
            status = LookupStatus(obj["status"])
            if status not in {LookupStatus.MATCHED, LookupStatus.NO_MATCH}:
                raise ValueError()
            values = obj.get("vulnerabilities", [])
            if not isinstance(values, list) or len(values) > 1000:
                raise ValueError()
            vulns = []
            for item in values:
                if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                        or not _ID.fullmatch(item["id"]) or safe_finding_path(item["id"]) != item["id"]):
                    raise ValueError()
                if not isinstance(item.get("aliases", []), list) or not isinstance(item.get("references", []), list):
                    raise ValueError()
                vuln = Vulnerability(**{**item, "severity": Severity(item["severity"]),
                                        "aliases": tuple(item.get("aliases", [])),
                                        "fixed_versions": tuple(item.get("fixed_versions", [])),
                                        "references": tuple(item.get("references", []))})
                if (len(vuln.aliases) > 100 or len(vuln.references) > 20 or len(vuln.fixed_versions) > 40
                        or not isinstance(vuln.summary, str) or len(vuln.summary) > 300
                        or safe_finding_path(vuln.summary) != vuln.summary
                        or any(not isinstance(x, str) or not _ID.fullmatch(x)
                               or safe_finding_path(x) != x for x in vuln.aliases)
                        or any(_safe_reference(x) != x for x in vuln.references)
                        or any(not safe_exact_version(x) for x in vuln.fixed_versions)
                        or not isinstance(vuln.severity_source, str) or len(vuln.severity_source) > 100
                        or (vuln.cvss_vector is not None and
                            (not isinstance(vuln.cvss_vector, str) or len(vuln.cvss_vector) > 200))):
                    raise ValueError()
                vulns.append(vuln)
            stale = time.time() - fetched > ttl_seconds
            return LookupResult(key, status, tuple(vulns), stale)
        except (OSError, ValueError, TypeError, KeyError):
            raise CacheError("DEPENDENCY_CACHE_CORRUPT") from None

    def write(self, result: LookupResult) -> None:
        if result.status not in {LookupStatus.MATCHED, LookupStatus.NO_MATCH}:
            return
        payload = json.dumps({"schema": SCHEMA, "key": list(result.key), "fetched_at": time.time(),
                              "status": result.status.value,
                              "vulnerabilities": [asdict(v) for v in result.vulnerabilities]},
                             separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(payload) > MAX_ENTRY_BYTES:
            raise CacheError("DEPENDENCY_CACHE_WRITE_FAILED")
        temp = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.NamedTemporaryFile(mode="wb", dir=self.directory, prefix=".lookup-", delete=False) as stream:
                temp = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self._path(result.key))
        except OSError:
            raise CacheError("DEPENDENCY_CACHE_WRITE_FAILED") from None
        finally:
            if temp is not None:
                try: temp.unlink(missing_ok=True)
                except OSError: pass
