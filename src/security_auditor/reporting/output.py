"""Output-path validation and same-directory atomic UTF-8 writes."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile

_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


class ReportOutputError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _validate(path: Path, *, force: bool) -> None:
    raw = os.fspath(path)
    if "\x00" in raw or (os.name == "nt" and (raw.startswith("\\\\") or ":" in path.name)):
        raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH")
    if os.name == "nt" and any(part.name.rstrip(" .").split(".")[0].upper() in _RESERVED or
                               part.name.endswith((" ", ".")) for part in (path, *path.parents)
                               if part.name):
        raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH")
    parent = path.parent
    if not parent.is_dir():
        raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH")
    for node in (parent, *parent.parents):
        try:
            info = node.lstat()
        except OSError:
            raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH") from None
        if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH") from None
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise ReportOutputError("REPORT_OUTPUT_UNSAFE_PATH")
    if not force:
        raise ReportOutputError("REPORT_OUTPUT_EXISTS")


def write_text(path: Path, text: str, *, force: bool = False) -> None:
    """Never create a partial final file; parent must already exist."""
    destination = path.absolute()
    _validate(destination, force=force)
    temp: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".security-auditor-", suffix=".tmp",
                                             dir=destination.parent)
        temp = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        _validate(destination, force=force)
        if force:
            os.replace(temp, destination)
        else:
            # Exclusive hard-link creation avoids a check/create overwrite race.
            os.link(temp, destination)
    except ReportOutputError:
        raise
    except FileExistsError:
        raise ReportOutputError("REPORT_OUTPUT_EXISTS") from None
    except (OSError, UnicodeError):
        raise ReportOutputError("REPORT_ATOMIC_WRITE_FAILED") from None
    finally:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
