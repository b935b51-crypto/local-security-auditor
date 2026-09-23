"""Tool-owned Gemini credential loading. Never parse a scanned target .env."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from security_auditor.discovery.path_safety import is_reparse_point, is_within_root


def _reasonable(value: str | None) -> str | None:
    if value and 8 <= len(value) <= 512 and not any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return value
    return None


def gemini_api_key(target_root: Path, tool_config_dir: Path | None = None) -> str | None:
    """Process environment wins; a trusted tool .env outside target is fallback."""
    direct = _reasonable(os.environ.get("GEMINI_API_KEY"))
    if direct is not None or tool_config_dir is None:
        return direct
    try:
        target = target_root.resolve(strict=True)
        config = tool_config_dir.resolve(strict=True)
        if is_within_root(target, config):
            return None
        file = config / ".env"
        info = file.lstat()
        if (not stat.S_ISREG(info.st_mode) or is_reparse_point(info) or
                info.st_size > 8192 or info.st_size < 1):
            return None
        with file.open("rb") as stream:
            content = stream.read(8193)
        if len(content) > 8192:
            return None
        for line in content.decode("utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, value = stripped.split("=", 1)
            if name.strip() != "GEMINI_API_KEY":
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            return _reasonable(value)
    except (OSError, UnicodeError, ValueError, RuntimeError):
        return None
    return None
