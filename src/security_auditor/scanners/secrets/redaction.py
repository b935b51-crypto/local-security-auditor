"""Safe descriptors only; never return source fragments containing a credential."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit


def redacted_preview(family: str) -> str:
    if family == "private_key":
        return "[REDACTED PRIVATE KEY]"
    if family == "password" or family == "connection_string":
        return "[REDACTED PASSWORD]"
    return "[REDACTED CREDENTIAL]"


def sanitize_url_for_evidence(url: str) -> str:
    """Return a bounded URL shape; userinfo and all query values are discarded."""
    try:
        parsed = urlsplit(url[:4096])
        if not parsed.scheme or not parsed.netloc:
            return "[REDACTED URL]"
        scheme = parsed.scheme.lower()
        if not re.fullmatch(r"[a-z][a-z0-9+.-]{0,31}", scheme):
            return "[REDACTED URL]"
        # Host may itself contain hostile text. Do not preserve it.
        host = "[HOST]"
        userinfo = "[USER]:[REDACTED]@" if "@" in parsed.netloc else ""
        query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32)
        # Query names may themselves be secrets. Preserve only a count.
        query_marker = f"?[{len(query)} REDACTED QUERY FIELDS]" if query else ""
        return f"{scheme}://{userinfo}{host}{query_marker}"[:256]
    except (ValueError, UnicodeError):
        return "[REDACTED URL]"
