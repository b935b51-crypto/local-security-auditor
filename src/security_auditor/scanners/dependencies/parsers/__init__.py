"""Pure static parsers for selected admitted dependency artifacts."""

from .python import parse_python
from .npm import parse_npm
from .rust_go import parse_rust_go

__all__ = ("parse_python", "parse_npm", "parse_rust_go")
