"""Bounded, passive file discovery. No target code is executed."""

from .models import DiscoveryResult, ScanCompleteness
from .policy import DiscoveryPolicy
from .service import discover

__all__ = ["DiscoveryPolicy", "DiscoveryResult", "ScanCompleteness", "discover"]
