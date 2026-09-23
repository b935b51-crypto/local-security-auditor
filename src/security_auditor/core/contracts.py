"""Interfaces for future scanners; this module performs no scanning."""

from __future__ import annotations

from typing import Protocol, Sequence

from .models import FileArtifact, RuleReference, ScannerMetadata, ScannerResult, ScanSession


class Scanner(Protocol):
    @property
    def metadata(self) -> ScannerMetadata: ...

    def supports(self, artifact: FileArtifact) -> bool: ...

    def rules(self) -> Sequence[RuleReference]: ...

    def capabilities(self) -> frozenset[str]: ...

    def scan(self, session: ScanSession, artifacts: Sequence[FileArtifact]) -> ScannerResult: ...


class AsyncScanner(Protocol):
    @property
    def metadata(self) -> ScannerMetadata: ...

    async def scan(self, session: ScanSession, artifacts: Sequence[FileArtifact]) -> ScannerResult: ...
