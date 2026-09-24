"""Bounded large-text secret detection over admitted, identity-checked chunks."""

from __future__ import annotations

import codecs
from dataclasses import dataclass, replace
from pathlib import Path
import re
from time import monotonic

from security_auditor.core.config import SecretLimits
from security_auditor.core.models import Confidence, FileArtifact
from security_auditor.discovery.content import iter_admitted_artifact_chunks

from . import detectors
from .models import SecretCandidate
from .placeholders import is_hash_context


# JWT's maximum pattern length is 512 + 1024 + 1024 + two dots. The
# connection, provider, marker, and entropy patterns are shorter. Keep more
# than that full span on each side of a committed window boundary.
CHUNK_BYTES = 64 * 1024
SEGMENT_CHARS = 8 * 1024
OVERLAP_CHARS = 4 * 1024
_DOCUMENT_CONTEXT = re.compile(r"\b(?:example|sample|placeholder|documentation)\b", re.I)
_ASSIGNMENT_KEY = (
    r"(?:aws_secret_access_key|api[_-]?key|api[_-]?token|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|"
    r"connection[_-]?string|secret|token)"
)
# The current assignment regex allows unbounded whitespace. A gap longer
# than the overlap cannot be proven equivalent by fixed-window matching.
_UNBOUNDED_ASSIGNMENT = re.compile(
    rf"(?<![\w-]){_ASSIGNMENT_KEY}[\"']?\s{{{OVERLAP_CHARS},}}(?::|=)?|"
    rf"(?<![\w-]){_ASSIGNMENT_KEY}[\"']?\s*(?::|=)\s{{{OVERLAP_CHARS},}}",
    re.I,
)
_RULE_IDS = len(detectors.PROVIDERS) + 5


class LargeTextDeadline(Exception):
    """Fixed safe failure: no source text in exception arguments."""


@dataclass(slots=True)
class LargeTextResult:
    candidates: list[tuple[int, SecretCandidate]]
    safe_path: str
    bytes_scanned: int = 0
    candidate_matches: int = 0
    placeholders: int = 0
    duplicates: int = 0
    limit_hits: int = 0
    long_lines: int = 0
    incomplete_lines: int = 0
    incomplete: bool = False
    inside_key: bool = False


def _deduplicate(candidates: list[SecretCandidate]) -> tuple[list[SecretCandidate], int]:
    selected: list[SecretCandidate] = []
    for item in sorted(candidates, key=lambda c: (c.priority, c.start, -(c.end - c.start), c.rule_id)):
        if not any(item.overlaps(other) for other in selected):
            selected.append(item)
    selected.sort(key=lambda c: (c.start, c.end, c.rule_id))
    return selected, len(candidates) - len(selected)


class _LongLine:
    """Scan one logical line without retaining the complete line."""

    def __init__(self, inside_key: bool, limit: int, safe_path: str,
                 *, enable_assignment: bool, enable_entropy: bool):
        self.started_inside_key = inside_key
        self.window = ""
        self.base = 0
        self.committed = 0
        self.total = 0
        self.context_tail = ""
        self.hash_context = False
        self.document_context = False
        self.incomplete = False
        self.end_seen = False
        self.begin: SecretCandidate | None = None
        self.end_after_begin = False
        self.candidates: list[SecretCandidate] = []
        self.candidate_count = 0
        self.limit = limit
        self.safe_path = safe_path
        self.enable_assignment = enable_assignment
        self.enable_entropy = enable_entropy

    def feed(self, text: str) -> None:
        context = self.context_tail + text
        self.hash_context |= is_hash_context(context)
        self.document_context |= bool(_DOCUMENT_CONTEXT.search(context))
        self.context_tail = context[-64:]
        for start in range(0, len(text), SEGMENT_CHARS):
            self.window += text[start:start + SEGMENT_CHARS]
            self.total += min(SEGMENT_CHARS, len(text) - start)
            if len(self.window) > 2 * OVERLAP_CHARS:
                self._scan(final=False)
                safe_end = len(self.window) - OVERLAP_CHARS
                remove = max(0, safe_end - OVERLAP_CHARS)
                self.window = self.window[remove:]
                self.base += remove

    def _scan(self, *, final: bool) -> None:
        safe_end = len(self.window) if final else len(self.window) - OVERLAP_CHARS
        safe_absolute = self.base + safe_end
        if safe_absolute <= self.committed:
            return
        for match in detectors.PRIVATE_END.finditer(self.window):
            position = self.base + match.end()
            if self.committed < position <= safe_absolute:
                self.end_seen = True
                if self.begin is not None and position > self.begin.end:
                    self.end_after_begin = True
        if self.started_inside_key:
            self.committed = safe_absolute
            return
        if _UNBOUNDED_ASSIGNMENT.search(self.window):
            self.incomplete = True
        groups: list[list[SecretCandidate]] = []
        private, _ = detectors.private_key(self.window)
        groups.append(private)
        for detector in (detectors.provider, detectors.connection_string, detectors.jwt,
                         *((detectors.assignment,) if self.enable_assignment else ()),
                         *((detectors.entropy_context,) if self.enable_entropy else ())):
            groups.append(detector(self.window)[0])
        for candidate in (item for group in groups for item in group):
            absolute_end = self.base + candidate.end
            if (absolute_end <= self.committed or absolute_end > safe_absolute
                    or (self.base and candidate.start == 0)):
                continue
            absolute = replace(candidate, start=self.base + candidate.start, end=absolute_end)
            matched_value = self.window[candidate.start:candidate.end]
            if matched_value and matched_value in self.safe_path:
                self.safe_path = self.safe_path.replace(matched_value, "[REDACTED]")
            if candidate.rule_id == "SECRET.PRIVATE_KEY.PEM":
                if self.begin is None:
                    self.begin = absolute
                    self.candidates.append(absolute)
                continue
            self.candidate_count += 1
            if len(self.candidates) >= self.limit:
                self.incomplete = True
                continue
            self.candidates.append(absolute)
        if self.begin is not None and any(
            self.begin.end < self.base + match.end() <= safe_absolute
            for match in detectors.PRIVATE_END.finditer(self.window)
        ):
            self.end_after_begin = True
        self.committed = safe_absolute

    def finish(self) -> tuple[list[SecretCandidate], bool, bool, int]:
        self._scan(final=True)
        if self.hash_context:
            self.candidates = [item for item in self.candidates
                               if item.rule_id not in {"SECRET.GENERIC.ASSIGNMENT",
                                                       "SECRET.GENERIC.ENTROPY"}]
        elif self.document_context:
            self.candidates = [
                replace(item, confidence=Confidence.LOW)
                if item.rule_id == "SECRET.GENERIC.ASSIGNMENT" else item
                for item in self.candidates
            ]
        inside = (not self.end_seen if self.started_inside_key else
                  self.begin is not None and not self.end_after_begin)
        return self.candidates, inside, self.incomplete, self.candidate_count


def scan_large_artifact(root: Path, artifact: FileArtifact, limits: SecretLimits,
                        started: float, result: LargeTextResult | None = None) -> LargeTextResult:
    """Return only raw-free candidates after a complete bounded read."""
    result = result if result is not None else LargeTextResult([], artifact.path)
    decoder = codecs.getincrementaldecoder(artifact.encoding or "utf-8")("strict")
    line_number = 1
    short_line = ""
    long_line: _LongLine | None = None
    rule_counts: dict[str, int] = {}
    max_raw_candidates = min(100_000, max(64, limits.max_findings_per_file * _RULE_IDS))
    detection_stopped = False

    def accept_line(items: list[SecretCandidate], *, long: bool, incomplete: bool,
                    candidate_count: int = 0) -> None:
        nonlocal detection_stopped
        if long:
            result.long_lines += 1
        if incomplete:
            result.incomplete = True
            result.incomplete_lines += 1
            result.limit_hits += 1
        result.candidate_matches += candidate_count if long else len(items)
        admitted: list[SecretCandidate] = []
        for item in items:
            count = rule_counts.get(item.rule_id, 0)
            if count >= limits.max_matches_per_rule_per_file:
                result.incomplete = True
                result.limit_hits += 1
                continue
            rule_counts[item.rule_id] = count + 1
            admitted.append(item)
        chosen, dropped = _deduplicate(admitted)
        result.duplicates += dropped
        if len(result.candidates) + len(chosen) > limits.max_findings_per_file:
            chosen = chosen[:max(0, limits.max_findings_per_file - len(result.candidates))]
            result.incomplete = True
            result.limit_hits += 1
            detection_stopped = True
        for item in chosen:
            result.candidates.append((line_number, item))

    def finish_line() -> None:
        nonlocal line_number, short_line, long_line
        if detection_stopped:
            line_number += 1
            short_line = ""
            long_line = None
            return
        if long_line is not None:
            items, result.inside_key, incomplete, count = long_line.finish()
            result.safe_path = long_line.safe_path
            accept_line(items, long=True, incomplete=incomplete, candidate_count=count)
            long_line = None
        else:
            line = short_line
            if result.inside_key:
                if detectors.PRIVATE_END.search(line):
                    result.inside_key = False
            else:
                private, result.inside_key = detectors.private_key(line)
                groups = [private]
                for detector in (detectors.provider, detectors.connection_string, detectors.jwt,
                                 *((detectors.assignment,) if limits.enable_generic_assignment else ()),
                                 *((detectors.entropy_context,) if limits.enable_entropy else ())):
                    found, suppressed = detector(line)
                    groups.append(found)
                    result.placeholders += suppressed
                accept_line([item for group in groups for item in group],
                            long=False, incomplete=False)
                for item in (item for group in groups for item in group):
                    matched_value = line[item.start:item.end]
                    if matched_value and matched_value in result.safe_path:
                        result.safe_path = result.safe_path.replace(matched_value, "[REDACTED]")
            short_line = ""
        line_number += 1

    def feed_piece(piece: str) -> None:
        nonlocal short_line, long_line
        if detection_stopped:
            return
        if long_line is not None:
            long_line.feed(piece)
        elif len((short_line + piece).encode(artifact.encoding or "utf-8")) <= limits.max_line_bytes:
            short_line += piece
        else:
            long_line = _LongLine(
                result.inside_key, max_raw_candidates, result.safe_path,
                enable_assignment=limits.enable_generic_assignment,
                enable_entropy=limits.enable_entropy,
            )
            long_line.feed(short_line)
            long_line.feed(piece)
            short_line = ""

    def feed_text(text: str) -> None:
        pieces = text.split("\n")
        for index, piece in enumerate(pieces):
            if monotonic() - started >= limits.max_elapsed_seconds:
                raise LargeTextDeadline
            for offset in range(0, len(piece), SEGMENT_CHARS):
                feed_piece(piece[offset:offset + SEGMENT_CHARS])
            if index < len(pieces) - 1:
                feed_piece("\n")
                finish_line()

    for chunk in iter_admitted_artifact_chunks(root, artifact, max_bytes=limits.max_file_bytes,
                                               chunk_bytes=CHUNK_BYTES):
        result.bytes_scanned += len(chunk)
        feed_text(decoder.decode(chunk, final=False))
    feed_text(decoder.decode(b"", final=True))
    if short_line or long_line is not None:
        finish_line()
    return result
