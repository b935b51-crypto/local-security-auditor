# Large Text Secret Coverage Assessment — 2026-09-24

> Implementation update (Hardening #8, 2026-09-24): The separately authorized hybrid bounded large-text path is now implemented in source. The assessment below is the historical decision basis; its statements that no production mode exists describe the earlier assessment turn. See [Secret Scanner](SECRET_SCANNER.md) and the [new offline Trading Platform re-scan](RC_REAL_WORLD_VALIDATION.md#bounded-large-text-secret-re-scan-hardening-8-2026-09-24). The existing 0.9.0 distribution artifacts have not yet been rebuilt from this source change.

This is a read-only v1 RC assessment, not an implemented scanner mode. Target content was never printed, executed, imported, copied into this repository, or uploaded. Synthetic benchmark files and prototypes lived only in verified system temporary directories and were removed. Production Secret limits, exclusions, rules, reports, and Gate behavior are unchanged.

## Current architecture and limits

| Source | Function | Relevant behavior |
| --- | --- | --- |
| `discovery/service.py`, `core/config.py` | discovery admission | Default 4 MiB and hard 32 MiB per file; only a bounded prefix is read for classification. An unadmitted file cannot reach Secret Scanner. |
| `discovery/content.py` | `read_admitted_artifact` | Rechecks admitted root-relative path, reparse status, containment, regular-file identity, size, and mtime before/after one bounded full-file read. Checks reduce but do not eliminate races. |
| `scanners/secrets/scanner.py` | `SecretScanner._scan` | Tests 1 MiB per-file and 64 MiB scan-total defaults before reading. Strictly decodes the whole byte buffer, then walks `StringIO(source)` line by line. A line above 16 KiB is skipped and marks coverage PARTIAL. Time is checked between operations, not inside a single read/regex. |
| `scanners/secrets/detectors.py` | rule functions | Provider shape, connection URL, JWT, assignment, and contextual entropy inspect one complete line. Private-key BEGIN/END keeps cross-line state. AWS ID and secret assignment are correlated within five lines after candidate collection. |
| `scanners/secrets/scanner.py`, `fingerprint.py` | candidate/output | Detector candidates contain no matched value; overlapping candidates use fixed precedence. Redaction occurs before Finding construction. Fingerprint hashes rule, safe relative path, line, column, family, and safe label, never the credential. |

Secret defaults / hard ceilings: per file 1 / 4 MiB; total 64 / 256 MiB; line 16 / 64 KiB; matches per rule per file 100 / 1,000; findings per file 100 / 1,000; total findings 1,000 / 10,000; elapsed time 300 / 3,600 seconds. The scanner is serial today. Raising Secret's cap above Discovery's 4 MiB default alone would not make 8–16 MiB files eligible.

## Current rule context and mode compatibility

“Line stream” below means a *bounded* line reader that skips overlong lines. “Chunk” means a future line-aware chunk and overlap design, not the simple benchmark prototype. FULL means existing behavior can be preserved; NEEDS CONTEXT means a new implementation needs explicit state or a second pass.

| Rule family | Full buffer | Bounded line stream | Chunk + overlap | Risk / context |
| --- | --- | --- | --- | --- |
| GitHub, AWS, Stripe, Slack, GitLab shapes | FULL | FULL on accepted lines | NEEDS CONTEXT | Match lengths are bounded; token may cross a read boundary. AWS severity depends on another candidate within five lines. |
| Connection URL credentials | FULL | FULL on accepted lines | NEEDS CONTEXT | Scheme/user/password may cross a chunk boundary; emit only the password span. |
| JWT structure | FULL | FULL on accepted lines | NEEDS CONTEXT | Pattern may span a boundary; bounded base64 JSON header/payload checks must remain. |
| Generic assignment | FULL | FULL on accepted lines | NEEDS CONTEXT | Key/value is bounded, but hash and documentation context checks inspect the *whole line*, even text after the candidate. |
| Contextual entropy | FULL | FULL on accepted lines | NEEDS CONTEXT | Candidate plus preceding 40 characters is local, but hash-context gating is whole-line. Entropy never stands alone. |
| Private-key marker | FULL | FULL on accepted lines | NEEDS CONTEXT | BEGIN/END state crosses lines; body is never retained in evidence. A marker split across chunks must be recognized once. |
| Overlap dedup / Finding identity | FULL | FULL if line/column preserved | NEEDS CONTEXT | Overlap must not duplicate candidates, consume match budgets twice, or change fingerprints. |

Current rules intentionally do not generally recognize arbitrary cross-line assignments or split URLs. A future large-file path must not silently claim coverage for patterns the current rule set does not support.

## Real-world file statistics

The already identified `log/program.log.20260924` was read only as 64 KiB binary chunks with a 4 MiB assessment cap. Only aggregate statistics were emitted. Its provenance is unverified; its path and line distribution are consistent with a log, but it remains applicable text under current policy.

| Measure | Observed |
| --- | ---: |
| Size | 2,169,199 bytes (about 2.07 MiB) |
| Strict UTF-8 validation | Passed |
| Lines / newline style | 251 / LF only |
| Average / median / p95 line bytes | 8,642 / 1,072 / 3,372 |
| Longest line | 485,512 bytes |
| Lines above 16 KiB default | 9; 1,893,205 bytes, **87.3%** of the file |
| Lines above 64 KiB hard ceiling | 6; 1,791,954 bytes, **82.6%** of the file |
| NUL / other binary-like controls | 0 / 0 |

The file is newline-delimited, but no JSONL or fixed record format was established. No line or source content was output. Raising only the 1 MiB file cap would still skip nine lines and leave Secret coverage PARTIAL; most bytes are in those lines.

## Synthetic benchmark

Repo-external files contained repeated inert short log lines and no real secrets. One warmed Python 3.12.11 run per point measured `perf_counter` time and `tracemalloc` peak Python allocations while invoking the existing detector functions. Values are directional, not throughput guarantees; they exclude OS process RSS and filesystem cache effects. “Full” is a temporary full-read/decode/StringIO prototype, deliberately outside production limits. “Line” uses a normal text iterator on short lines; “Chunk” uses incremental UTF-8 decoding and 64 KiB chunked line assembly. All these short-line runs found zero candidates and zero duplicates, with no skipped lines.

| Input | Full: s / peak MiB | Line: s / peak MiB | Chunk: s / peak MiB |
| ---: | ---: | ---: | ---: |
| 2 MiB | 0.182 / 10.01 | 0.177 / 0.03 | 0.179 / 0.20 |
| 4 MiB | 0.389 / 20.00 | 0.368 / 0.03 | 0.367 / 0.20 |
| 8 MiB | 0.755 / 40.00 | 0.731 / 0.03 | 0.740 / 0.20 |
| 16 MiB | 1.551 / 80.00 | 1.539 / 0.03 | 1.594 / 0.20 |

An additional 2 MiB fixture with 63,551 very short lines took 0.699 seconds and 0.03 MiB traced peak in a reduced line prototype using the provider and assignment detectors; it found zero candidates. Its detector workload is narrower than the main matrix, so those times are not directly comparable.

The low line/chunk peaks apply to *short lines*. A naive unbounded line iterator or chunk accumulator can retain an entire adversarial line: the first 1 MiB single-line prototype peaked at about 2 MiB (line) and 2.13 MiB (chunk), and the full-buffer prototype at 7 MiB. Separate bounded UTF-8 prototype paths used a 16 KiB line cap and explicitly discarded the remainder: a 16 MiB single line was counted as one overlong line with about 0.06 MiB (bounded line reader) or 0.13 MiB (bounded chunks) traced peak. Skipping it is resource-safe but **PARTIAL**, not complete secret coverage. An early temporary chunk prototype missed an overlong final line without a newline; correcting that prototype to count the final discarded line demonstrated a concrete end-of-file test requirement. No prototype entered production.

### Boundary checks and their limits

An additional in-memory check placed the first byte of a three-byte Chinese character at byte offset 65,535. The incremental UTF-8 decoder crossed the 64 KiB read boundary and produced exactly the same text as whole-buffer decoding. This verifies decoder behavior only, not full scanner parity on long lines.

Synthetic, clearly fake provider-shaped token, private-key marker, JWT, credential assignment, connection URL, and Chinese UTF-8 text were placed six bytes before a 64 KiB read boundary. CRLF was checked at a boundary too. Full-buffer, bounded-line, and bounded-chunk prototypes produced the same raw candidate rule/line/column/fingerprint tuples on these bounded lines. The marker check verified detection, **not** full multiline private-key state. Assignment also yielded a second contextual-entropy candidate before production overlap dedup, equally in each mode. A synthetic 16 MiB no-newline line was safely skipped by bounded prototypes. These checks do **not** establish parity for >16 KiB lines, whole-line suppression context, every encoding, malformed UTF-8, match-budget exhaustion, or all scanner output semantics.

## Options and security trade-offs

| Option | Benefit | Main risk and v1 fit |
| --- | --- | --- |
| A. Raise current file limit to 4 MiB | Simple, reuses all current rules and location logic; the 2.07 MiB log becomes readable. | It still skips 87.3% of this file's bytes by the existing 16 KiB line policy. Full-buffer memory/CPU increase for any newly accepted hostile file. Insufficient as the sole fix. |
| B. Full-buffer with higher default/hard cap (e.g. 4/16 MiB) | No new matcher architecture and exact current rule behavior. | 16 MiB synthetic input used ~80 MiB traced Python allocations; real peak can be higher. Requires Discovery policy changes above 4 MiB and still does not solve long lines without raising that cap, exposing regex work on huge hostile lines. Not a sustainable v1 default. |
| C. Bounded line-by-line streaming | Natural line numbers and low memory for short-line logs; existing detectors can be reused. | To remain bounded, overlong lines must be skipped, leaving this log PARTIAL. An unbounded iterator is unsafe on a single huge line. UTF-8/UTF-16 decoding, CRLF, and final partial line need exact tests. |
| D. Chunked scan with overlap | Could analyze long lines without retaining them; bounded maximum detector spans make an overlap feasible. | Needs an incremental decoder, line/column accounting, whole-line context gates, cross-line private-key/AWS state, overlap dedup, match-budget accounting, and freshness-safe reopen or bounded deferred decisions. No complete prototype proved these semantics yet. |
| E. Hybrid: current full buffer ≤1 MiB, chunked large text ≤X | Leaves established small-file path unchanged while potentially covering the real 2.07 MiB file under a separate bounded mode. | Two modes must produce identical Finding identity. Discovery's default 4 MiB caps an initial X; 8/16 MiB support would also require Discovery changes. This is the lowest-risk *implementation shape* if D is fully validated. |
| F. Keep current limitation for v1 | Preserves reviewed resource and detection behavior; PARTIAL and Gate BLOCK disclose the omission. | The 2.07 MiB log remains unexamined by Secrets; operators must not interpret that scan as complete. |

## Design requirements if separately authorized

**Decision: HARDENING #8 — CHUNKED + OVERLAP, implemented as a hybrid large-text path, before declaring v1.0.0 real-world coverage complete.** The measured long-line concentration makes a file-limit increase or pure bounded-line iterator insufficient. This is a recommendation, not implementation authorization. A safe first scope is files >1 and ≤4 MiB already admitted by Discovery; a larger X requires separate Discovery and total-budget analysis. A candidate 64 KiB read chunk is supported only as an I/O starting point; overlap must be derived from the longest active bounded regex/context span and verified by tests, rather than picked arbitrarily. A 16 MiB file is not currently admitted by default.

The future design must:

1. Use freshness-checked admitted reads in bounded chunks without following reparse points or losing root/identity checks; path-based Windows races remain a residual risk.
2. Decode incrementally, including split multibyte UTF-8, CRLF, malformed input, and a final line without newline. Decide how supported UTF-16 encodings are handled; do not silently drop them.
3. Cover long lines without a full-line buffer, or label them PARTIAL. Preserve line-global hash/documentation suppression and cross-line private-key/AWS state; a bounded first pass or deferred per-line candidate decisions may be needed.
4. Bound per-file and scan-total bytes, per-chunk memory, elapsed/per-file time, matches/rule, findings/file, and findings total. Eight 16 MiB files would consume 128 MiB and exceed the current 64 MiB total default. A hundred 15 MiB logs must stop honestly at budgets. Repeated token-like strings, entropy-heavy data, huge CRLF density, malformed UTF-8, and pathological regex inputs need adversarial tests. A per-file timer is worth evaluating because the current 300-second check is only between operations.
5. Emit redacted raw-free candidates before Finding construction; never log, persist, or upload raw match/chunk text. Use absolute line/column and the existing fingerprint inputs so a file crossing the 1 MiB threshold does not change identity. Count a match crossing overlap exactly once.
6. Return COMPLETE only when every applicable byte/line was analyzed within the declared rule scope. Oversize, undecodable, skipped long-line, timeout, or budget exhaustion remains PARTIAL/ABORTED and Gate BLOCK. A future optional mode field (`FULL_BUFFER` / `CHUNKED`) can be additive; do not change JSON 1.1 semantics silently.

With a correct chunked long-line path, the observed 2,169,199-byte log is within Discovery's 4 MiB admission default and could in principle be fully scanned with bounded memory. This assessment does **not** prove it would yield COMPLETE or change Gate status: encoding/freshness, all rule-state parity, and budget behavior must be validated on synthetic hostile cases, then the real target safely re-scanned. Until then Secrets and Overall remain PARTIAL and Gate BLOCK. Final 1.0.0 is **conditional**: shipping the existing tool with an explicit incomplete-coverage contract is possible, but claiming complete coverage or a passing Gate for this real-world target requires a separately authorized and verified solution. No production behavior changed in this assessment.
