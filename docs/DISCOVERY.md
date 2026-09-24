# Safe file discovery — Phase 1

`discover(ScanTarget, DiscoveryPolicy) -> DiscoveryResult` is the public, passive API. It validates one root, enumerates a bounded tree, admits files under a separate security-scan policy, reads only a short prefix, and returns sorted artifacts, skips, diagnostics, summary counters, and completeness. It does not produce findings, execute target content, parse dependency vulnerabilities, extract archives, hash full files, or write the target.

## Traversal and path trust

The selected root must exist, be a directory, and not itself be a symlink/reparse point. `Path.resolve(strict=True)` gives its canonical absolute representation. Each child comes only from `os.scandir`; components with ambiguous separators, `..`, NUL, or Windows device/ADS/reserved-name forms are rejected. Root containment uses resolved paths and `os.path.commonpath`, never a string prefix. A different `st_dev` volume is denied. Every directory entry is fresh `os.stat(..., follow_symlinks=False)` before use; directories are checked again after enumeration and files again after opening. A changed or inaccessible item becomes a structured skip and diagnostic.

The default is **no traversal through symlinks, junctions, or any Windows reparse point**. Their metadata may be observed, but contents are not followed. A link to an external root gets `REPARSE_POINT_SKIPPED` and, when resolvable, `OUTSIDE_ROOT_SKIPPED`. Explicit reparse root selection fails. Opt-in following is not implemented; `follow_symlinks=true` and `follow_reparse_points=true` are rejected by config.

Directory loop protection uses a visited `FileIdentity` set. Python 3.12 `os.stat()` supplies `st_dev` (device identifier) and `st_ino` (Windows file index when available); `DirEntry.stat()` is **not** used for identity on Windows because its `st_dev`/`st_ino` can be zero. If `st_ino` is unavailable, a normalized resolved path is the fallback and `IDENTITY_FALLBACK` marks the result partial. This fallback cannot prove identity across aliases or unusual network filesystems. [Python 3.12 `os` documentation](https://docs.python.org/3.12/library/os.html) describes these fields and reparse attributes. No ctypes or external command is needed for the baseline.

All filesystem checks are path based; a hostile concurrent process can race between checks and opens. The implementation checks no-follow metadata, resolved containment, open-handle identity, size, and modification time before reading, and checks handle metadata again afterward. This reduces risk but is **not a race-free Windows handle-relative sandbox**. UNC roots and long paths use Python/Windows path handling subject to the same checks; unusual network filesystems, reparse races, and UNC aliases need further platform testing. NTFS alternate data streams are outside baseline coverage and colon-bearing Windows components are rejected.

## Budgets and counters

`DiscoveryLimits` defaults and built-in hard ceilings are in `core/config.py`. Config values outside hard ceilings fail validation; no target-local file is automatically loaded as config.

| Limit | Default | Hard ceiling | Meaning |
| --- | ---: | ---: | --- |
| `max_file_count` | 100,000 | 250,000 | regular files observed, including excluded files |
| `max_directories` | 50,000 | 100,000 | directories actually visited |
| `max_entries` | 200,000 | 500,000 | all names enumerated, bounding one-directory sort memory |
| `max_directory_depth` | 64 | 128 | root is depth 0 |
| `max_file_size_bytes` | 4 MiB | 32 MiB | larger files are skipped before content reads |
| `max_sniff_bytes` | 8 KiB | 16 KiB | maximum prefix requested per file |
| `max_single_text_read` | 8 KiB | 16 KiB | second per-file read ceiling |
| `max_total_bytes_inspected` | 128 MiB | 512 MiB | cumulative bytes actually read for prefixes |
| `max_line_length` | 8 Ki characters | 64 Ki characters | first-line/shebang classification cap |
| `max_elapsed_seconds` | 300 | 3,600 | best-effort monotonic wall-clock stop |

Each `read(size)` is bounded by both per-file byte limits and the remaining total-byte budget. A large file is stat-ed, counted as discovered, then skipped; it is not hashed or fully read. `TraversalStats` distinguishes entries seen, directories visited, files discovered, files admitted, files inspected, bytes inspected, and file/directory skips. `max_entries` prevents an enormous single directory from being materialized without bound. Time checks occur between entries/directories, so a single blocking filesystem syscall may exceed the nominal time cap.

## Admission and ignores

The order is: immutable root/reparse/type/budget rules → configurable default traversal excludes → security-scan `exclude` → optional `.gitignore` → explicit `include` override/filter → file size → prefix read. `include` may restore a file under a default or security exclude but cannot override root safety or hard caps. If includes exist, the walker does not prune excluded directories because an included descendant may live there; all other files must match an include to be admitted.

Default traversal excludes cover `.git/`, `node_modules/`, `.venv/`, `venv/`, `dist/`, `build/`, `coverage/`, `__pycache__/`, and `.cache/`. They live in config, not fixed walker logic. `.env` is **not** excluded by default. `respect_gitignore=false` keeps version-control ignore independent from security-scan ignore. When enabled, Phase 1 supports only a bounded, root-level `.gitignore` subset: comments, literal names, simple globs, directory suffix `/`, and `!` negation. It does not implement nested `.gitignore`, escaped syntax, bracket classes, or all Git wildmatch rules. Unsupported/oversized/malformed input yields `GITIGNORE_UNAVAILABLE` and a partial result; the target ignore file never grants execution, network, or larger budgets. No Git command is invoked.

Patterns use `/` internally; `\` in patterns is normalized to `/`. A pattern without `/` matches a matching component anywhere; a trailing `/` matches a directory and descendants; a pattern containing `/` matches the relative path using `fnmatch`-style `*` (which may span a separator). Matching is case-insensitive on Windows and case-sensitive elsewhere. Results are sorted by `(casefold(path), path)` for stable order.

## Classification

Content is `text`, `binary`, or `unknown`. Magic prefixes take precedence over extensions: fake `MZ`, ELF, Mach-O, ZIP, gzip, PDF, PNG, and JPEG signatures are recognized without executing or extracting anything. NULs and control-character ratio conservatively mark binary. UTF-8, UTF-8 BOM, UTF-16 LE/BE BOM, and cautious BOM-less UTF-16 are handled by strict incremental decoding; undecodable prefixes remain `unknown` with `DECODE_FAILED`. `errors="ignore"` is not used. A `.py` file beginning with PE magic is an executable-like binary with unknown language.

Text language hints come from filename suffix or a parsed first-line shebang, with separate confidence. Supported names include Python, JavaScript, TypeScript, JSX, TSX, PowerShell, Batch/CMD, shell, C/C++, C#, Java, Kotlin, Go, Rust, Ruby, PHP, Swift, SQL, HTML, CSS, JSON, YAML, TOML, XML, and Markdown. Shebangs are inspected as text only. Artifact roles include source, script, config, dependency manifest, lockfile, CI/container config, documentation, archive, binary, executable, certificate-like, key-material-like, env file, and unknown. Manifest/lockfile names for the Python, Node, Rust, Go, .NET, Java, Ruby, and PHP ecosystems are identified by name; dependencies are not parsed. `private.pem` is only a key-material-like **role**, not a secret finding.

`FileArtifact` stores a root-relative POSIX path, basename/suffixes, size, modification time, content/role/language, classification confidence, optional file identity, encoding, executable-like flag, and sniffed byte count. Full SHA-256 is left `None`. Raw filenames stay in the domain; `safe_display()` escapes terminal controls and bidi formatting characters at a presentation boundary.

## Completeness and diagnostics

- `COMPLETE`: traversal finished; only deliberate includes/excludes were omitted.
- `PARTIAL`: useful artifacts exist or traversal continued, but a file/directory was inaccessible, unsafe, too large, reparse-linked, changed, undecodable, depth-limited, or otherwise uninspected.
- `ABORTED`: a global file, directory, entry, total-byte, or elapsed-time budget stopped the remaining tree.
- `FAILED`: root is absent, invalid, reparse-linked, inaccessible, or cannot be enumerated.

`SkippedArtifact.reason` is machine-readable. `DiscoveryDiagnostic` has a code, severity, raw relative path, fixed safe message, exception class name only, and `affects_completeness`. It never embeds exception messages or source bytes. Results sort artifacts, skips, and diagnostics; elapsed time is the only runtime-dependent summary field. Under a static tree and without a time-budget hit, identical config yields identical ordered content. A race or time cap can change the result and is explicitly reported.

## Known validation gaps

The Windows host used for Phase 1 could not create symlink fixtures, so the real symlink loop/outside-root integration test was skipped; reparse detection and default-deny behavior were also covered with a simulated reparse identity. Junction creation and UNC/network filesystem identity remain unverified on this host. The full offline suite has now passed under uv-managed Python 3.12.11. These are limits of verification, not claims that those cases are safe on every filesystem.
