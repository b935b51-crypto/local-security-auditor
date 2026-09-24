# Phase 3 Python SAST

`SASTScanner` is an offline, synchronous scanner for regular Python source and script artifacts admitted by Phase 1 discovery. It reopens files through `read_admitted_artifact`, decodes strictly, and uses `ast.parse` as data parsing. **It never imports or executes target modules.** The scanner has no CLI, reporter, network, or external tool dependency. Its preferred entry is `scan_discovery(session, discovery)` to retain discovery completeness; `scan(session, artifacts)` is the protocol entry for an orchestrator that already holds admitted artifacts.

## Detection model

The frontend recognizes direct source categories: user input, HTTP request fields, CLI arguments/stdin, environment variables, and selected network responses. `FILE_INPUT` is reserved in the taxonomy; an arbitrary local file is not automatically attacker controlled. Local name assignment and reassignment are flow sensitive. `if` branches merge taint conservatively, loops receive one pass and merge, and functions are analyzed separately. Route-decorated function parameters are treated as HTTP input. Import aliases are resolved for known APIs. Trace descriptors contain only category, structural step, and line number, never source text.

The following rule IDs are emitted by this implementation:

| Rule | Condition | Default assessment |
| --- | --- | --- |
| `SAST.PYTHON.COMMAND_INJECTION` | Recognized source reaches `os.system`/`os.popen` or a subprocess call with literal `shell=True`, without recognized `shlex.quote` guard | HIGH severity, HIGH confidence; environment source MEDIUM confidence |
| `SAST.PYTHON.SQL_INJECTION` | Recognized source participates in interpolation/concatenation and reaches `.execute`/`.executemany`/`.raw` without separate parameter argument | HIGH, HIGH |
| `SAST.PYTHON.PATH_TRAVERSAL` | Recognized source reaches file operation without recognized path-boundary guard | MEDIUM, MEDIUM; component/environment input LOW confidence |
| `SAST.PYTHON.UNSAFE_DESERIALIZATION` | Recognized source reaches `pickle`/`marshal` load API | HIGH, HIGH |
| `SAST.PYTHON.DYNAMIC_CODE_EXEC` | Recognized source reaches `eval`/`exec`/`compile` | HIGH, HIGH |
| `SAST.PYTHON.TLS_VERIFY_DISABLED` | Supported HTTP call explicitly passes literal `verify=False` | MEDIUM, HIGH |
| `SAST.PYTHON.UNSAFE_YAML_LOAD` | `yaml.load` has no recognized `SafeLoader`/`CSafeLoader` | MEDIUM, MEDIUM |
| `SAST.PYTHON.INSECURE_TEMP_FILE` | `tempfile.mktemp` is called | MEDIUM, HIGH |

`shlex.quote`, `os.path.basename`, `Path.name`, and `Path.relative_to` are recognized as narrow guards. Recognition does not prove end-to-end safety. A SQL query that is not visibly interpolated does not trigger the SQL injection rule; supplying an additional parameter argument does not make an already interpolated query safe. Constant misuse rules are separate from taint rules. A sink call alone does not establish command injection. Findings carry rule provenance, separate severity/confidence, safe source/sink descriptors, static evidence, and a stable location-based fingerprint. Source snippets and literal values are excluded from `Finding`.

## Limits, failure, and accuracy

Default SAST limits are 512 KiB per file, 32 MiB per scan, 20,000 AST nodes per Python file (50,000 hard ceiling), depth 100 per Python file, 5,000 nodes per function, 100 findings per file, 1,000 total findings, and 300 seconds elapsed. The node default was raised from 10,000 after a passive Mosaic scan measured 10,593 and 11,532 nodes in two ordinary 65–69 KiB Python files; their maximum depths were both 14. Node and depth counters reset for each file. Operator config may lower or raise limits only within hard ceilings; target content cannot grant execution or bypass limits. Oversize files, parse failures, AST/function limits, changed admitted files, and rule failures yield fixed diagnostic codes and `partial` coverage. Total byte, total finding, or deadline exhaustion aborts. Discovery incompleteness propagates. AST limit diagnostics distinguish `SAST_AST_NODE_LIMIT_REACHED` from `SAST_AST_DEPTH_LIMIT_REACHED` and carry the admitted root-relative path, never an absolute host path. Diagnostic text never includes source lines or exception messages.

Scanner summary counts separate considered, applicable, scanned, skipped after applicability, and not applicable. Unsupported/non-Python artifacts are not failed coverage and do not make SAST partial. The added JSON scanner summary keys are additive within report schema 1.1.

This is an intentionally shallow **intraprocedural** analysis. It does not build a full CFG, model arbitrary framework sources, track object fields/interprocedural returns, analyze generated code, prove path containment, or prove exploitability. Taint merges may produce false positives; unmodeled wrappers and sanitizer semantics can yield false negatives. `ast.parse` itself is bounded by input bytes before parse, while node/depth and elapsed checks apply during/after parsing; a hard parser time or memory isolation boundary is future work. Results are candidate findings for review, not verified exploits or intent claims.
