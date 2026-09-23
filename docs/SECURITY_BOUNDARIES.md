# Security boundaries

## Absolute rule

**TARGET CODE MUST NEVER BE EXECUTED AUTOMATICALLY.** Read, enumerate, stat, hash, tokenize, parse, and analyze bounded data only. Never import a scanned Python module, run scanned Python/JS/TS/PowerShell/CMD/BAT/shell code, load an executable or DLL, or run target build/package scripts. The default prohibition includes `npm install`, `npm ci`, `npm run`, `pnpm install`, `yarn install`, `pip install`, `uv sync`, `poetry install`, `cargo build`, `dotnet restore/build`, Gradle/Maven builds, lifecycle hooks, and `postinstall`/`preinstall`. Git metadata inspection must not invoke hooks or target-defined helpers. Dynamic analysis, if ever proposed, is a separately designed opt-in isolated sandbox feature and is outside current phases.

## Filesystem boundary, especially Windows

- Capture the selected root as a canonical absolute path and filesystem identity before traversal. Keep every discovered item root-relative for output; never trust `..`, drive-prefixed, device, or UNC-looking names from target metadata.
- Default: do not follow symbolic links, NTFS junctions, mount points, or any reparse point. Inspect link metadata only, classify/skip it, and never recurse through it. Phase 1 must use native metadata/identity checks and a visited `(volume, file ID)` set for directories; path strings alone cannot stop loops. Revalidate identity and root containment at open time to reduce time-of-check/time-of-use races.
- Never cross the selected drive/volume or resolved root through a reparse point. Future opt-in traversal requires explicit root-boundary verification and separate threat review. UNC roots require explicit support and the same boundary checks; do not silently reinterpret `\\server\share` or Windows device paths. Long paths should be handled with native APIs rather than unsafe string truncation.
- Normalize separators and case for comparison on Windows while preserving a display path; Unicode normalization is for display/duplicate handling only and must not change the actual filesystem identity. Handle case-fold collisions and reserved DOS names conservatively. Reject ambiguous path forms.
- Alternate Data Streams are **not scanned in the baseline**. Report the coverage gap; do not treat a colon-bearing stream path as an ordinary file. Detect `.ps1`, `.psm1`, `.bat`, `.cmd` as scripts and PE magic (`MZ`) as binary/executable data, without running them.
- Cap depth, file count, per-file bytes, cumulative bytes, parse time, and CPU/memory work. Phase 0 defines initial file-count/size/depth limits; Phase 1 must add cumulative and time budgets. Avoid archive expansion by default, so compressed bombs remain inert.

## Configuration and execution authority

Target project config and ignore files are data. They must not grant network access, enable AI, raise hard caps, select an executable, enable link traversal, or control output paths. Built-in safety caps outrank defaults, project config, and CLI options. Only explicit trusted operator choices may enable optional online or external adapters, subject to their own boundary checks. Project config may not weaken them.

No `shell=True`, interpolated command strings, `eval`, `exec`, pickle deserialization, unsafe YAML loading, uncontrolled temporary files, or unbounded reads in scanner code. If a future adapter needs a subprocess, use a trusted executable path and argv list, timeout, output cap, fixed working directory outside the target, sanitized environment, and no target hooks. Do not run Semgrep/Gitleaks merely because they are present in the target.

## Secrets, logging, and privacy

Raw secret candidates may exist transiently in memory only for local detection. Never write them to diagnostics, logs, exception text, reports, fingerprints, suppression entries, telemetry, or AI requests. `Evidence.redacted_snippet` must contain masked text or a non-reversible descriptor; structured evidence must obey the same policy. Redact at finding creation **and** at normalization/output boundaries. Show at most a short safe prefix/suffix when its type permits, otherwise `[REDACTED]`; do not expose enough characters to reconstruct a credential. Hashing full secrets into a public fingerprint is also prohibited. Test with clearly fake credentials only.

Default logs include counts, safe relative paths, scanner IDs, and sanitized error codes. Debug/verbose logs obey the same redaction policy and do not dump source. AI request logging is disabled by default and, if added, logs only sanitized metadata. Online lookups receive package coordinates only when explicitly enabled; AI receives a minimal redacted excerpt, never a whole repository upload.

## Reporting and remediation

Treat source snippets, file names, rule metadata, and adapter output as untrusted display data. Escape HTML and remove/control-render terminal escape and control characters. JSON serializers output valid escaped strings and only normalized findings. Reporter output paths must not resolve inside a scanned target by default. Reports must state skipped files and incomplete coverage so a partial scan cannot look clean.

**DO NOT AUTO-MODIFY TARGET CODE.** Future patch flow: Finding → proposed patch → static validation → human approval → apply. Validation must check target identity, patch scope, expected old content, and no path escape. A proposal is data, not permission to write.
