# Project Status

- Last updated: 2026-09-23 (Asia/Taipei)
- Current phase: Phase 2 — Secret Scanner
- Objective: detect credential-like material in Phase 1 admitted text artifacts without leaking matched values
- Status: Phase 2 implemented and validated on Python 3.14.7, with verification limits below

## Completed

- APPS v1 project guidance, Phase 0 architecture, and Phase 1 bounded discovery remain in place.
- Native synchronous `SecretScanner` implements the existing `Scanner` protocol and a preferred `scan_discovery` entry that retains Phase 1 completeness. It never traverses a target independently.
- `discovery/content.py` reopens admitted regular files with bounded reads and fresh root, reparse, containment, identity, size, and modification-time checks.
- Private-key markers; GitHub, AWS, Stripe, Slack, and GitLab token shapes; password-bearing connection URLs; JWT shape; credential assignments; and context-gated entropy detection produce normalized redacted `Finding` objects.
- Placeholder, empty/null, environment/secret-manager reference, UUID, public-certificate/key, and hash-context handling reduces false positives. Overlapping candidates use deterministic precedence. AWS ID plus nearby secret assignment changes assessment.
- Secret-specific byte, line, match, finding, and elapsed-time caps; fixed-message diagnostics; summary counts; and `complete|partial|aborted|failed` coverage are implemented.
- [Secret Scanner](docs/SECRET_SCANNER.md), architecture/security/finding/scanner/roadmap docs, example config, and architecture project skill are updated.
- Local implementation checkpoint: `230e782` (`feat: implement secret scanner`). No remote push.

## In progress

- No Phase 2 implementation remains in progress. Phase 3 has not started.

## Decisions

- Python baseline remains `>=3.12,<3.13` with uv and no runtime dependencies. Python 3.12 is absent on this host.
- Target code is hostile data, never executed or imported. The scanner reads only Phase 1 admitted artifacts; reparse traversal remains denied.
- Redaction precedes `Finding`; raw secret values never intentionally enter candidates, findings, diagnostics, logs, or public fingerprints. Python memory zeroization cannot be guaranteed.
- Public fingerprints use rule, relative path, position, family, and safe label, not a secret hash. Cross-file reuse correlation waits for safe HMAC key management.
- Oversize files and overlong lines are skipped with incomplete status. No active validation, Git history inspection, network lookup, external secret tool, AI, or Phase 3 code is present.

## Verification

- Tested on Python 3.14.7: `$env:PYTHONDONTWRITEBYTECODE='1'; $env:PYTHONPATH='src'; py -3.14 -m unittest discover -s tests -v` — 36 tests, 35 passed, 1 skipped (real Windows symlink creation unavailable). Includes serialization/private-key leakage, no-log rule error, placeholders, hash/UUID, UTF-16, changed file, limits, adversarial long line, provider shapes, and completeness.
- Tested on Python 3.14.7: package/SecretScanner import, example config load, Python AST parses, Markdown relative links, and both project Skill frontmatter passed a standard-library validation script.
- Tested: `git diff --cached --check` passed before implementation checkpoint. No lint or formatter is configured.
- Unable to verify on Python 3.12: `py -3.12 --version` reports no suitable runtime. No system/global Python change was made. **Python 3.12 baseline not yet verified.**
- Not verified: real Windows symlink/junction traversal, UNC/network filesystem identity, long paths, or race-free containment under concurrent mutation. The path-based reopen is not a handle-relative sandbox.
- Not verified: current provider-issued token formats or live credential validity. The global Skill validator requires an unavailable `yaml` package; project Skill frontmatter and links were checked without it.

## Git and next action

- Branch `main`; implementation checkpoint `230e782`. Global Git author identity is unset; commits use one-command `Codex <codex@localhost>`. Inspect `git status` and `git log` for the final status-document checkpoint and live working tree.
- Only upon a new user request, begin Phase 3 — SAST + Dangerous Behavior Scanner. Preserve Phase 1 discovery and Phase 2 raw-secret boundaries; verify Python 3.12 when available.
