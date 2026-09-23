# Codex defensive scan and gate workflow

The project-scoped [security-auditor Skill](../.agents/skills/security-auditor/SKILL.md) describes this workflow. An operator may copy that Skill into their global Codex skill directory, but this repository does not alter global skills. Codex can invoke the installed `security-auditor` after authorized development work to check a trusted working copy. The auditor treats that copy as **untrusted data** and never executes it.

1. Produce a new report outside the scan root when possible: `security-auditor scan <path> --offline --format json --output <new-report.json>`.
2. Evaluate it: `security-auditor gate <new-report.json> --format json`.
3. Read `coverage_status` before drawing any conclusion. `PASS` requires COMPLETE coverage; `WARN` calls for review; `BLOCK` calls for investigation of primary deterministic findings or incomplete coverage. The gate's exit codes are in [Security Gate](SECURITY_GATE.md).
4. Review primary findings, related risk assessments, optional AI advisory, and remediation guidance in the JSON or GUI. Supporting behavior signals are context, not additional blockers. AI cannot override a HIGH deterministic finding. A proposed patch is not permission to apply it.
5. If the user has authorized edits to their trusted project, inspect the code and make an independently reasoned change through the normal coding workflow. Then run the auditor and gate again. If coverage is partial, address scanner availability or coverage limits instead of declaring success.

Do not suppress rules, weaken scanner config, change the auditor itself, or blindly apply an AI patch to make a gate pass. Scanning an unfamiliar target never authorizes running its tests, package managers, scripts, or executables. Online OSV and Gemini require separate trusted choices; the documented workflow is offline by default. The gate evaluates a report as data and does not verify its authenticity; preserve report provenance in CI/Codex workflows.
