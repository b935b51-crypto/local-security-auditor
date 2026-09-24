# Windows desktop GUI

Phase 9 uses Python's standard-library `tkinter/ttk` with native Windows folder and save dialogs. PySide6/PyQt offer richer tables and accessibility APIs but add a large binary dependency and deployment surface; Tauri/React/WebView add a second runtime, packaging complexity, and a web content boundary. Tk keeps startup and distribution simple, works offline, calls the Python core directly, and leaves the CLI independent of a GUI extra. The full automated offline suite passes with uv-managed Python 3.12.11; manual Tk smoke was performed with Python 3.14. Accessibility with assistive technology, high-DPI behavior, Python 3.12 standalone packaging, and a standalone executable remain unverified. There is **no added GUI dependency** or local HTTP server.

| Criterion | Tk/ttk (chosen) | Qt/PySide6 or PyQt | Tauri/React/WebView |
| --- | --- | --- | --- |
| Windows and Python core | Direct process call; native picker | Direct Python binding; native picker | Bridge between Rust/JS and Python core |
| Package size/startup | Standard-library runtime; small and fast | Large native wheels; richer widgets | Multiple runtimes and frontend assets |
| Accessibility and dark mode | Native semantics for basic controls; custom theme work | Stronger widget/theming support | Web accessibility tooling, extra content security boundary |
| Large table/tree | Adequate for canonical 1,000-finding cap | Best headroom for larger datasets | Depends on frontend virtualization |
| Distribution/maintenance | Wheel plus Python/Tk installation; no new dependency | Optional GUI extra and Qt bundling | Separate toolchain, bridge, and packaging path |
| Offline/security surface | No HTTP server or web content renderer | No server, but larger dependency surface | WebView/bridge and possible local service surface |

The v1 interface uses a deliberate light, information-dense palette: deep blue navigation, high-contrast neutral surfaces, and distinct status colors with text labels. Tables favor readable evidence over decoration; no animations or graphs are needed. Dark mode is deferred until both themes can be verified for contrast and focus visibility.

## Start and workflow

From an installed package: `security-auditor gui`. From this checkout under the uv-managed Python 3.12.11 environment: `uv run security-auditor gui`. GUI automation tests passed under Python 3.12.11; manual native display verification remains from Python 3.14.

Choose **Scan folder**, then profile and per-scan options. Offline is selected by default. OSV live lookup and Gemini review are separate online check boxes; Gemini remediation requires another separate check box plus proposals. Choosing Gemini alone does not silently enable OSV. No setting, API key, source path, report, or scan history is persisted by the GUI. The GUI never reads or displays a key; its default controller can use a trusted process `GEMINI_API_KEY` if the existing provider is explicitly enabled. It does not load a target `.env` or expose a trusted config-directory picker. **Open report** reads only bounded canonical JSON 1.1, validates it, and never re-scans or contacts providers.

Navigation includes Dashboard, Findings, Risks, Secrets, SAST, Behaviors, Dependencies, AI Reviews, Remediation, Gate, Diagnostics, Reports, and Settings. The dashboard shows target, profile, coverage, gate, severity/priority, external service use, attack path count, proposals, and diagnostics. A prominent banner distinguishes COMPLETE, PARTIAL, ABORTED, and FAILED. Zero findings under partial coverage explicitly says only the analyzed portion had no findings. The Findings table defaults to primary findings and supports search, category/severity/priority/AI filters, sorting, and optional supporting signals. Detail keeps deterministic evidence, relationships, AI advice, and remediation visually labeled as different kinds of information. Risks are shown as a bounded text/group view, not a node graph.

The remediation pane presents guidance, static validation, limitations, human-approval requirement, `NOT_RUN` runtime status, and the **public redacted diff only**. Copy uses that same public diff and rejects an omitted diff. There is no Apply, Fix, Save to Source, or target test action. JSON/SARIF/HTML export of a live `ScanReport` uses the existing reporters and safe atomic writer. An opened JSON report remains a read-only viewer; fresh scan is required to export another format. Existing files are not silently overwritten.

## Architecture and safety

`gui/controller.py` is the application boundary: GUI → `ApplicationController` → `ScanOrchestrator` → immutable `ScanReport` → public whitelist view and shared `evaluate_gate`. The GUI never calls a scanner directly. One worker thread runs the bounded orchestrator; only the Tk main thread updates widgets. A queue transfers fixed progress stages and completion/errors. Cancellation is cooperative at discovery iteration and between scanner phases; a single in-flight parser, provider request, or bounded scanner operation may finish before cancellation is observed. A canceled report is `ABORTED` with `SCAN_CANCELLED`, retains already completed results, and gates to `BLOCK`. No guessed percentage is shown.

Target code is never executed or modified. Tk widgets receive plain text after redaction and removal of escape/bidirectional control characters; no HTML/Markdown is interpreted. No external links are opened, and the interface does not launch target files via OS associations. Error dialogs show fixed diagnostic codes, never raw exceptions. Report loading has a 16 MiB cap, duplicate-key rejection, schema/field validation, and no pickle. Export uses an explicit user-selected path and the Phase 7 output writer. GUI crashes cannot create a target patch; provider egress remains under the existing explicit grant.

## Current limits

Tk table rendering is capped by the canonical report's 1,000 findings; sorting/searching are in-memory. Cancellation is cooperative, not a hard thread kill. There is no persistent manual gate override, persistent scan history, graph visualization, installer, or standalone `.exe`. Native screen-reader and high-DPI behavior need manual Windows verification. The file picker and Tk availability were manually checked on Windows 11 with Python 3.14; Python 3.12 packaging is not verified.
