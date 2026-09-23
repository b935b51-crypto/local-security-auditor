"""argparse entry point with stable exit codes and pure machine stdout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from security_auditor import __version__
from security_auditor.core.config import AuditConfig, load_config
from security_auditor.core.models import ScanProfile
from security_auditor.gate import GateReportError, evaluate_gate, load_report, result_view
from security_auditor.orchestrator import ScanOrchestrator, ScanRequest
from security_auditor.reporting import console, html, json_report, sarif
from security_auditor.reporting.output import ReportOutputError, write_text
from security_auditor.reporting.serialization import report_view

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_SCAN = 3
EXIT_OUTPUT = 4
EXIT_THRESHOLD = 10


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="security-auditor",
                                   description="Static security analysis of an untrusted local folder")
    root.add_argument("--version", action="version", version=f"security-auditor {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a local directory without executing its code")
    scan.add_argument("path", type=Path)
    scan.add_argument("--profile", choices=[x.value for x in ScanProfile])
    scan.add_argument("--format", choices=("console", "json", "sarif", "html"), default="console")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--force", action="store_true", help="replace an existing regular report file")
    scan.add_argument("--offline", action="store_true", help="disable all network providers")
    ai = scan.add_mutually_exclusive_group()
    ai.add_argument("--ai", action="store_true", help="explicitly request online Gemini advisory review")
    ai.add_argument("--no-ai", action="store_true", help="disable AI review")
    scan.add_argument("--config", type=Path, help="explicit trusted operator config")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"))
    scan.add_argument("--propose-fixes", action="store_true",
                      help="generate remediation guidance and non-applied patch proposals")
    scan.add_argument("--ai-remediation", action="store_true",
                      help="explicitly request Gemini patch proposals; requires --propose-fixes")
    gate = commands.add_parser("gate", help="evaluate a canonical JSON report without rescanning")
    gate.add_argument("report", type=Path)
    gate.add_argument("--format", choices=("console", "json"), default="console")
    commands.add_parser("gui", help="open the local read-only Windows desktop interface")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "gate":
        try:
            result = evaluate_gate(load_report(args.report))
        except GateReportError as error:
            print(f"Gate failed: {error.code}", file=sys.stderr)
            return EXIT_SCAN
        if args.format == "json":
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
            sys.stdout.write(json.dumps(result_view(result), sort_keys=True,
                                        separators=(",", ":")) + "\n")
        else:
            print(f"Security gate: {result.status.value} | coverage: {result.coverage_status}"
                  f" | policy: {result.policy_version}")
            for reason in result.reasons:
                print(f"- {reason}")
            print(f"Blocking primary findings: {len(result.blocking_findings)}; "
                  f"warnings: {len(result.warning_findings)}")
        return {"PASS": 0, "WARN": 10, "BLOCK": 20}[result.status.value]
    if args.command == "gui":
        try:
            from security_auditor.gui.app import run_gui
            return run_gui()
        except ImportError:
            print("GUI unavailable: Tk runtime is not installed", file=sys.stderr)
            return EXIT_USAGE
    if args.format == "html" and args.output is None:
        print("HTML output requires --output", file=sys.stderr)
        return EXIT_USAGE
    if args.ai_remediation and not args.propose_fixes:
        print("--ai-remediation requires --propose-fixes", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(args.config) if args.config else AuditConfig()
        request = ScanRequest(args.path, config,
                              ScanProfile(args.profile) if args.profile else None,
                              True if args.offline else None, args.ai, args.no_ai,
                              args.propose_fixes, args.ai_remediation)
    except (OSError, ValueError, TypeError):
        print("Invalid trusted configuration or scan options", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = ScanOrchestrator().run_scan(request)
    except KeyboardInterrupt:
        print("Scan interrupted", file=sys.stderr)
        return EXIT_SCAN
    except Exception:
        print("Scan failed: internal error", file=sys.stderr)
        return EXIT_SCAN
    if report.coverage.overall.value == "FAILED":
        print("Scan could not start; target validation failed", file=sys.stderr)
        return EXIT_SCAN
    try:
        if args.format == "console":
            rendered = console.render(report, verbose=args.verbose)
        elif args.format == "json":
            rendered = json_report.render(report)
        elif args.format == "sarif":
            rendered = sarif.render(report)
        else:
            rendered = html.render(report)
        if args.output:
            write_text(args.output, rendered, force=args.force)
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
            sys.stdout.write(rendered)
        if args.verbose:
            for diagnostic in report_view(report)["diagnostics"][:50]:
                print(f"{diagnostic['source']}:{diagnostic['code']} {diagnostic['path'] or ''}",
                      file=sys.stderr)
    except ReportOutputError as error:
        print(f"Report output failed: {error.code}", file=sys.stderr)
        return EXIT_OUTPUT
    except KeyboardInterrupt:
        print("Report output interrupted", file=sys.stderr)
        return EXIT_OUTPUT
    except (OSError, UnicodeError, ValueError):
        print("Report output failed: REPORT_SERIALIZATION_FAILED", file=sys.stderr)
        return EXIT_OUTPUT
    if args.fail_on:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        roles = dict(report.roles)
        if any(rank[f.severity.value.lower()] <= rank[args.fail_on] and
               roles.get(f.fingerprint, "primary") == "primary"
               for result in report.scanner_results for f in result.findings):
            return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
