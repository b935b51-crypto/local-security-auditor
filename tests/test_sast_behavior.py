"""Phase 3 security regression tests: hostile fixtures are read only, never run."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
import ast
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import BehaviorLimits, SASTLimits, load_config
from security_auditor.core.models import Confidence, ScanProfile, ScanSession, ScanTarget
from security_auditor.discovery import DiscoveryPolicy, discover
from security_auditor.scanners.behavior import BehaviorScanner
from security_auditor.scanners.sast import SASTScanner
from security_auditor.scanners.sast.python.engine import PythonTaintAnalyzer


class Phase3ScannerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="auditor-phase3-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.session = ScanSession("synthetic", ScanTarget(self.root, "synthetic"),
                                   ScanProfile.STANDARD, datetime.now(timezone.utc))

    def write(self, path: str, content: str | bytes):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)

    def scan(self, scanner):
        return scanner.scan_discovery(self.session, discover(self.session.target, DiscoveryPolicy()))

    def test_sast_tainted_sinks_and_aliases(self):
        self.write("app.py", """import os as platform
import subprocess as proc
import pickle as p
from flask import request
from pathlib import Path
cmd = input()
proc.run(cmd, shell=True)
platform.system(cmd)
query = 'SELECT * FROM users WHERE name=' + request.args['name']
cursor.execute(query)
Path(request.args['file']).open()
p.loads(request.args['payload'])
eval(input())
""")
        result = self.scan(SASTScanner())
        self.assertEqual(result.status, "completed")
        self.assertEqual({finding.rule_id for finding in result.findings}, {
            "SAST.PYTHON.COMMAND_INJECTION", "SAST.PYTHON.SQL_INJECTION",
            "SAST.PYTHON.PATH_TRAVERSAL", "SAST.PYTHON.UNSAFE_DESERIALIZATION",
            "SAST.PYTHON.DYNAMIC_CODE_EXEC",
        })
        self.assertTrue(all(finding.source for finding in result.findings))
        self.assertTrue(all(finding.sink for finding in result.findings))

    def test_sast_negative_guard_parameterization_and_reassignment(self):
        self.write("safe.py", """import subprocess, shlex, os, yaml
cmd = input()
subprocess.run([cmd], shell=False)
subprocess.run(shlex.quote(cmd), shell=True)
cmd = 'fixed'
os.system(cmd)
name = input()
cursor.execute('SELECT * FROM users WHERE name=?', (name,))
yaml.safe_load(input())
yaml.load('x', Loader=yaml.SafeLoader)
""")
        result = self.scan(SASTScanner())
        self.assertEqual(result.status, "completed")
        self.assertFalse(result.findings)

    def test_sast_branch_merge_and_static_misconfiguration(self):
        self.write("branch.py", """import os, requests, tempfile, yaml
if input():
    value = input()
else:
    value = 'safe'
os.system(value)
requests.get('https://example.invalid', verify=False)
yaml.load('x', Loader=yaml.Loader)
tempfile.mktemp()
""")
        result = self.scan(SASTScanner())
        self.assertEqual({finding.rule_id for finding in result.findings}, {
            "SAST.PYTHON.COMMAND_INJECTION", "SAST.PYTHON.TLS_VERIFY_DISABLED",
            "SAST.PYTHON.UNSAFE_YAML_LOAD", "SAST.PYTHON.INSECURE_TEMP_FILE",
        })

    def test_sql_format_with_unused_parameter_remains_tainted(self):
        self.write("query.py", """name = input()
cursor.execute('SELECT * FROM users WHERE name={}'.format(name), ())
""")
        result = self.scan(SASTScanner())
        self.assertEqual([f.rule_id for f in result.findings], ["SAST.PYTHON.SQL_INJECTION"])

    def test_route_parameter_and_scope_are_local(self):
        self.write("routes.py", """import os
@app.get('/run')
def run(command):
    os.system(command)
def safe():
    command = 'fixed'
    os.system(command)
""")
        result = self.scan(SASTScanner())
        self.assertEqual([f.rule_id for f in result.findings], ["SAST.PYTHON.COMMAND_INJECTION"])

    def test_behavior_python_neutral_signals_and_local_correlation(self):
        self.write("activity.py", """import os, subprocess, requests, winreg, shutil
response = requests.get('https://example.invalid/tool.exe')
open('tool.exe', 'wb').write(response.content)
subprocess.run(['tool.exe'])
subprocess.run(['powershell.exe', '-EncodedCommand', 'FAKE_PAYLOAD'])
os.system('echo hello')
winreg.SetValueEx(key, 'Run', 0, 1, 'value')
shutil.rmtree('build')
""")
        result = self.scan(BehaviorScanner())
        self.assertEqual(result.status, "completed")
        ids = {finding.rule_id for finding in result.findings}
        self.assertTrue({"BEHAVIOR.NETWORK_REQUEST", "BEHAVIOR.DOWNLOAD_EXECUTE",
                         "BEHAVIOR.PROCESS_EXEC", "BEHAVIOR.POWERSHELL_EXEC",
                         "BEHAVIOR.ENCODED_COMMAND", "BEHAVIOR.RECURSIVE_DELETE",
                         "BEHAVIOR.REGISTRY_WRITE", "BEHAVIOR.SHELL_EXEC"} <= ids)
        self.assertNotIn("SAST.PYTHON.COMMAND_INJECTION", ids)
        self.assertTrue(all(finding.confidence in Confidence for finding in result.findings))

    def test_behavior_text_language_rules_and_long_line(self):
        self.write("setup.ps1", "Invoke-WebRequest https://example.invalid -OutFile tool.exe\nStart-Process tool.exe\nSet-MpPreference -DisableRealtimeMonitoring $true\n")
        self.write("setup.cmd", "powershell.exe -EncodedCommand FAKE_PAYLOAD\nreg add HKCU\\Software\\Example\n")
        self.write("deploy.sh", "curl https://example.invalid\nrm -rf ./build\n")
        self.write("script.js", "child_process.exec('echo example')\nfetch('https://example.invalid')\n")
        result = self.scan(BehaviorScanner())
        ids = {finding.rule_id for finding in result.findings}
        self.assertTrue({"BEHAVIOR.DOWNLOAD_EXECUTE", "BEHAVIOR.SECURITY_CONTROL",
                         "BEHAVIOR.ENCODED_COMMAND", "BEHAVIOR.REGISTRY_WRITE",
                         "BEHAVIOR.RECURSIVE_DELETE", "BEHAVIOR.NETWORK_REQUEST",
                         "BEHAVIOR.PROCESS_EXEC"} <= ids, sorted(ids))
        self.assertTrue(all(finding.confidence in {Confidence.MEDIUM, Confidence.LOW} for finding in result.findings))
        limited = self.scan(BehaviorScanner(replace(BehaviorLimits(), max_line_bytes=12)))
        self.assertEqual(limited.status, "partial")
        self.assertIn("BEHAVIOR_LINE_TOO_LONG", {diagnostic.code for diagnostic in limited.diagnostics})

    def test_malformed_and_budget_diagnostics(self):
        self.write("bad.py", "def broken(:\n    pass\n")
        self.write("complex.py", "x = [1, 2, 3, 4, 5]\n")
        sast = self.scan(SASTScanner(replace(SASTLimits(), max_ast_nodes=5)))
        behavior = self.scan(BehaviorScanner(replace(BehaviorLimits(), max_ast_nodes=5)))
        self.assertEqual(sast.status, "partial")
        self.assertEqual(behavior.status, "partial")
        self.assertIn("SAST_PARSE_FAILED", {d.code for d in sast.diagnostics})
        self.assertIn("SAST_AST_NODE_LIMIT_REACHED", {d.code for d in sast.diagnostics})
        self.assertIn("BEHAVIOR_PARSE_FAILED", {d.code for d in behavior.diagnostics})
        self.assertIn("BEHAVIOR_AST_NODE_LIMIT_REACHED", {d.code for d in behavior.diagnostics})

    def test_parse_failure_does_not_stop_other_file(self):
        self.write("bad.py", "def broken(:\n")
        self.write("good.py", "import os\nos.system(input())\n")
        result = self.scan(SASTScanner())
        self.assertEqual(result.status, "partial")
        self.assertEqual([f.location.path for f in result.findings], ["good.py"])
        self.assertIn("SAST_PARSE_FAILED", {d.code for d in result.diagnostics})

    def test_rule_error_is_diagnostic_and_other_rule_continues(self):
        self.write("rules.py", "import os, tempfile\nos.system(input())\ntempfile.mktemp()\n")
        original = PythonTaintAnalyzer._check_call

        def fail_one(analyzer, call, env, aliases):
            if isinstance(call.func, ast.Attribute) and call.func.attr == "system":
                raise RuntimeError("FAKE_SECRET_MUST_NOT_LEAK")
            return original(analyzer, call, env, aliases)

        with patch.object(PythonTaintAnalyzer, "_check_call", fail_one):
            result = self.scan(SASTScanner())
        self.assertEqual(result.status, "partial")
        self.assertIn("SAST_RULE_ERROR", {d.code for d in result.diagnostics})
        self.assertIn("SAST.PYTHON.INSECURE_TEMP_FILE", {f.rule_id for f in result.findings})
        self.assertNotIn("FAKE_SECRET_MUST_NOT_LEAK", repr(result))

    def test_no_source_or_fake_secret_in_result_and_no_target_execution(self):
        marker = self.root / "EXECUTED"
        fake = "FAKE_SECRET_ONLY_DO_NOT_USE_123456"
        self.write("hostile.py", f"import os\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('danger')\nvalue = input()\nos.system(value)\ncredential = {fake!r}\n")
        sast = self.scan(SASTScanner())
        behavior = self.scan(BehaviorScanner())
        self.assertFalse(marker.exists())
        for result in (sast, behavior):
            serialized = json.dumps(asdict(result), default=str)
            self.assertNotIn(fake, serialized)
            self.assertNotIn(fake, repr(result))
            self.assertNotIn("danger", serialized)

    def test_provider_shaped_secret_in_filename_is_redacted(self):
        fake_token = "ghp_" + "A1b2C3d4" * 4 + "E5f6"
        self.write(f"{fake_token}.py", "import os\nos.system(input())\n")
        for scanner in (SASTScanner(), BehaviorScanner()):
            result = self.scan(scanner)
            self.assertTrue(result.findings)
            self.assertNotIn(fake_token, repr(result))
            self.assertNotIn(fake_token, json.dumps(asdict(result), default=str))

    def test_config_tables_and_invalid_limits(self):
        path = self.root / "security-auditor.toml"
        path.write_text("[sast]\nmax_ast_nodes=9000\n[behavior]\nmax_line_bytes=2048\n", encoding="utf-8")
        config = load_config(path)
        self.assertEqual(config.sast.max_ast_nodes, 9000)
        self.assertEqual(config.behavior.max_line_bytes, 2048)
        path.write_text("[sast]\nmax_ast_nodes=999999999\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(path)

    def test_byte_caps_and_stable_redacted_fingerprint(self):
        self.write("one.py", "import os\nos.system(input())\n")
        self.write("two.py", "import os\nos.system(input())\n")
        first = self.scan(SASTScanner())
        second = self.scan(SASTScanner())
        self.assertEqual([f.fingerprint for f in first.findings],
                         [f.fingerprint for f in second.findings])
        capped = self.scan(SASTScanner(replace(SASTLimits(), max_total_bytes=30)))
        self.assertEqual(capped.status, "aborted")
        self.assertIn("SAST_TOTAL_BYTE_BUDGET_REACHED", {d.code for d in capped.diagnostics})
        behavior = self.scan(BehaviorScanner(replace(BehaviorLimits(), max_file_bytes=8)))
        self.assertEqual(behavior.status, "partial")
        self.assertIn("BEHAVIOR_FILE_TOO_LARGE", {d.code for d in behavior.diagnostics})

    def test_scanner_code_has_no_target_execution_calls(self):
        root = Path(__file__).resolve().parents[1] / "src" / "security_auditor" / "scanners"
        for package in ("sast", "behavior"):
            for file in (root / package).rglob("*.py"):
                tree = ast.parse(file.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, {"eval", "exec", "__import__"})
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                                   else [node.module or ""])
                        self.assertFalse(any(name == "subprocess" or name.startswith("subprocess.")
                                             for name in modules))

    def test_phase3_document_links_and_project_skills(self):
        project = Path(__file__).resolve().parents[1]
        documents = [project / name for name in ("README.md", "AGENTS.md", "PROJECT_STATUS.md")]
        documents.extend((project / "docs").glob("*.md"))
        documents.extend((project / ".agents" / "skills").glob("*/SKILL.md"))
        for document in documents:
            text = document.read_text(encoding="utf-8")
            for destination in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
                if "://" not in destination and not destination.startswith("#"):
                    self.assertTrue((document.parent / destination.split("#", 1)[0]).exists(),
                                    f"broken local link in {document.name}")
        for skill in ("safe-untrusted-code-analysis", "security-scanner-architecture"):
            skill_text = (project / ".agents" / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(skill_text.startswith("---\nname: " + skill + "\n"))


if __name__ == "__main__":
    unittest.main()
