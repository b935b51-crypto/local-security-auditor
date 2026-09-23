"""Passive discovery tests. Every tree is synthetic data, never executed."""

from dataclasses import replace
from pathlib import Path
import ast
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import AuditConfig, DiscoveryLimits, load_config
from security_auditor.core.models import (  # noqa: E402
    ArtifactKind, Confidence, ContentKind, ManifestKind, ScanTarget,
)
from security_auditor.discovery import DiscoveryPolicy, ScanCompleteness, discover  # noqa: E402
from security_auditor.discovery.classifier import classify  # noqa: E402
from security_auditor.discovery.models import DiagnosticCode, SkipReason  # noqa: E402
from security_auditor.discovery.path_safety import is_reparse_point, is_within_root, safe_display, unsafe_component  # noqa: E402
from security_auditor.discovery.platform.identity import file_identity  # noqa: E402
from security_auditor.discovery.policy import pattern_matches  # noqa: E402
from security_auditor.discovery.sniffing import sniff_prefix  # noqa: E402


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="auditor-phase1-")
        self.addCleanup(self.temp.cleanup)
        self.sandbox = Path(self.temp.name)
        self.root = self.sandbox / "repo"
        self.root.mkdir()

    def write(self, relative: str, data: bytes = b"safe example\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, policy: DiscoveryPolicy | None = None):
        return discover(ScanTarget(self.root, "synthetic"), policy or DiscoveryPolicy())

    def test_root_validation_and_component_boundary(self):
        missing = discover(ScanTarget(self.sandbox / "missing", "missing"), DiscoveryPolicy())
        self.assertEqual(missing.completeness, ScanCompleteness.FAILED)
        self.assertEqual(missing.diagnostics[0].code, DiagnosticCode.ROOT_NOT_FOUND)
        file_root = self.write("one.txt")
        result = discover(ScanTarget(file_root, "file"), DiscoveryPolicy())
        self.assertEqual(result.completeness, ScanCompleteness.FAILED)
        self.assertEqual(result.diagnostics[0].code, DiagnosticCode.ROOT_NOT_DIRECTORY)
        sibling = self.sandbox / "repo-evil"
        sibling.mkdir()
        self.assertFalse(is_within_root(self.root.resolve(), sibling))
        self.assertTrue(is_within_root(self.root.resolve(), file_root))
        trailing = discover(ScanTarget(Path(str(self.root) + os.sep), "trailing"), DiscoveryPolicy())
        self.assertEqual(trailing.completeness, ScanCompleteness.COMPLETE)
        dotted = discover(ScanTarget(self.root / ".", "dotted"), DiscoveryPolicy())
        self.assertEqual(dotted.completeness, ScanCompleteness.COMPLETE)

    def test_normal_tree_and_no_findings(self):
        self.write("app.py", b"print('synthetic')\n")
        self.write("config.json", b"{}\n")
        self.write("package.json", b"{}\n")
        self.write(".env", b"EXAMPLE=NOT_A_SECRET\n")
        self.write("image.png", b"\x89PNG\r\n\x1a\nFAKE")
        result = self.scan()
        by_path = {item.path: item for item in result.artifacts}
        self.assertEqual(result.completeness, ScanCompleteness.COMPLETE)
        self.assertEqual(len(by_path), 5)
        self.assertEqual(by_path["app.py"].kind, ArtifactKind.SOURCE_CODE)
        self.assertEqual(by_path["app.py"].language.language, "python")
        self.assertEqual(by_path["config.json"].kind, ArtifactKind.CONFIG)
        self.assertEqual(by_path["package.json"].kind, ArtifactKind.DEPENDENCY_MANIFEST)
        self.assertEqual(by_path[".env"].kind, ArtifactKind.ENV_FILE)
        self.assertEqual(by_path["image.png"].content_kind, ContentKind.BINARY)
        self.assertEqual(result.summary.stats.files_inspected, 5)
        self.assertEqual(result.summary.stats.files_discovered, 5)

    def test_manifest_lockfile_and_ci_roles(self):
        cases = {
            "pyproject.toml": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.PYTHON),
            "requirements-dev.txt": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.PYTHON),
            "uv.lock": (ArtifactKind.LOCKFILE, ManifestKind.PYTHON),
            "pnpm-lock.yaml": (ArtifactKind.LOCKFILE, ManifestKind.NODE),
            "Cargo.toml": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.RUST),
            "go.sum": (ArtifactKind.LOCKFILE, ManifestKind.GO),
            "project.csproj": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.DOTNET),
            "pom.xml": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.JAVA),
            "Gemfile.lock": (ArtifactKind.LOCKFILE, ManifestKind.RUBY),
            "composer.json": (ArtifactKind.DEPENDENCY_MANIFEST, ManifestKind.PHP),
        }
        for name in cases:
            self.write(name)
        self.write(".github/workflows/check.yml")
        self.write("Dockerfile")
        self.write("private.pem")
        result = self.scan()
        by_path = {item.path: item for item in result.artifacts}
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual((by_path[name].kind, by_path[name].manifest_kind), expected)
        self.assertEqual(by_path[".github/workflows/check.yml"].kind, ArtifactKind.CI_CONFIG)
        self.assertEqual(by_path["Dockerfile"].kind, ArtifactKind.CONTAINER_CONFIG)
        self.assertEqual(by_path["private.pem"].kind, ArtifactKind.KEY_MATERIAL_LIKE)

    def test_binary_masquerade_and_archive_inert(self):
        self.write("malware.py", b"MZFAKE-NOT-AN-EXECUTABLE\x00")
        self.write("data.txt", b"PK\x03\x04FAKE-ZIP")
        result = self.scan()
        by_path = {item.path: item for item in result.artifacts}
        self.assertEqual(by_path["malware.py"].content_kind, ContentKind.BINARY)
        self.assertEqual(by_path["malware.py"].kind, ArtifactKind.EXECUTABLE)
        self.assertIsNone(by_path["malware.py"].language.language)
        self.assertTrue(by_path["malware.py"].is_executable_like)
        self.assertEqual(by_path["data.txt"].kind, ArtifactKind.ARCHIVE)

    def test_sniff_encoding_shebang_and_long_line(self):
        utf16 = sniff_prefix(b"\xff\xfe" + "hello".encode("utf-16-le"), max_line_length=100)
        self.assertEqual((utf16.content_kind, utf16.encoding), (ContentKind.TEXT, "utf-16-le"))
        bad = sniff_prefix(b"\xff\xffgarbage", max_line_length=100)
        self.assertTrue(bad.decode_failed)
        self.assertEqual(bad.content_kind, ContentKind.UNKNOWN)
        script = classify("tool", sniff_prefix(b"#!/usr/bin/env python3\npass\n", max_line_length=100))
        self.assertEqual(script.language.language, "python")
        self.assertEqual(script.language.confidence, Confidence.HIGH)
        self.assertEqual(script.kind, ArtifactKind.SCRIPT)
        long = sniff_prefix(b"a" * 100, max_line_length=10)
        self.assertTrue(long.long_line)
        self.assertIsNone(long.first_line)

    def test_language_and_windows_script_hints(self):
        plain = sniff_prefix(b"safe synthetic text\n", max_line_length=100)
        cases = {
            "a.py": "python", "a.js": "javascript", "a.ts": "typescript",
            "a.tsx": "tsx", "a.jsx": "jsx", "a.ps1": "powershell",
            "a.cmd": "batch", "a.sh": "shell", "a.c": "c", "a.cpp": "c++",
            "a.cs": "c#", "a.java": "java", "a.kt": "kotlin",
            "a.go": "go", "a.rs": "rust", "a.rb": "ruby",
            "a.php": "php", "a.swift": "swift", "a.sql": "sql",
            "a.html": "html", "a.css": "css", "a.json": "json",
            "a.yaml": "yaml", "a.toml": "toml", "a.xml": "xml",
            "a.md": "markdown",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(classify(name, plain).language.language, expected)
        self.assertEqual(classify("script.ps1", plain).kind, ArtifactKind.SCRIPT)
        self.assertEqual(classify("script.cmd", plain).kind, ArtifactKind.SCRIPT)

    def test_ignore_layers_include_override_and_windows_patterns(self):
        self.write(".gitignore", b".env\n")
        self.write(".env")
        self.write("src/app.py")
        self.write("nested/node_modules/dependency.py")
        self.write("build/generated.py")
        default = self.scan()
        self.assertIn(".env", {a.path for a in default.artifacts})
        self.assertIn("nested/node_modules", {s.path for s in default.skipped})
        self.assertTrue(pattern_matches("SRC\\*.PY", "src/app.py", is_directory=False, windows=True))
        self.assertFalse(pattern_matches("SRC\\*.PY", "src/app.py", is_directory=False, windows=False))
        with_gitignore = self.scan(DiscoveryPolicy(respect_gitignore=True))
        self.assertNotIn(".env", {a.path for a in with_gitignore.artifacts})
        override = self.scan(DiscoveryPolicy(include=("nested/node_modules/dependency.py",)))
        self.assertIn("nested/node_modules/dependency.py", {a.path for a in override.artifacts})
        self.assertTrue(any(s.reason is SkipReason.NOT_INCLUDED for s in override.skipped))

    def test_config_limits_and_reparse_opt_in_rejected(self):
        config = load_config(Path(__file__).resolve().parents[1] / "security-auditor.example.toml")
        policy = DiscoveryPolicy.from_config(config)
        self.assertFalse(policy.respect_gitignore)
        with self.assertRaises(ValueError):
            DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_file_count=999_999_999))
        with self.assertRaises(ValueError):
            DiscoveryPolicy(include=("../outside",))
        with self.assertRaises(ValueError):
            DiscoveryPolicy.from_config(replace(AuditConfig(), limits=replace(DiscoveryLimits(), max_entries=999_999_999)))

    def test_file_depth_entry_and_total_byte_budgets(self):
        for name in ("a.txt", "b.txt", "c.txt"):
            self.write(name, b"abc")
        files = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_file_count=2)))
        self.assertEqual(files.completeness, ScanCompleteness.ABORTED)
        self.assertIn(DiagnosticCode.MAX_FILES_REACHED, {d.code for d in files.diagnostics})
        entries = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_entries=2)))
        self.assertEqual(entries.completeness, ScanCompleteness.ABORTED)
        self.assertEqual(entries.artifacts, ())
        bytes_limited = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_total_bytes_inspected=4)))
        self.assertEqual(bytes_limited.completeness, ScanCompleteness.ABORTED)
        self.assertEqual(bytes_limited.summary.stats.bytes_inspected, 3)
        self.write("deep/nested/file.py")
        depth = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_directory_depth=1)))
        self.assertEqual(depth.completeness, ScanCompleteness.PARTIAL)
        self.assertIn(DiagnosticCode.MAX_DEPTH_REACHED, {d.code for d in depth.diagnostics})

    def test_directory_budget_and_mocked_reparse_point(self):
        self.write("a/one.py")
        self.write("b/two.py")
        limited = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_directories=1)))
        self.assertEqual(limited.completeness, ScanCompleteness.ABORTED)
        self.assertIn(DiagnosticCode.MAX_DIRECTORIES_REACHED, {d.code for d in limited.diagnostics})
        blocked = self.root / "blocked"
        blocked.mkdir()
        (blocked / "unread.py").write_bytes(b"safe data")
        blocked_ino = os.stat(blocked, follow_symlinks=False).st_ino
        actual = is_reparse_point
        with patch("security_auditor.discovery.service.is_reparse_point",
                   side_effect=lambda info: info.st_ino == blocked_ino or actual(info)):
            result = self.scan()
        self.assertNotIn("blocked/unread.py", {a.path for a in result.artifacts})
        self.assertIn(SkipReason.REPARSE_POINT, {s.reason for s in result.skipped})

    def test_invalid_gitignore_is_visible_in_completeness(self):
        self.write(".gitignore", b"\xff\xff")
        self.write("app.py")
        result = self.scan(DiscoveryPolicy(respect_gitignore=True))
        self.assertEqual(result.completeness, ScanCompleteness.PARTIAL)
        self.assertIn(DiagnosticCode.GITIGNORE_UNAVAILABLE, {d.code for d in result.diagnostics})
        self.assertIn("app.py", {a.path for a in result.artifacts})

    def test_file_size_and_bounded_read(self):
        self.write("large.txt", b"A" * 1000)
        limited = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_file_size_bytes=100)))
        self.assertEqual(limited.completeness, ScanCompleteness.PARTIAL)
        self.assertEqual(limited.skipped[0].reason, SkipReason.TOO_LARGE)
        bounded = self.scan(DiscoveryPolicy(limits=replace(DiscoveryLimits(), max_sniff_bytes=16, max_single_text_read=16)))
        self.assertEqual(bounded.artifacts[0].sniffed_bytes, 16)
        self.assertEqual(bounded.summary.stats.bytes_inspected, 16)

    def test_permission_failure_is_partial_and_other_tree_continues(self):
        self.write("denied/hidden.py")
        self.write("ok/visible.py")
        real_scandir = os.scandir

        def selective_scandir(path):
            if Path(path).name == "denied":
                raise PermissionError("synthetic private path should not be logged")
            return real_scandir(path)

        with patch("security_auditor.discovery.service.os.scandir", side_effect=selective_scandir):
            result = self.scan()
        self.assertEqual(result.completeness, ScanCompleteness.PARTIAL)
        self.assertIn("ok/visible.py", {a.path for a in result.artifacts})
        self.assertIn(DiagnosticCode.ACCESS_DENIED, {d.code for d in result.diagnostics})
        self.assertNotIn("synthetic private", str(result.diagnostics))

    def test_disappearing_file_is_partial(self):
        self.write("vanish.py")
        real_open = os.open

        def disappearing_open(path, flags, *args, **kwargs):
            if Path(path).name == "vanish.py":
                Path(path).unlink()
            return real_open(path, flags, *args, **kwargs)

        with patch("security_auditor.discovery.service.os.open", side_effect=disappearing_open):
            result = self.scan()
        self.assertEqual(result.completeness, ScanCompleteness.PARTIAL)
        self.assertIn(DiagnosticCode.FILE_DISAPPEARED, {d.code for d in result.diagnostics})

    def test_symlink_loop_and_external_target_never_followed(self):
        outside = self.sandbox / "outside"
        outside.mkdir()
        (outside / "private.txt").write_bytes(b"synthetic")
        try:
            os.symlink(self.root, self.root / "loop", target_is_directory=True)
            os.symlink(outside, self.root / "external", target_is_directory=True)
            os.symlink(self.sandbox / "missing", self.root / "broken", target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {type(error).__name__}")
        result = self.scan()
        self.assertEqual(result.completeness, ScanCompleteness.PARTIAL)
        self.assertEqual(len(result.artifacts), 0)
        self.assertIn(DiagnosticCode.REPARSE_POINT_SKIPPED, {d.code for d in result.diagnostics})
        self.assertIn(DiagnosticCode.OUTSIDE_ROOT_SKIPPED, {d.code for d in result.diagnostics})
        self.assertIn(SkipReason.BROKEN_LINK, {s.reason for s in result.skipped})

    def test_reparse_flag_and_file_identity(self):
        class ReparseInfo:
            st_mode = 0
            st_file_attributes = 0x400

        with patch("security_auditor.discovery.path_safety.stat.FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True):
            self.assertTrue(is_reparse_point(ReparseInfo()))
        identity = file_identity(self.root, os.stat(self.root, follow_symlinks=False))
        self.assertEqual(identity.platform, "windows" if os.name == "nt" else "portable")
        self.assertIsNotNone(identity.file_id or identity.fallback_key)
        self.assertTrue(unsafe_component("CON.txt", windows=True))
        self.assertTrue(unsafe_component("file:ads", windows=True))
        self.assertTrue(unsafe_component("name.", windows=True))
        self.assertFalse(unsafe_component("normal name", windows=True))

    def test_deterministic_order_unicode_and_safe_display(self):
        self.write("z.py")
        self.write("A.py")
        self.write("資料夾/檔案.py")
        self.write("space name/nested/file.py")
        first, second = self.scan(), self.scan()
        self.assertEqual(first.artifacts, second.artifacts)
        self.assertEqual(first.skipped, second.skipped)
        self.assertEqual(first.diagnostics, second.diagnostics)
        self.assertEqual([a.path for a in first.artifacts], ["A.py", "space name/nested/file.py", "z.py", "資料夾/檔案.py"])
        self.assertEqual(safe_display("x\x1b[31m\n\u202e"), "x\\x1b[31m\\n\\u202e")

    def test_discovery_package_has_no_execution_or_subprocess_calls(self):
        package = Path(__file__).resolve().parents[1] / "src" / "security_auditor" / "discovery"
        forbidden_imports = {"subprocess", "runpy", "importlib", "pickle"}
        forbidden_calls = {"eval", "exec", "compile"}
        for path in package.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(forbidden_imports.intersection(alias.name for alias in node.names), path)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, forbidden_imports, path)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_calls, path)


if __name__ == "__main__":
    unittest.main()
