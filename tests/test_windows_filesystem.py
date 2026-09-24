"""Real Windows filesystem checks over a disposable synthetic sandbox only."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.discovery.path_safety import is_reparse_point
from security_auditor.discovery.platform.identity import file_identity


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAN_CHILD = """
import json
from pathlib import Path
import sys
from security_auditor.core.config import DiscoveryLimits
from security_auditor.core.models import ScanTarget
from security_auditor.discovery import DiscoveryPolicy, discover
root = Path(sys.argv[1])
limits = DiscoveryLimits(max_file_count=20, max_directories=20, max_entries=60,
                         max_directory_depth=8, max_elapsed_seconds=3)
result = discover(ScanTarget(root, "synthetic"), DiscoveryPolicy(limits=limits))
print(json.dumps({"completeness": result.completeness.value,
                  "admitted": [a.path for a in result.artifacts],
                  "skipped": [s.path for s in result.skipped],
                  "diagnostics": [[d.code.value, d.path] for d in result.diagnostics],
                  "visited": result.summary.stats.directories_visited}))
"""


@contextmanager
def synthetic_sandbox():
    """Verify the exact temp target before recursive cleanup; remove links first."""
    parent = Path(tempfile.gettempdir()).resolve(strict=True)
    base = Path(tempfile.mkdtemp(prefix="security-auditor-fs-validation-", dir=parent))
    if base.resolve(strict=True).parent != parent:
        raise AssertionError("Synthetic sandbox escaped the temp parent")
    links: list[tuple[Path, str]] = []
    try:
        yield base, links
    finally:
        for link, kind in reversed(links):
            try:
                if is_reparse_point(link.lstat()):
                    if kind == "junction":
                        os.rmdir(link)  # remove only the junction itself
                    else:
                        link.unlink()   # remove only the symlink itself
            except FileNotFoundError:
                pass
        if (base.resolve(strict=True).parent != parent or
                is_reparse_point(base.lstat()) or not base.is_dir()):
            raise AssertionError("Unsafe synthetic sandbox cleanup target")
        shutil.rmtree(base)


def scan_bounded(root: Path) -> dict:
    """Trusted scanner child has a hard timeout; it never executes target data."""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            [sys.executable, "-c", SCAN_CHILD, str(root)], cwd=PROJECT_ROOT,
            env=environment, capture_output=True, text=True, shell=False, timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise AssertionError("Bounded discovery child timed out") from None
    if completed.returncode != 0:
        raise AssertionError("Trusted discovery child failed")
    return json.loads(completed.stdout)


def make_junction(base: Path, links: list[tuple[Path, str]], link: Path, target: Path):
    if (link.parent.resolve(strict=True).is_relative_to(base.resolve(strict=True)) is False or
            not target.resolve(strict=True).is_relative_to(base.resolve(strict=True))):
        raise AssertionError("Junction arguments escaped synthetic sandbox")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
    try:
        created = subprocess.run(
            [str(executable), "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, text=True, shell=False, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise unittest.SkipTest("SKIPPED_ENVIRONMENT_LIMITATION: junction creation unavailable")
    if created.returncode != 0:
        raise unittest.SkipTest("SKIPPED_ENVIRONMENT_LIMITATION: junction creation unavailable")
    if not is_reparse_point(link.lstat()):
        raise AssertionError("Created junction was not marked as a reparse point")
    links.append((link, "junction"))


@unittest.skipUnless(os.name == "nt", "Real Windows filesystem validation")
class WindowsFilesystemTests(unittest.TestCase):
    def test_real_symlinks_inside_loop_and_outside_root(self):
        with synthetic_sandbox() as (base, links):
            root = base / "scanroot"
            normal = root / "normal"
            outside = base / "outside"
            normal.mkdir(parents=True)
            outside.mkdir()
            (normal / "inside.txt").write_text("synthetic", encoding="utf-8")
            (outside / "sentinel.txt").write_text("synthetic", encoding="utf-8")
            for name, destination in (("inside_link", normal), ("loop", root),
                                      ("outside_link", outside)):
                link = root / name
                try:
                    os.symlink(destination, link, target_is_directory=True)
                except (OSError, NotImplementedError):
                    self.skipTest("SKIPPED_ENVIRONMENT_LIMITATION: symlink privilege unavailable")
                links.append((link, "symlink"))
                self.assertTrue(is_reparse_point(link.lstat()))
            result = scan_bounded(root)
            self.assertEqual(result["completeness"], "partial")
            self.assertEqual(result["admitted"], ["normal/inside.txt"])
            self.assertLessEqual(result["visited"], 2)
            self.assertTrue({("REPARSE_POINT_SKIPPED", "inside_link"),
                             ("REPARSE_POINT_SKIPPED", "loop"),
                             ("REPARSE_POINT_SKIPPED", "outside_link"),
                             ("OUTSIDE_ROOT_SKIPPED", "outside_link")}
                            <= {tuple(item) for item in result["diagnostics"]})
            self.assertNotIn("outside_link/sentinel.txt", result["admitted"])
            self.assertFalse(any(str(base) in str(item) for item in result["diagnostics"]))
            self.assertTrue((outside / "sentinel.txt").exists())

    def test_real_junction_inside_and_outside_root(self):
        with synthetic_sandbox() as (base, links):
            root = base / "scanroot"
            normal = root / "normal"
            outside = base / "outside"
            normal.mkdir(parents=True)
            outside.mkdir()
            (normal / "inside.txt").write_text("synthetic", encoding="utf-8")
            sentinel = outside / "sentinel.txt"
            sentinel.write_text("synthetic", encoding="utf-8")
            make_junction(base, links, root / "inside_junction", normal)
            make_junction(base, links, root / "outside_junction", outside)
            result = scan_bounded(root)
            self.assertEqual(result["completeness"], "partial")
            self.assertEqual(result["admitted"], ["normal/inside.txt"])
            self.assertLessEqual(result["visited"], 2)
            self.assertTrue({("REPARSE_POINT_SKIPPED", "inside_junction"),
                             ("REPARSE_POINT_SKIPPED", "outside_junction"),
                             ("OUTSIDE_ROOT_SKIPPED", "outside_junction")}
                            <= {tuple(item) for item in result["diagnostics"]})
            self.assertNotIn("outside_junction/sentinel.txt", result["admitted"])
            selected_link = scan_bounded(root / "inside_junction")
            self.assertEqual(selected_link["completeness"], "failed")
            self.assertIn(["ROOT_REPARSE_POINT", None], selected_link["diagnostics"])
            self.assertTrue(sentinel.exists())
            os.rmdir(root / "outside_junction")
            links.remove((root / "outside_junction", "junction"))
            self.assertTrue(sentinel.exists(), "Junction cleanup removed its outside target")
            identity = file_identity(root, os.stat(root, follow_symlinks=False))
            self.assertEqual(identity.platform, "windows")
            self.assertIsNotNone(identity.file_id or identity.fallback_key)

    def test_real_junction_loop_has_hard_timeout(self):
        with synthetic_sandbox() as (base, links):
            root = base / "scanroot"
            nested = root / "a" / "b"
            nested.mkdir(parents=True)
            (root / "a" / "safe.txt").write_text("synthetic", encoding="utf-8")
            make_junction(base, links, nested / "loop", root / "a")
            result = scan_bounded(root)
            self.assertEqual(result["completeness"], "partial")
            self.assertEqual(result["admitted"], ["a/safe.txt"])
            self.assertIn(["REPARSE_POINT_SKIPPED", "a/b/loop"], result["diagnostics"])
            self.assertLessEqual(result["visited"], 3)

    def test_unicode_long_path_is_bounded(self):
        with synthetic_sandbox() as (base, links):
            root = base / "scanroot"
            root.mkdir()
            current = root
            try:
                for index in range(4):
                    current = current / ("中文 空白 " + str(index) + "_" + "x" * 58)
                    current.mkdir()
                (current / "sample.py").write_text("x = 1\n", encoding="utf-8")
            except OSError:
                self.skipTest("SKIPPED_ENVIRONMENT_LIMITATION: long paths unavailable")
            self.assertGreater(len(str(current / "sample.py")), 260)
            result = scan_bounded(root)
            relative = (current / "sample.py").relative_to(root).as_posix()
            self.assertEqual(result["completeness"], "complete")
            self.assertEqual(result["admitted"], [relative])
            self.assertLessEqual(result["visited"], 5)


if __name__ == "__main__":
    unittest.main()
