"""The package and source checkout obtain one version from pyproject metadata."""

from importlib.metadata import version as distribution_version
from pathlib import Path
import sys
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import security_auditor


class VersionTests(unittest.TestCase):
    def test_installed_metadata_and_package_match_project(self):
        with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)["project"]
        self.assertRegex(project["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(security_auditor.__version__, project["version"])
        self.assertEqual(distribution_version(project["name"]), project["version"])

    def test_uninstalled_source_fallback_reads_project_version(self):
        with patch.object(security_auditor, "distribution_version",
                          side_effect=security_auditor.PackageNotFoundError):
            self.assertEqual(security_auditor._resolve_version(), security_auditor.__version__)


if __name__ == "__main__":
    unittest.main()
