import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from scripts.build_release import build_release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.archive, self.checksum = build_release(self.root / "release")
        self.working = self.root / "unrelated"
        self.working.mkdir()

    def invoke(self, *arguments):
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        return subprocess.run([sys.executable, "-B", str(self.archive), *map(str, arguments)],
                              cwd=self.working, env=environment, capture_output=True, text=True, timeout=15)

    def test_release_contains_only_runtime_files_and_matching_checksum(self):
        self.assertEqual(self.archive.name, "vaccum-0.1.0.pyz")
        with zipfile.ZipFile(self.archive) as archive:
            self.assertEqual(set(archive.namelist()), {"__main__.py", "vaccum.py", "vaccum_actions.py",
                                                      "vaccum_analysis.py", "vaccum_inventory.py"})
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(self.checksum.name, "SHA256SUMS")
        self.assertEqual(self.checksum.read_text(), f"{digest}  {self.archive.name}\n")

    def test_standalone_help_scan_and_exit_statuses(self):
        for command in ((), ("scan",), ("apps",), ("recommend",), ("ai-report",), ("cleanup",), ("uninstall",)):
            with self.subTest(command=command):
                process = self.invoke(*command, "--help")
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIn("usage:", process.stdout)
        selected = self.working / "selected"
        selected.mkdir()
        (selected / "fixture.txt").write_text("fixture")
        process = self.invoke("scan", selected, "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertTrue(report["complete"])
        self.assertEqual(report["totals"]["unique_regular_files"], 1)
        self.assertEqual(report["totals"]["logical_bytes"], 7)
        process = self.invoke("scan", selected / "missing", "--format", "json")
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertFalse(json.loads(process.stdout)["complete"])
        self.assertEqual(self.invoke().returncode, 2)
        self.assertEqual({path.name for path in self.working.iterdir()}, {"selected"})

    def test_standalone_dynamic_command_imports_remain_available(self):
        selected = self.working / "selected"
        selected.mkdir()
        target = selected / "fixture.txt"
        target.write_text("untouched")
        process = self.invoke("recommend", selected, "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "proposal-only")
        process = self.invoke("ai-report", selected)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(str(selected), process.stdout)
        database = self.working / "database"
        database.mkdir()
        (database / "status").write_text("Package: vaccum-release-fixture\nStatus: install ok installed\n"
                                         "Architecture: all\nVersion: 1.0\nInstalled-Size: 2\n"
                                         "Description: Release fixture\n\n")
        process = self.invoke("apps", "--admindir", database, "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["installed_packages"][0]["package_id"], "vaccum-release-fixture:all")
        process = self.invoke("cleanup", selected / "missing", "--target", target, "--format", "json")
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "rejected")
        process = self.invoke("uninstall", "invalid!package", "--format", "json")
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "rejected")
        self.assertEqual(target.read_text(), "untouched")
        self.assertEqual({path.name for path in database.iterdir()}, {"status"})


if __name__ == "__main__":
    unittest.main()
