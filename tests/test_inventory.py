from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import vaccum_inventory


class InventoryTests(unittest.TestCase):
    def query(self, output, returncode=0):
        result = subprocess.CompletedProcess([], returncode, output, "private diagnostics")
        with mock.patch("vaccum_inventory.subprocess.run", return_value=result) as run:
            report = vaccum_inventory.inventory()
        return report, run

    def test_installed_packages_are_separate_from_leftovers_and_size_is_estimate(self):
        report, run = self.query("install ok installed\teditor\t1.2-3\tamd64\t12\n"
                                 "deinstall ok config-files\tremoved\t1\tall\t5\n"
                                 "hold ok installed\theld\t2\tall\t\n")
        self.assertTrue(report["complete"])
        self.assertEqual([item["package_id"] for item in report["installed_packages"]], ["editor:amd64", "held:all"])
        item = report["installed_packages"][0]
        self.assertEqual(item["category"], "installed-package")
        self.assertEqual(item["estimated_installed_bytes"], 12 * 1024)
        self.assertIsNone(item["estimated_reclaimable_bytes"])
        self.assertIsNone(report["installed_packages"][1]["estimated_installed_bytes"])
        self.assertIn("unused", item["uncertainty"])
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/bin/dpkg-query")
        self.assertNotIn("shell", kwargs)
        self.assertGreater(kwargs["timeout"], 0)
        self.assertNotIn("LD_PRELOAD", kwargs["env"])

    def test_invalid_rows_mark_partial_without_losing_valid_rows(self):
        for bad in ("bad", "install ok installed\t--evil\t1\tall\t5",
                    "install ok installed\tvalid\t1\t../../bad\t5",
                    "install ok installed\tvalid\t1\tall\t-1",
                    "install ok installed\tvalid\t1\x1b[31m\tall\t5"):
            with self.subTest(row=bad):
                report, _ = self.query("install ok installed\tvalid\t1\tall\t5\n" + bad + "\n")
                self.assertFalse(report["complete"])
                self.assertEqual(len(report["installed_packages"]), 1)
                self.assertNotIn(bad, str(report["errors"]))

    def test_nonzero_exit_preserves_valid_observations(self):
        report, _ = self.query("install ok installed\tvalid\t1\tall\t5\n", 2)
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["installed_packages"]), 1)
        self.assertNotIn("private diagnostics", str(report))

    def test_timeout_and_unavailable_backend_are_reported(self):
        for error in (subprocess.TimeoutExpired([], 10), FileNotFoundError(2, "private")):
            with self.subTest(error=error):
                with mock.patch("vaccum_inventory.subprocess.run", side_effect=error):
                    report = vaccum_inventory.inventory()
                self.assertFalse(report["complete"])
                self.assertFalse(report["installed_packages"])
                self.assertNotIn("private", str(report))

    def test_explicit_admindir_is_one_literal_argument(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("vaccum_inventory.subprocess.run", return_value=result) as run:
            vaccum_inventory.inventory("/tmp/db; touch ignored")
        self.assertIn("--admindir=/tmp/db; touch ignored", run.call_args.args[0])

    def test_relative_database_resolves_from_invoking_directory(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("vaccum_inventory.subprocess.run", return_value=result) as run:
            report = vaccum_inventory.inventory("relative-db")
        self.assertIn("--admindir=" + os.path.abspath("relative-db"), run.call_args.args[0])
        self.assertEqual(report["database"], os.path.abspath("relative-db"))

    def test_timeout_preserves_complete_rows_from_partial_output(self):
        error = subprocess.TimeoutExpired([], 10, output=b"install ok installed\tvalid\t1\tall\t5\n")
        with mock.patch("vaccum_inventory.subprocess.run", side_effect=error):
            report = vaccum_inventory.inventory()
        self.assertFalse(report["complete"])
        self.assertEqual([item["package_id"] for item in report["installed_packages"]], ["valid:all"])

    def test_real_disposable_dpkg_database_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "status").write_text("Package: vaccum-fixture\nStatus: install ok installed\n"
                                         "Architecture: all\nVersion: 1.0\nInstalled-Size: 7\n"
                                         "Description: Disposable test package\n\n"
                                         "Package: vaccum-leftover\nStatus: deinstall ok config-files\n"
                                         "Architecture: all\nVersion: 1.0\nDescription: Leftover\n\n")
            before = (path / "status").read_bytes()
            report = vaccum_inventory.inventory(directory)
            self.assertTrue(report["complete"], report)
            self.assertEqual([item["package_id"] for item in report["installed_packages"]], ["vaccum-fixture:all"])
            self.assertEqual((path / "status").read_bytes(), before)
            self.assertEqual({item.name for item in path.iterdir()}, {"status"})


if __name__ == "__main__":
    unittest.main()
