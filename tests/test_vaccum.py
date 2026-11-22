import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import vaccum


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def scan(self, *roots):
        return vaccum.scan([os.fspath(path) for path in roots or [self.root]])

    def test_metadata_findings_and_report_contract(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "résumé.tmp").write_bytes(b"abc")
        (self.root / "empty").touch()
        report = self.scan()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["status"], "complete")
        findings = {item["path"]: item for item in report["findings"]}
        self.assertEqual(set(findings), {".", "nested", "nested/résumé.tmp", "empty"})
        item = findings["nested/résumé.tmp"]
        self.assertEqual(item["category"], "temporary-candidate")
        self.assertEqual(item["logical_bytes"], 3)
        self.assertEqual(item["allocated_bytes"], (self.root / item["path"]).stat().st_blocks * 512)
        self.assertIsNone(item["estimated_reclaimable_bytes"])
        for item in findings.values():
            for key in ("root", "type", "reason", "uncertainty", "suggested_action"):
                self.assertTrue(item[key])
        self.assertEqual(report["roots"], [{"label": "root-1", "input": str(self.root)}])

    def test_links_cycles_and_special_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "outside-secret").touch()
            (self.root / "outside").symlink_to(outside, target_is_directory=True)
            (self.root / "cycle").symlink_to(self.root, target_is_directory=True)
            os.mkfifo(self.root / "pipe")
            report = self.scan()
        self.assertEqual(report["status"], "complete")
        self.assertEqual({item["path"] for item in report["skipped"]}, {"outside", "cycle", "pipe"})
        self.assertEqual([item["path"] for item in report["findings"]], ["."])

    def test_symlink_in_root_components_is_rejected(self):
        (self.root / "real").mkdir()
        (self.root / "real" / "nested").mkdir()
        (self.root / "alias").symlink_to(self.root / "real", target_is_directory=True)
        for path in (self.root / "alias", self.root / "alias" / "nested"):
            with self.subTest(path=path):
                report = self.scan(path)
                self.assertEqual(report["status"], "partial")
                self.assertFalse(report["findings"])
                self.assertEqual(report["skipped"][0]["code"], "root_unavailable")

    def test_overlapping_roots_and_hardlinks_are_counted_once(self):
        nested = self.root / "nested"
        nested.mkdir()
        source = nested / "file"
        source.write_bytes(b"12345")
        os.link(source, self.root / "hardlink")
        report = self.scan(self.root, nested, self.root)
        self.assertEqual(report["totals"]["logical_bytes"], 5)
        self.assertEqual(report["totals"]["unique_regular_files"], 1)
        self.assertEqual(len([item for item in report["findings"] if item["type"] == "regular"]), 2)
        self.assertEqual(len(report["skipped"]), 2)
        self.assertTrue(all(item["code"] == "overlap" for item in report["skipped"]))

    def test_sparse_sizes_remain_distinct_and_reclaimable_unknown(self):
        sparse = self.root / "sparse"
        with sparse.open("wb") as stream:
            stream.truncate(1024 * 1024)
        report = self.scan()
        item = next(item for item in report["findings"] if item["path"] == "sparse")
        self.assertEqual(item["logical_bytes"], 1024 * 1024)
        self.assertEqual(item["allocated_bytes"], sparse.stat().st_blocks * 512)
        self.assertIsNone(report["totals"]["estimated_reclaimable_bytes"])

    def test_permission_and_disappearing_entries_are_reported(self):
        (self.root / "denied").touch()
        (self.root / "gone").touch()
        original = os.stat

        def unavailable(path, *args, **kwargs):
            if path == "denied":
                raise PermissionError(13, "sensitive message", "/private/path")
            if path == "gone":
                raise FileNotFoundError(2, "gone")
            return original(path, *args, **kwargs)

        with mock.patch("vaccum.os.stat", side_effect=unavailable):
            report = self.scan()
        self.assertEqual(report["status"], "partial")
        self.assertEqual({item["path"] for item in report["skipped"]}, {"denied", "gone"})
        self.assertNotIn("sensitive message", json.dumps(report))
        self.assertNotIn("/private/path", json.dumps(report))

    def test_replaced_directory_is_not_scanned(self):
        child = self.root / "child"
        child.mkdir()
        (child / "original").touch()
        original_open = os.open
        changed = False

        def replace_before_open(path, *args, **kwargs):
            nonlocal changed
            if path == "child" and not changed:
                changed = True
                child.rename(self.root / "old-child")
                child.mkdir()
                (child / "replacement").touch()
            return original_open(path, *args, **kwargs)

        with mock.patch("vaccum.os.open", side_effect=replace_before_open):
            report = self.scan()
        self.assertEqual(report["status"], "partial")
        self.assertFalse(any(item["path"].endswith("replacement") for item in report["findings"]))
        self.assertTrue(any(item["code"] == "changed" for item in report["skipped"]))

    def test_symlink_directory_replacement_cannot_list_outside(self):
        child = self.root / "child"
        child.mkdir()
        original_open = os.open
        changed = False
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "outside-secret").touch()

            def replace_before_open(path, *args, **kwargs):
                nonlocal changed
                if path == "child" and not changed:
                    changed = True
                    child.rmdir()
                    child.symlink_to(outside, target_is_directory=True)
                return original_open(path, *args, **kwargs)

            with mock.patch("vaccum.os.open", side_effect=replace_before_open):
                report = self.scan()
        self.assertEqual(report["status"], "partial")
        self.assertFalse(any("outside-secret" in item["path"] for item in report["findings"]))

    def test_human_output_escapes_controls_and_cli_json_is_valid(self):
        name = "bad\n\x1b[31m.tmp"
        (self.root / name).touch()
        human = io.StringIO()
        with contextlib.redirect_stdout(human):
            status = vaccum.main(["scan", str(self.root)])
        self.assertEqual(status, 0)
        self.assertNotIn("\x1b", human.getvalue())
        self.assertIn("bad\\n\\u001b[31m.tmp", human.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = vaccum.main(["scan", str(self.root), "--format", "json"])
        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(any(item["path"] == name for item in report["findings"]))

    def test_partial_cli_returns_nonzero(self):
        with contextlib.redirect_stdout(io.StringIO()):
            status = vaccum.main(["scan", str(self.root / "missing"), "--format", "json"])
        self.assertEqual(status, 1)

    def test_mount_boundaries_are_skipped_even_on_same_device(self):
        (self.root / "mounted").mkdir()
        (self.root / "mounted" / "unseen").touch()
        with mock.patch("vaccum.mount_id", side_effect=[10, 11]):
            report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual(report["skipped"][0]["code"], "mount_boundary")
        self.assertFalse(any(item["path"].endswith("unseen") for item in report["findings"]))

    def test_missing_mount_identity_fails_closed(self):
        (self.root / "unseen").touch()
        with mock.patch("vaccum.mount_id", side_effect=OSError(5, "unavailable")):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertFalse(report["findings"])
        self.assertEqual(report["skipped"][0]["code"], "mount_unavailable")

    def test_depth_limit_marks_coverage_incomplete(self):
        (self.root / "one").mkdir()
        (self.root / "one" / "two").mkdir()
        with mock.patch("vaccum.MAX_DEPTH", 1):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["skipped"][0]["code"], "depth_limit")

    def test_interruption_preserves_partial_report_and_returns_130(self):
        output = io.StringIO()
        with mock.patch("vaccum.os.scandir", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(output):
                status = vaccum.main(["scan", str(self.root), "--format", "json"])
        self.assertEqual(status, 130)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "interrupted")
        self.assertFalse(report["complete"])

    def test_scanner_opens_only_directories_and_kernel_mount_metadata(self):
        (self.root / "file").write_bytes(b"contents must stay unread")
        original_open = os.open
        original_builtin_open = open
        opened = []

        def directory_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_DIRECTORY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return original_open(path, flags, *args, **kwargs)

        def metadata_open(path, *args, **kwargs):
            opened.append(path)
            self.assertTrue(path.startswith("/proc/self/fdinfo/"))
            return original_builtin_open(path, *args, **kwargs)

        with mock.patch("vaccum.os.open", side_effect=directory_open):
            with mock.patch("builtins.open", side_effect=metadata_open):
                report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual(len(opened), 1)

    def test_root_with_symlink_then_parent_component_is_rejected(self):
        (self.root / "real").mkdir()
        (self.root / "alias").symlink_to(self.root / "real", target_is_directory=True)
        report = self.scan(str(self.root) + "/alias/..")
        self.assertFalse(report["complete"])
        self.assertFalse(report["findings"])

    def test_parent_components_are_rejected_before_directory_access(self):
        with mock.patch("vaccum.os.open") as opened:
            report = self.scan(str(self.root) + "/../" + self.root.name)
        self.assertFalse(report["complete"])
        self.assertFalse(report["findings"])
        opened.assert_not_called()

    def test_directory_listing_failure_is_partial(self):
        with mock.patch("vaccum.os.scandir", side_effect=PermissionError(13, "private")):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["skipped"][0]["code"], "directory_unavailable")

    def test_child_mount_failure_is_partial_and_parent_results_survive(self):
        (self.root / "child").mkdir()
        with mock.patch("vaccum.mount_id", side_effect=[10, OSError(5, "unavailable")]):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual([item["path"] for item in report["findings"]], ["."])
        self.assertEqual(report["skipped"][0]["code"], "mount_unavailable")

    def test_root_rename_after_open_scans_selected_object(self):
        selected = self.root / "selected"
        selected.mkdir()
        (selected / "original").touch()
        original_open_root = vaccum.open_root

        def replace_selected(path):
            fd = original_open_root(path)
            selected.rename(self.root / "moved")
            selected.mkdir()
            (selected / "replacement").touch()
            return fd

        with mock.patch("vaccum.open_root", side_effect=replace_selected):
            report = self.scan(selected)
        self.assertTrue(report["complete"])
        self.assertEqual({item["path"] for item in report["findings"]}, {".", "original"})

    def test_directory_descriptors_are_closed_on_success_errors_and_interrupt(self):
        (self.root / "nested").mkdir()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            self.assertTrue(self.scan()["complete"])
            self.assertFalse(self.scan(self.root / "missing")["complete"])
            with mock.patch("vaccum.mount_id", side_effect=OSError(5, "unavailable")):
                self.assertFalse(self.scan()["complete"])
            with mock.patch("vaccum.os.scandir", side_effect=KeyboardInterrupt):
                self.assertEqual(self.scan()["status"], "interrupted")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
