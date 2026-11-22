from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import vaccum_actions


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.target = self.root / "old.tmp"
        self.target.write_text("disposable")
        self.backend = mock.patch("vaccum_actions._package_owned", return_value=False)
        self.backend.start()
        self.addCleanup(self.backend.stop)

    def approve(self, plan):
        return plan["confirmation_phrase"]

    def trash(self, command, **kwargs):
        self.assertEqual(command[:3], ["/usr/bin/gio", "trash", "--"])
        self.assertFalse(kwargs.get("shell", False))
        Path(command[3]).unlink()
        return subprocess.CompletedProcess(command, 0, "", "")

    def test_exact_confirmation_runs_native_trash_and_verifies_source_absence(self):
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.trash) as run:
            report = vaccum_actions.cleanup([self.root], [self.target], self.approve)
        self.assertTrue(report["complete"], report)
        self.assertEqual(report["items"][0]["status"], "trashed")
        self.assertFalse(self.target.exists())
        self.assertEqual(run.call_count, 1)
        self.assertIsNone(report["plan"]["items"][0]["estimated_reclaimable_bytes"])
        self.assertIn("race", " ".join(report["warnings"]))

    def test_cancel_and_boolean_cannot_authorize(self):
        for answer in (None, True, "TRASH", ""):
            with self.subTest(answer=answer), mock.patch("vaccum_actions.subprocess.run") as run:
                report = vaccum_actions.cleanup([self.root], [self.target], lambda plan: answer)
                self.assertEqual(report["status"], "cancelled")
                self.assertTrue(self.target.exists())
                run.assert_not_called()

    def test_changes_after_preview_rejected(self):
        def changed(plan):
            self.target.write_text("changed after approval")
            return self.approve(plan)
        with mock.patch("vaccum_actions.subprocess.run") as run:
            report = vaccum_actions.cleanup([self.root], [self.target], changed)
        self.assertEqual(report["items"][0]["status"], "changed")
        run.assert_not_called()

    def test_descendant_change_and_parent_permission_change_rejected(self):
        directory = self.root / "folder"
        directory.mkdir()
        child = directory / "child"
        child.write_text("before")
        for change in (lambda: child.write_text("after"), lambda: self.root.chmod(0o777)):
            with self.subTest(change=change):
                def changed(plan):
                    change()
                    return self.approve(plan)
                with mock.patch("vaccum_actions.subprocess.run") as run:
                    report = vaccum_actions.cleanup([self.root], [directory], changed)
                self.assertEqual(report["items"][0]["status"], "changed")
                run.assert_not_called()
                self.root.chmod(0o700)

    def test_scope_links_specials_overlap_and_root_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.target)
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "child").write_text("x")
        cases = ([self.root], [linked], [fifo], [self.root.parent / "outside"],
                 [self.target, self.target], [folder, folder / "child"])
        for selections in cases:
            with self.subTest(selections=selections), mock.patch("vaccum_actions.subprocess.run") as run:
                report = vaccum_actions.cleanup([self.root], selections, self.approve)
                self.assertFalse(report["complete"])
                run.assert_not_called()
        with mock.patch("vaccum_actions.os.geteuid", return_value=0), mock.patch("vaccum_actions.subprocess.run") as run:
            self.assertFalse(vaccum_actions.cleanup([self.root], [self.target], self.approve)["complete"])
            run.assert_not_called()

    def test_equivalent_leading_slashes_preserve_cleanup_ancestry(self):
        root = "/" + str(self.root)
        target = "/" + str(self.target)
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.trash) as run:
            report = vaccum_actions.cleanup([root], [target], self.approve)
        self.assertTrue(report["complete"], report)
        self.assertEqual(report["items"][0]["target"], str(self.target))
        self.assertEqual(run.call_count, 1)

    def test_native_failure_or_source_still_present_is_not_success(self):
        for code in (0, 1):
            with self.subTest(code=code), mock.patch("vaccum_actions.subprocess.run", return_value=subprocess.CompletedProcess([], code, "", "private diagnostic")):
                report = vaccum_actions.cleanup([self.root], [self.target], self.approve)
                self.assertFalse(report["complete"])
                self.assertNotIn("private diagnostic", str(report))
                self.assertEqual(report["items"][0]["status"], "uncertain" if code == 0 else "failed")

    def test_timeout_is_uncertain_without_retry(self):
        with mock.patch("vaccum_actions.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)) as run:
            report = vaccum_actions.cleanup([self.root], [self.target], self.approve)
        self.assertEqual(report["items"][0]["status"], "uncertain")
        self.assertEqual(run.call_count, 1)

    def test_native_interrupt_is_uncertain_and_leaves_later_target_unattempted(self):
        second = self.root / "second"
        second.write_text("second")
        with mock.patch("vaccum_actions.subprocess.run", side_effect=KeyboardInterrupt) as run:
            report = vaccum_actions.cleanup([self.root], [self.target, second], self.approve)
        self.assertEqual(report["status"], "interrupted")
        self.assertFalse(report["complete"])
        self.assertEqual([item["status"] for item in report["items"]], ["uncertain", "not_attempted"])
        self.assertTrue(self.target.exists())
        self.assertTrue(second.exists())
        self.assertEqual(run.call_count, 1)

    def test_package_owned_or_untrusted_root_rejected(self):
        with mock.patch("vaccum_actions._package_owned", return_value=True), mock.patch("vaccum_actions.subprocess.run") as run:
            self.assertFalse(vaccum_actions.cleanup([self.root], [self.target], self.approve)["complete"])
            run.assert_not_called()
        self.root.chmod(0o777)
        with mock.patch("vaccum_actions.subprocess.run") as run:
            self.assertFalse(vaccum_actions.cleanup([self.root], [self.target], self.approve)["complete"])
            run.assert_not_called()

    def test_subtree_links_mounts_and_inaccessible_metadata_fail_closed(self):
        folder = self.root / "folder"
        folder.mkdir()
        child = folder / "child"
        child.symlink_to(self.target)
        with mock.patch("vaccum_actions.subprocess.run") as run:
            self.assertFalse(vaccum_actions.cleanup([self.root], [folder], self.approve)["complete"])
            run.assert_not_called()
        child.unlink()
        child.write_text("x")
        mounted = vaccum_actions.mount_id
        def nested_mount(fd):
            return mounted(fd) + (1 if os.readlink(f"/proc/self/fd/{fd}") == str(child) else 0)
        for patch in (mock.patch("vaccum_actions.mount_id", side_effect=nested_mount),
                      mock.patch("vaccum_actions.os.scandir", side_effect=PermissionError())):
            with patch, mock.patch("vaccum_actions.subprocess.run") as run:
                self.assertFalse(vaccum_actions.cleanup([self.root], [folder], self.approve)["complete"])
                run.assert_not_called()

    def test_mixed_native_outcomes_are_preserved(self):
        second = self.root / "second"
        second.write_text("x")
        def backend(command, **kwargs):
            if command[-1] == str(self.target):
                return subprocess.CompletedProcess(command, 1, "", "private")
            return self.trash(command, **kwargs)
        with mock.patch("vaccum_actions.subprocess.run", side_effect=backend):
            report = vaccum_actions.cleanup([self.root], [self.target, second], self.approve)
        self.assertEqual([item["status"] for item in report["items"]], ["failed", "trashed"])
        self.assertFalse(report["complete"])
        self.assertTrue(self.target.exists())
        self.assertFalse(second.exists())

    def test_intermediate_parent_replaced_by_symlink_cannot_enumerate_outside(self):
        parent = self.root / "parent"
        parent.mkdir()
        nested = parent / "nested"
        nested.mkdir()
        selected = nested / "selected"
        selected.mkdir()
        (selected / "inside").write_text("x")
        outside = self.root / "outside"
        (outside / "nested/selected").mkdir(parents=True)
        (outside / "nested/selected/private").write_text("secret")
        original = vaccum_actions._tree
        enumerated = []
        scandir = os.scandir
        def track(fd):
            enumerated.append(os.readlink(f"/proc/self/fd/{fd}"))
            return scandir(fd)
        def swap(path, *args, **kwargs):
            parent.rename(self.root / "old-parent")
            parent.symlink_to(outside, target_is_directory=True)
            return original(path, *args, **kwargs)
        with mock.patch("vaccum_actions._tree", side_effect=swap), mock.patch("vaccum_actions.os.scandir", side_effect=track):
            report = vaccum_actions.cleanup([self.root], [selected], self.approve)
        self.assertFalse(report["complete"])
        self.assertFalse(any(str(outside) in path for path in enumerated))

    def test_replaced_real_ancestor_is_rejected_before_enumeration(self):
        parent = self.root / "parent"
        parent.mkdir()
        selected = parent / "selected"
        selected.mkdir()
        (selected / "original").write_text("x")
        original = vaccum_actions._tree
        enumerated = []
        scandir = os.scandir
        def track(fd):
            enumerated.append(os.readlink(f"/proc/self/fd/{fd}"))
            return scandir(fd)
        def swap(path, *args, **kwargs):
            parent.rename(self.root / "old-parent")
            (parent / "selected").mkdir(parents=True)
            (parent / "selected/foreign").write_text("x")
            return original(path, *args, **kwargs)
        with mock.patch("vaccum_actions._tree", side_effect=swap), mock.patch("vaccum_actions.os.scandir", side_effect=track):
            report = vaccum_actions.cleanup([self.root], [selected], self.approve)
        self.assertFalse(report["complete"])
        self.assertEqual(enumerated, [])

    def test_package_ownership_preflight_cannot_hide_a_changed_subtree(self):
        calls = 0
        def ownership(paths):
            nonlocal calls
            calls += 1
            self.target.write_text(str(calls))
            return False
        with mock.patch("vaccum_actions._package_owned", side_effect=ownership), mock.patch("vaccum_actions.subprocess.run") as run:
            report = vaccum_actions.cleanup([self.root], [self.target], self.approve)
        self.assertFalse(report["complete"])
        self.assertIsNone(report["plan"])
        run.assert_not_called()

    def test_confirmation_interrupt_is_reported_without_mutation(self):
        def interrupt(plan):
            raise KeyboardInterrupt
        with mock.patch("vaccum_actions.subprocess.run") as run:
            report = vaccum_actions.cleanup([self.root], [self.target], interrupt)
        self.assertEqual(report["status"], "interrupted")
        run.assert_not_called()

    def test_revalidation_interrupt_preserves_completed_and_unattempted_targets(self):
        second = self.root / "second"
        third = self.root / "third"
        second.write_text("second")
        third.write_text("third")
        capture = vaccum_actions._capture
        def interrupt(target, root):
            if target == str(second) and not self.target.exists():
                raise KeyboardInterrupt
            return capture(target, root)
        with mock.patch("vaccum_actions._capture", side_effect=interrupt), mock.patch("vaccum_actions.subprocess.run", side_effect=self.trash) as run:
            try:
                report = vaccum_actions.cleanup([self.root], [self.target, second, third], self.approve)
            except KeyboardInterrupt:
                self.fail("Revalidation interruption discarded completed action outcomes.")
        self.assertEqual(report["status"], "interrupted")
        self.assertFalse(report["complete"])
        self.assertEqual([item["target"] for item in report["items"]], [str(self.target), str(second), str(third)])
        self.assertEqual([item["status"] for item in report["items"]], ["trashed", "not_attempted", "not_attempted"])
        self.assertEqual(report["items"][0]["returncode"], 0)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(self.target.exists())
        self.assertTrue(second.exists())
        self.assertTrue(third.exists())

    def test_native_environment_excludes_injected_loader_and_gio_overrides(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/bad", "GIO_EXTRA_MODULES": "/bad", "DPKG_ROOT": "/bad"}), mock.patch("vaccum_actions.subprocess.run", return_value=result) as run:
            vaccum_actions._run(["/usr/bin/gio", "trash", "--", str(self.target)])
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("GIO_EXTRA_MODULES", environment)
        self.assertNotIn("DPKG_ROOT", environment)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_native_package_ownership_matches_literal_metacharacters(self):
        self.backend.stop()
        database = self.root / "database"
        (database / "info").mkdir(parents=True)
        (database / "status").write_text("Package: vaccum-owned-fixture\nStatus: install ok installed\nArchitecture: all\nVersion: 1\nDescription: fixture\n\n")
        paths = [str(self.root / name) for name in ("literal*file", "literal?file", "literal[file", "literal\\file")]
        (database / "info/vaccum-owned-fixture.list").write_text("\n".join(paths) + "\n")
        native = vaccum_actions._run
        def fixture_run(command):
            return native(command[:1] + ["--admindir=" + str(database)] + command[1:])
        with mock.patch("vaccum_actions._run", side_effect=fixture_run):
            for path in paths:
                self.assertTrue(vaccum_actions._package_owned([path]), path)
            self.assertFalse(vaccum_actions._package_owned([str(self.root / "literal-unowned-file")]))

    def test_missing_native_package_metadata_does_not_authorize_cleanup(self):
        self.backend.stop()
        with mock.patch("vaccum_actions.subprocess.run", return_value=subprocess.CompletedProcess([], 2, "", "private")) as run:
            report = vaccum_actions.cleanup([self.root], [self.target], self.approve)
        self.assertFalse(report["complete"])
        self.assertTrue(all(call.args[0][0] == "/usr/bin/dpkg-query" for call in run.call_args_list))


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/log").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").write_text("fixture")

    def approve(self, plan):
        return plan["confirmation_phrase"]

    def backend(self, command, **kwargs):
        if command[0] == "/usr/bin/dpkg-query":
            status = "config-files" if getattr(self, "removed", False) else "installed"
            return subprocess.CompletedProcess(command, 0, f"fixture:all\t1.0\t{status}\tno\tno\n", "")
        if "--no-act" not in command:
            self.removed = True
        return subprocess.CompletedProcess(command, 0, "", "")

    def test_native_exact_remove_then_verify_status(self):
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)
        self.assertTrue(report["complete"], report)
        commands = [call.args[0] for call in run.call_args_list]
        mutations = [command for command in commands if command[0] == "/usr/bin/dpkg" and "--no-act" not in command]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][-2:], ["--remove", "fixture:all"])
        self.assertIn(f"--root={self.root}", mutations[0])
        self.assertIn(f"--log={self.root}/var/log/dpkg.log", mutations[0])
        self.assertEqual(report["items"][0]["status"], "removed")

    def test_equivalent_host_roots_are_normalized_and_rejected_before_native_calls(self):
        for root in ("/", "//", "///"):
            with self.subTest(root=root):
                self.assertEqual(vaccum_actions._path(root), vaccum_actions._path("/"))
                with mock.patch("vaccum_actions._package") as package, mock.patch("vaccum_actions.subprocess.run") as run:
                    report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=root)
                self.assertEqual(report["status"], "rejected")
                self.assertIsNone(report["plan"])
                package.assert_not_called()
                run.assert_not_called()

    def test_cancel_does_not_remove(self):
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], lambda plan: None, root=self.root)
        self.assertEqual(report["status"], "cancelled")
        self.assertTrue(all("--no-act" in call.args[0] for call in run.call_args_list if call.args[0][0] == "/usr/bin/dpkg"))

    def test_revalidation_interrupt_preserves_completed_and_unattempted_packages(self):
        identifiers = ["first:all", "second:all", "third:all"]
        removed = []
        def package(identifier, admindir):
            if identifier == identifiers[1] and removed:
                raise KeyboardInterrupt
            return {"package_id": identifier, "version": "1.0", "status": "config-files" if identifier in removed else "installed",
                    "essential": False, "protected": False}
        def backend(command, **kwargs):
            if "--no-act" not in command:
                removed.append(command[-1])
            return subprocess.CompletedProcess(command, 0, "", "")
        with mock.patch("vaccum_actions._package", side_effect=package), mock.patch("vaccum_actions.subprocess.run", side_effect=backend):
            try:
                report = vaccum_actions.uninstall(identifiers, self.approve, root=self.root)
            except KeyboardInterrupt:
                self.fail("Revalidation interruption discarded completed action outcomes.")
        self.assertEqual(report["status"], "interrupted")
        self.assertFalse(report["complete"])
        self.assertEqual([item["target"] for item in report["items"]], identifiers)
        self.assertEqual([item["status"] for item in report["items"]], ["removed", "not_attempted", "not_attempted"])
        self.assertEqual(report["items"][0]["returncode"], 0)
        self.assertEqual(removed, identifiers[:1])

    def test_invalid_protected_dependency_failure_and_stale_database_rejected(self):
        with mock.patch("vaccum_actions.subprocess.run") as run:
            report = vaccum_actions.uninstall(["--force-all"], self.approve, root=self.root)
            self.assertFalse(report["complete"])
            run.assert_not_called()
        for row in ("fixture:all\t1.0\tinstalled\tyes\tno\n", "fixture:all\t1.0\tinstalled\tno\tyes\n", "fixture:all\t1.0\thalf-installed\tno\tno\n"):
            with self.subTest(row=row), mock.patch("vaccum_actions.subprocess.run", return_value=subprocess.CompletedProcess([], 0, row, "")) as run:
                self.assertFalse(vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)["complete"])
                self.assertTrue(all(call.args[0][0] == "/usr/bin/dpkg-query" for call in run.call_args_list))
        def stale(plan):
            (self.root / "var/lib/dpkg/status").write_text("new metadata")
            return self.approve(plan)
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], stale, root=self.root)
        self.assertEqual(report["items"][0]["status"], "changed")
        self.assertTrue(all("--no-act" in call.args[0] for call in run.call_args_list if call.args[0][0] == "/usr/bin/dpkg"))

    def test_post_confirmation_dependency_failure_cannot_remove(self):
        confirmed = False
        def approve(plan):
            nonlocal confirmed
            confirmed = True
            return self.approve(plan)
        def backend(command, **kwargs):
            if command[0] == "/usr/bin/dpkg" and confirmed:
                return subprocess.CompletedProcess(command, 1, "", "private")
            return self.backend(command, **kwargs)
        with mock.patch("vaccum_actions.subprocess.run", side_effect=backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], approve, root=self.root)
        self.assertEqual(report["items"][0]["status"], "changed")
        self.assertTrue(all("--no-act" in call.args[0] for call in run.call_args_list if call.args[0][0] == "/usr/bin/dpkg"))

    def test_native_removal_failure_and_timeout_preserve_uncertainty_without_retry(self):
        for failure in (subprocess.CompletedProcess([], 1, "", "private"), subprocess.TimeoutExpired([], 1)):
            def backend(command, **kwargs):
                if command[0] == "/usr/bin/dpkg" and "--no-act" not in command:
                    if isinstance(failure, Exception):
                        raise failure
                    return failure
                return self.backend(command, **kwargs)
            with self.subTest(failure=failure), mock.patch("vaccum_actions.subprocess.run", side_effect=backend) as run:
                report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)
            self.assertFalse(report["complete"])
            self.assertEqual(report["items"][0]["status"], "uncertain" if isinstance(failure, Exception) else "failed")
            self.assertEqual(sum(call.args[0][0] == "/usr/bin/dpkg" and "--no-act" not in call.args[0] for call in run.call_args_list), 1)
            self.assertNotIn("private", str(report))

    def test_native_interrupt_remains_uncertain(self):
        def backend(command, **kwargs):
            if command[0] == "/usr/bin/dpkg" and "--no-act" not in command:
                raise KeyboardInterrupt
            return self.backend(command, **kwargs)
        with mock.patch("vaccum_actions.subprocess.run", side_effect=backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)
        self.assertEqual(report["status"], "interrupted")
        self.assertFalse(report["complete"])
        self.assertEqual(report["items"][0]["status"], "uncertain")
        self.assertEqual(sum(call.args[0][0] == "/usr/bin/dpkg" and "--no-act" not in call.args[0] for call in run.call_args_list), 1)

    def test_alternate_root_log_symlink_is_rejected_without_native_calls(self):
        outside = self.root / "outside-log"
        outside.write_text("untouched")
        (self.root / "var/log/dpkg.log").symlink_to(outside)
        with mock.patch("vaccum_actions.subprocess.run") as run:
            report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)
        self.assertFalse(report["complete"])
        run.assert_not_called()
        self.assertEqual(outside.read_text(), "untouched")

    def test_root_symlink_and_database_symlink_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with mock.patch("vaccum_actions.subprocess.run") as run:
            self.assertFalse(vaccum_actions.uninstall(["fixture:all"], self.approve, root=linked)["complete"])
            run.assert_not_called()
        (self.root / "var/lib/dpkg/status").unlink()
        (self.root / "var/lib/dpkg/status").symlink_to("/etc/passwd")
        with mock.patch("vaccum_actions.subprocess.run", side_effect=self.backend) as run:
            report = vaccum_actions.uninstall(["fixture:all"], self.approve, root=self.root)
        self.assertFalse(report["complete"])
        self.assertTrue(all("--no-act" in call.args[0] for call in run.call_args_list if call.args[0][0] == "/usr/bin/dpkg"))


if __name__ == "__main__":
    unittest.main()
