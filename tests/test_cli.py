import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vaccum


class CliTests(unittest.TestCase):
    def invoke(self, arguments):
        output = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = vaccum.main(arguments)
        return status, output.getvalue(), error.getvalue()

    def test_apps_dispatch_and_json_status(self):
        report = {"schema_version": 1, "status": "partial", "complete": False,
                  "installed_packages": [], "errors": []}
        with mock.patch("vaccum_inventory.inventory", return_value=report) as inventory:
            status, output, error = self.invoke(["apps", "--admindir", "/tmp/database", "--format", "json"])
        inventory.assert_called_once_with("/tmp/database")
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output), report)
        self.assertTrue(error)

    def test_apps_human_escapes_database_and_fields(self):
        report = {"schema_version": 1, "status": "complete", "complete": True,
                  "scope": "Packages only", "database": "db\n\x1b[31m",
                  "installed_packages": [], "errors": []}
        with mock.patch("vaccum_inventory.inventory", return_value=report):
            status, output, _ = self.invoke(["apps"])
        self.assertEqual(status, 0)
        self.assertNotIn("\x1b", output)
        self.assertIn("db\\n\\u001b[31m", output)

    def test_recommendations_are_proposals_and_default_ai_handoff_is_anonymous(self):
        with tempfile.TemporaryDirectory(prefix="vaccum-private-") as directory:
            (Path(directory) / "private-name.txt").touch()
            (Path(directory) / "private-photo.jpg").touch()
            status, output, _ = self.invoke(["recommend", directory, "--format", "json"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output)["status"], "proposal-only")
            status, output, _ = self.invoke(["ai-report", directory])
            self.assertEqual(status, 0)
            self.assertNotIn(directory, output)
            self.assertNotIn("private-name", output)
            _, output, _ = self.invoke(["ai-report", directory, "--include-paths"])
            self.assertIn(directory, output)

    def test_incomplete_scan_propagates_through_recommend_and_ai_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            for command in ("recommend", "ai-report"):
                with self.subTest(command=command):
                    status, _, error = self.invoke([command, str(Path(directory) / "missing")])
                    self.assertEqual(status, 1)
                    self.assertTrue(error)

    def test_real_apps_cli_uses_disposable_native_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)
            (database / "status").write_text("Package: vaccum-cli-fixture\nStatus: install ok installed\n"
                                             "Architecture: all\nVersion: 1.0\nInstalled-Size: 2\n"
                                             "Description: CLI fixture\n\n")
            process = subprocess.run([sys.executable, "-B", str(Path(vaccum.__file__)), "apps",
                                      "--admindir", directory, "--format", "json"],
                                     capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(process.stdout)
            self.assertEqual(report["installed_packages"][0]["package_id"], "vaccum-cli-fixture:all")
            self.assertEqual(report["installed_packages"][0]["estimated_installed_bytes"], 2048)
            self.assertEqual({path.name for path in database.iterdir()}, {"status"})

    def action(self, roots, selections, callback):
        self.assertEqual(roots, ["selected-root"])
        self.assertEqual(selections, ["selected-target"])
        plan = {"action": "trash", "items": [{"target": "bad\n\x1b[31m"}],
                "warnings": ["Fixture only"], "confirmation_phrase": "TRASH fixture"}
        accepted = callback(plan) == plan["confirmation_phrase"]
        return {"schema_version": 1, "action": "trash", "status": "complete" if accepted else "cancelled",
                "complete": accepted, "plan": plan, "items": [], "warnings": []}

    def test_cleanup_defaults_to_escaped_preview_without_reading_input(self):
        stdin = mock.Mock()
        stdin.isatty.return_value = False
        with mock.patch("vaccum_actions.cleanup", side_effect=self.action):
            with mock.patch("vaccum.sys.stdin", stdin):
                status, output, error = self.invoke(["cleanup", "selected-root", "--target", "selected-target", "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["status"], "preview")
        stdin.readline.assert_not_called()
        self.assertNotIn("\x1b", error)
        self.assertIn("bad\\n\\u001b[31m", error)

    def test_apply_without_tty_or_exact_phrase_never_authorizes_action(self):
        for tty, response in ((False, "TRASH fixture\n"), (True, "wrong\n"), (True, "")):
            with self.subTest(tty=tty, response=response):
                stdin = mock.Mock()
                stdin.isatty.return_value = tty
                stdin.readline.return_value = response
                with mock.patch("vaccum_actions.cleanup", side_effect=self.action):
                    with mock.patch("vaccum.sys.stdin", stdin):
                        status, output, _ = self.invoke(["cleanup", "selected-root", "--target", "selected-target", "--apply", "--format", "json"])
                self.assertEqual(status, 1)
                self.assertEqual(json.loads(output)["status"], "cancelled")
                if not tty:
                    stdin.readline.assert_not_called()

    def test_interactive_apply_requires_exact_confirmation_and_keeps_json_valid(self):
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        stdin.readline.return_value = "TRASH fixture\n"
        with mock.patch("vaccum_actions.cleanup", side_effect=self.action):
            with mock.patch("vaccum.sys.stdin", stdin):
                status, output, error = self.invoke(["cleanup", "selected-root", "--target", "selected-target", "--apply", "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["status"], "complete")
        self.assertIn("TRASH fixture", error)

    def test_confirmation_interrupt_returns_structured_interrupted_report(self):
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        stdin.readline.side_effect = KeyboardInterrupt
        with mock.patch("vaccum_actions.cleanup", side_effect=self.action):
            with mock.patch("vaccum.sys.stdin", stdin):
                status, output, _ = self.invoke(["cleanup", "selected-root", "--target", "selected-target", "--apply", "--format", "json"])
        self.assertEqual(status, 130)
        self.assertEqual(json.loads(output)["status"], "interrupted")

    def test_uninstall_dispatches_explicit_package_ids_and_disposable_root(self):
        plan = {"action": "uninstall", "items": [], "confirmation_phrase": "REMOVE fixture", "warnings": []}

        def uninstall(packages, callback, root):
            self.assertEqual(packages, ["fixture:all"])
            self.assertEqual(root, "/tmp/fixture-root")
            self.assertIsNone(callback(plan))
            return {"status": "cancelled", "complete": False, "plan": plan}

        with mock.patch("vaccum_actions.uninstall", side_effect=uninstall):
            status, output, _ = self.invoke(["uninstall", "fixture:all", "--root", "/tmp/fixture-root", "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["status"], "preview")

    def test_preview_preserves_rejected_targets_as_incomplete(self):
        report = {"status": "cancelled", "complete": False, "plan": {"items": [{"target": "valid"}]},
                  "items": [{"target": "valid", "status": "cancelled"},
                            {"target": "invalid", "status": "rejected"}]}
        with mock.patch("vaccum_actions.cleanup", return_value=report):
            status, output, _ = self.invoke(["cleanup", "selected-root", "--target", "selected-target", "--format", "json"])
        result = json.loads(output)
        self.assertEqual(status, 1)
        self.assertFalse(result["complete"])
        self.assertEqual([item["status"] for item in result["items"]], ["planned", "rejected"])


if __name__ == "__main__":
    unittest.main()
