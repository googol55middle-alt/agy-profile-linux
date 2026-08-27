import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from email.message import Message
from pathlib import Path
from queue import SimpleQueue
from types import SimpleNamespace
from unittest.mock import patch

from agy_profile_linux import cli, manager


class ManagerHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="agy-profile-linux-")
        self.work = Path(self.tempdir.name)
        self.paths = manager.build_paths(self.work / "manager-state")

    def tearDown(self):
        self.tempdir.cleanup()

    def make_profile(
        self,
        name: str,
        *,
        token: str = "access-token",
        project_id: str = "project-id",
        expiry: str = "2999-01-01T00:00:00+00:00",
    ) -> Path:
        home = self.work / name
        profile = home / ".gemini" / "antigravity-cli"
        cache = profile / "cache"
        cache.mkdir(parents=True)
        (profile / "antigravity-oauth-token").write_text(
            json.dumps(
                {
                    "auth_method": "oauth",
                    "id_token": "id-token",
                    "token": {
                        "access_token": token,
                        "refresh_token": "refresh-token",
                        "expiry": expiry,
                        "token_type": "Bearer",
                    },
                }
            ),
            encoding="utf-8",
        )
        (cache / "default_project_id.txt").write_text(project_id + "\n", encoding="utf-8")
        return home

    def test_add_rejects_path_traversal_account_name_without_writing_outside_root(self):
        profile = self.make_profile("source")
        escaped = self.work / "escaped"

        with self.assertRaises(ValueError):
            manager.add_account(self.paths, "../../escaped", profile)

        self.assertFalse(escaped.exists())
        self.assertFalse(self.paths.accounts_dir.exists() and any(self.paths.accounts_dir.iterdir()))

    def test_overwrite_rejects_a_symlinked_account_directory_without_touching_its_target(self):
        manager.ensure_layout(self.paths)
        source = self.make_profile("source")
        outside = self.work / "outside-account"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        os.symlink(outside, self.paths.accounts_dir / "victim", target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.save_account_profile(self.paths, "victim", source, overwrite=True)

        self.assertEqual("keep", marker.read_text(encoding="utf-8"))

    def test_manager_lock_rejects_a_symlinked_lock_file_without_touching_its_target(self):
        manager.ensure_layout(self.paths)
        outside = self.work / "outside-lock"
        outside.write_text("keep", encoding="utf-8")
        os.symlink(outside, self.paths.lock_file)

        with self.assertRaisesRegex(ValueError, "symlink"):
            with manager.manager_lock(self.paths):
                self.fail("symlinked lock was accepted")

        self.assertEqual("keep", outside.read_text(encoding="utf-8"))

    def test_load_rejects_a_symlinked_state_file_without_touching_its_target(self):
        manager.ensure_layout(self.paths)
        self.paths.state_file.unlink()
        outside = self.work / "outside-state.json"
        outside.write_text("{}", encoding="utf-8")
        os.symlink(outside, self.paths.state_file)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.load_state(self.paths)

        self.assertEqual("{}", outside.read_text(encoding="utf-8"))

    def test_status_rejects_a_symlinked_account_directory(self):
        manager.ensure_layout(self.paths)
        outside = self.work / "outside-account"
        outside.mkdir()
        os.symlink(outside, self.paths.accounts_dir / "linked", target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.get_status_snapshot(self.paths)

    def test_cli_status_rejects_malformed_state_without_traceback(self):
        manager.ensure_layout(self.paths)
        self.paths.state_file.write_text(json.dumps({"accounts": []}), encoding="utf-8")

        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "status", "--json"],
            ),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as caught:
                cli.main()

        self.assertEqual(2, caught.exception.code)
        self.assertIn("Manager state file has invalid schema.", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_load_rejects_malformed_switch_history_without_numeric_traceback(self):
        manager.ensure_layout(self.paths)
        self.paths.state_file.write_text(
            json.dumps({"accounts": {}, "switch_history": [{"cooldown_minutes": "not-a-number"}]}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "invalid schema"):
            manager.load_state(self.paths)

    def test_cli_status_rejects_invalid_utf8_without_traceback(self):
        manager.ensure_layout(self.paths)
        self.paths.state_file.write_bytes(b'{"accounts": {\xff}')

        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "status"],
            ),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as caught:
                cli.main()

        self.assertEqual(2, caught.exception.code)
        self.assertIn("Manager state file is unreadable.", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_set_live_dir_rejects_a_symlink(self):
        manager.ensure_layout(self.paths)
        outside = self.work / "outside-live"
        outside.mkdir()
        link = self.work / "linked-live"
        os.symlink(outside, link, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.set_live_dir(self.paths, link)

    def test_live_profile_synchronization_is_disabled_but_legacy_setting_can_be_cleared(self):
        manager.ensure_layout(self.paths)
        live_dir = self.work / "legacy-live" / ".gemini"
        live_dir.parent.mkdir(parents=True)

        with self.assertRaisesRegex(ValueError, "disabled"):
            manager.set_live_dir(self.paths, live_dir)
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])

        state = manager.load_state(self.paths)
        state["live_dir"] = str(live_dir)
        manager.save_state(self.paths, state)
        manager.set_live_dir(self.paths, None)
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])

    def test_import_current_requires_an_explicit_source_when_a_legacy_live_dir_is_present(self):
        manager.ensure_layout(self.paths)
        legacy_home = self.make_profile("legacy-import", token="legacy-token")
        state = manager.load_state(self.paths)
        state["live_dir"] = str(legacy_home / ".gemini")
        manager.save_state(self.paths, state)

        with self.assertRaisesRegex(ValueError, "explicit source"):
            manager.import_current(self.paths, "new-account")

        self.assertFalse((self.paths.accounts_dir / "new-account").exists())

    def test_usage_refresh_rejects_a_legacy_live_dir_without_contacting_google(self):
        alice = self.make_profile("legacy-refresh-alice", token="alice-token")
        legacy_home = self.make_profile("legacy-refresh-live", token="legacy-token")
        manager.import_current(self.paths, "alice", alice)
        state = manager.load_state(self.paths)
        state["live_dir"] = str(legacy_home / ".gemini")
        manager.save_state(self.paths, state)

        with patch.object(
            manager,
            "_cloudcode_request",
            side_effect=AssertionError("unexpected Google request"),
        ):
            with self.assertRaisesRegex(ValueError, "disabled"):
                manager.refresh_account_usage(self.paths)

    def test_live_dir_is_opt_in_and_clearing_it_persists(self):
        manager.ensure_layout(self.paths)
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])
        manager.set_live_dir(self.paths, None)
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])

    def test_profile_copy_rejects_a_symlinked_cache_directory_without_touching_its_target(self):
        source = self.make_profile("source") / ".gemini"
        target = self.work / "target" / ".gemini"
        (target / "antigravity-cli").mkdir(parents=True)
        outside = self.work / "outside-cache"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        os.symlink(outside, target / "antigravity-cli" / "cache", target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager._copy_managed_profile_files(source, target)

        self.assertEqual("keep", marker.read_text(encoding="utf-8"))

    def test_layout_and_state_file_are_owner_private_and_default_to_manual_switching(self):
        manager.ensure_layout(self.paths)

        self.assertEqual(0o700, self.paths.root.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.paths.accounts_dir.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.paths.runtime_dir.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.paths.state_file.stat().st_mode & 0o777)
        self.assertEqual("manual", manager.load_state(self.paths)["switch_mode"])

    def test_state_write_replaces_using_directory_file_descriptors(self):
        manager.ensure_layout(self.paths)
        before = manager.load_state(self.paths)
        before["switch_mode"] = "manual"
        real_replace = manager.os.replace
        replace_calls = []

        def replace_spy(source, target, *args, **kwargs):
            replace_calls.append((source, target, kwargs))
            return real_replace(source, target, *args, **kwargs)

        with patch.object(manager.os, "replace", side_effect=replace_spy):
            manager.save_state(self.paths, before)

        self.assertTrue(replace_calls)
        self.assertTrue(
            any(
                call[2].get("src_dir_fd") is not None and call[2].get("dst_dir_fd") is not None
                for call in replace_calls
            )
        )

    def test_save_current_account_saves_only_the_live_account_files(self):
        live_home = self.make_profile("live-save", token="current-token", project_id="project-current")
        shared = live_home / ".gemini" / "settings.json"
        shared.write_text("keep-shared", encoding="utf-8")

        manager.save_current_account(self.paths, "current", live_home=live_home)

        saved_root = self.paths.accounts_dir / "current" / ".gemini" / "antigravity-cli"
        self.assertEqual("current-token", json.loads((saved_root / "antigravity-oauth-token").read_text(encoding="utf-8"))["token"]["access_token"])
        self.assertEqual("project-current", (saved_root / "cache" / "default_project_id.txt").read_text(encoding="utf-8").strip())
        self.assertFalse((self.paths.accounts_dir / "current" / ".gemini" / "settings.json").exists())

    def test_live_switch_replaces_only_auth_and_project_id_in_the_live_home(self):
        alice = self.make_profile("live-alice", token="alice-token", project_id="project-alice")
        bob = self.make_profile("live-bob", token="bob-token", project_id="project-bob")
        live_home = self.work / "live-home"
        live_profile = live_home / ".gemini" / "antigravity-cli"
        (live_profile / "cache").mkdir(parents=True)
        (live_profile / "settings.json").write_text("shared-settings", encoding="utf-8")
        (live_profile / "knowledge.db").write_text("shared-knowledge", encoding="utf-8")
        (live_profile / "antigravity-oauth-token").write_text(
            (alice / ".gemini" / "antigravity-cli" / "antigravity-oauth-token").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (live_profile / "cache" / "default_project_id.txt").write_text("project-alice\\n", encoding="utf-8")
        for directory in (live_home / ".gemini", live_profile, live_profile / "cache"):
            directory.chmod(0o755)

        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)

        manager.switch_live_account(self.paths, "bob", live_home=live_home)

        self.assertEqual(
            "bob-token",
            json.loads((live_profile / "antigravity-oauth-token").read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual("project-bob", (live_profile / "cache" / "default_project_id.txt").read_text(encoding="utf-8").strip())
        self.assertEqual("shared-settings", (live_profile / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual("shared-knowledge", (live_profile / "knowledge.db").read_text(encoding="utf-8"))
        self.assertEqual(0o755, (live_home / ".gemini").stat().st_mode & 0o777)
        self.assertEqual(0o755, live_profile.stat().st_mode & 0o777)
        self.assertEqual(0o755, (live_profile / "cache").stat().st_mode & 0o777)
        self.assertEqual("bob", manager.load_state(self.paths)["active"])

    def test_live_switch_can_gracefully_close_matching_live_home_agy(self):
        live_home = self.make_profile("live-close", token="current-token", project_id="project-current")
        target = self.make_profile("close-target", token="target-token", project_id="project-target")
        manager.import_current(self.paths, "target", target)
        code = "import time; open('/proc/self/comm', 'w').write('agy\\n'); time.sleep(60)"
        env = os.environ.copy()
        env["HOME"] = str(live_home)
        proc = subprocess.Popen([sys.executable, "-c", code], env=env)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if manager._running_agy_pids(live_home):
                    break
                time.sleep(0.05)
            self.assertTrue(manager._running_agy_pids(live_home))
            previous = manager.switch_live_account(self.paths, "target", live_home=live_home, close_running=True)
            self.assertEqual("target", previous)
            self.assertFalse(manager._running_agy_pids(live_home))
            self.assertEqual("target-token", json.loads((live_home / ".gemini" / "antigravity-cli" / "antigravity-oauth-token").read_text(encoding="utf-8"))["token"]["access_token"])
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_live_switch_refuses_while_agy_is_running(self):
        alice = self.make_profile("live-running-alice", token="alice-token")
        bob = self.make_profile("live-running-bob", token="bob-token")
        live_home = self.work / "live-running-home"
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)

        with patch.object(manager, "_running_agy_pids", return_value=[1234]):
            with self.assertRaisesRegex(ValueError, "agy is running"):
                manager.switch_live_account(self.paths, "bob", live_home=live_home)

        self.assertFalse(live_home.exists())
        self.assertEqual("alice", manager.load_state(self.paths)["active"])

    def test_live_switch_rolls_back_live_files_when_state_persistence_fails(self):
        alice = self.make_profile("live-rollback-alice", token="alice-token", project_id="project-alice")
        bob = self.make_profile("live-rollback-bob", token="bob-token", project_id="project-bob")
        live_home = self.work / "live-rollback-home"
        live_profile = live_home / ".gemini" / "antigravity-cli"
        (live_profile / "cache").mkdir(parents=True)
        shutil.copy2(alice / ".gemini" / "antigravity-cli" / "antigravity-oauth-token", live_profile / "antigravity-oauth-token")
        shutil.copy2(alice / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt", live_profile / "cache" / "default_project_id.txt")
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)

        with patch.object(manager, "save_state", side_effect=OSError("simulated state write failure")):
            with self.assertRaisesRegex(OSError, "simulated state write failure"):
                manager.switch_live_account(self.paths, "bob", live_home=live_home)

        self.assertEqual("alice-token", json.loads((live_profile / "antigravity-oauth-token").read_text(encoding="utf-8"))["token"]["access_token"])
        self.assertEqual("project-alice", (live_profile / "cache" / "default_project_id.txt").read_text(encoding="utf-8").strip())
        self.assertEqual("alice", manager.load_state(self.paths)["active"])

    def test_switch_copies_the_account_bound_project_id_into_the_isolated_runtime(self):
        alice = self.make_profile("alice", token="alice-token", project_id="project-alice")
        bob = self.make_profile("bob", token="bob-token", project_id="project-bob")
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)

        manager.switch_account(self.paths, "bob")

        project_file = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt"
        self.assertEqual("project-bob", project_file.read_text(encoding="utf-8").strip())
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])

    def test_saved_credentials_and_profile_directories_are_owner_private(self):
        alice = self.make_profile("alice")
        manager.import_current(self.paths, "alice", alice)

        token_paths = [
            self.paths.accounts_dir / "alice" / ".gemini" / "antigravity-cli" / "antigravity-oauth-token",
            self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "antigravity-oauth-token",
        ]
        for path in token_paths:
            self.assertEqual(0o600, path.stat().st_mode & 0o777, path)
        self.assertEqual(0o700, (self.paths.accounts_dir / "alice").stat().st_mode & 0o777)
        self.assertEqual(0o700, (self.paths.accounts_dir / "alice" / ".gemini").stat().st_mode & 0o777)
        self.assertEqual(0o700, (self.paths.runtime_dir / ".gemini").stat().st_mode & 0o777)

    def test_add_rejects_a_malformed_oauth_token_file(self):
        profile = self.make_profile("malformed")
        token_path = profile / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        token_path.write_text("not-json", encoding="utf-8")

        with self.assertRaises(ValueError):
            manager.add_account(self.paths, "bad", profile)

        self.assertFalse((self.paths.accounts_dir / "bad").exists())

    def test_invalid_utf8_oauth_token_is_reported_as_invalid_credentials(self):
        profile = self.make_profile("invalid-utf8")
        token_path = profile / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        token_path.write_bytes(b'{"token": \xff}')

        with self.assertRaisesRegex(ValueError, "not found or invalid"):
            manager._load_antigravity_token_state(profile)

    def test_invalid_utf8_optional_profile_metadata_is_ignored(self):
        profile = self.make_profile("invalid-metadata")
        metadata_path = profile / ".gemini" / "antigravity-cli" / "google_accounts.json"
        metadata_path.write_bytes(b"\xff")

        self.assertEqual("unavailable", manager.detect_profile_identity(profile)["source"])

    def test_profile_copy_runs_only_while_the_manager_lock_is_held(self):
        source = self.make_profile("lock-held-source")
        held = {"value": False}
        original_copy = manager._copy_account_profile

        @contextmanager
        def lock_spy(_paths):
            held["value"] = True
            try:
                yield
            finally:
                held["value"] = False

        def checked_copy(source_dir, target_home):
            if not held["value"]:
                raise AssertionError("profile copy happened outside manager lock")
            return original_copy(source_dir, target_home)

        with (
            patch.object(manager, "manager_lock", lock_spy),
            patch.object(manager, "_copy_account_profile", side_effect=checked_copy),
        ):
            manager.save_account_profile(self.paths, "locked", source)

        self.assertTrue((self.paths.accounts_dir / "locked").is_dir())

    def test_second_process_waits_before_mutating_an_account_store(self):
        source = self.make_profile("process-lock-source")
        source_root = Path(__file__).resolve().parents[1] / "src"
        script = (
            "from pathlib import Path\n"
            "from agy_profile_linux import manager\n"
            "import sys\n"
            "manager.add_account(manager.build_paths(Path(sys.argv[1])), 'second', Path(sys.argv[2]))\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(source_root) + os.pathsep + env.get("PYTHONPATH", "")

        with manager.manager_lock(self.paths):
            proc = subprocess.Popen(
                [sys.executable, "-c", script, str(self.paths.root), str(source)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            try:
                time.sleep(0.15)
                self.assertIsNone(proc.poll(), "second writer bypassed the manager lock")
            except Exception:
                proc.terminate()
                proc.wait(timeout=5)
                raise
        stdout, stderr = proc.communicate(timeout=5)
        self.assertEqual(0, proc.returncode, stderr or stdout)
        self.assertTrue((self.paths.accounts_dir / "second").is_dir())

    def test_failed_account_overwrite_restores_saved_and_runtime_profile(self):
        alice = self.make_profile("save-rollback-alice", token="alice-token")
        bob = self.make_profile("save-rollback-bob", token="bob-token")
        manager.import_current(self.paths, "alice", alice)

        with patch.object(manager, "save_state", side_effect=OSError("simulated state write failure")):
            with self.assertRaisesRegex(OSError, "simulated state write failure"):
                manager.save_account_profile(self.paths, "alice", bob, overwrite=True)

        saved_token = self.paths.accounts_dir / "alice" / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        runtime_token = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "alice-token",
            json.loads(saved_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual(
            "alice-token",
            json.loads(runtime_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual("alice", manager.load_state(self.paths)["active"])
        self.assertEqual(["alice"], sorted(entry.name for entry in self.paths.accounts_dir.iterdir()))

    def test_isolated_runtime_switching_does_not_block_on_an_unrelated_agy_process(self):
        alice = self.make_profile("alice", token="alice-token")
        bob = self.make_profile("bob", token="bob-token")
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)

        fake_agy = self.work / "agy"
        shutil.copy2("/bin/sleep", fake_agy)
        fake_agy.chmod(0o755)
        proc = subprocess.Popen([str(fake_agy), "30"])
        try:
            self.assertEqual("agy", Path(f"/proc/{proc.pid}/comm").read_text(encoding="utf-8").strip())
            self.assertEqual("alice", manager.switch_account(self.paths, "bob"))
            rotation = manager.rotate_after_failure(
                self.paths,
                reason="test",
                force_switch=True,
            )
            self.assertEqual("alice", rotation.switched_to)
            runtime_token = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
            self.assertEqual(
                "alice-token",
                json.loads(runtime_token.read_text(encoding="utf-8"))["token"]["access_token"],
            )
            self.assertEqual("alice", manager.load_state(self.paths)["active"])
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_switch_rolls_back_runtime_when_legacy_live_sync_is_blocked(self):
        alice = self.make_profile("race-alice", token="alice-token")
        bob = self.make_profile("race-bob", token="bob-token")
        legacy_home = self.make_profile("race-legacy-live", token="legacy-token")
        legacy_live_dir = legacy_home / ".gemini"
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)
        state = manager.load_state(self.paths)
        state["live_dir"] = str(legacy_live_dir)
        manager.save_state(self.paths, state)

        with self.assertRaisesRegex(ValueError, "disabled"):
            manager.switch_account(self.paths, "bob")

        runtime_token = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        live_token = legacy_live_dir / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "alice-token",
            json.loads(runtime_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual(
            "legacy-token",
            json.loads(live_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual("alice", manager.load_state(self.paths)["active"])

    def test_rotation_rolls_back_runtime_and_state_when_legacy_live_sync_is_blocked(self):
        alice = self.make_profile("rotate-alice", token="alice-token")
        bob = self.make_profile("rotate-bob", token="bob-token")
        legacy_home = self.make_profile("rotate-legacy-live", token="legacy-token")
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)
        state = manager.load_state(self.paths)
        state["live_dir"] = str(legacy_home / ".gemini")
        manager.save_state(self.paths, state)

        with self.assertRaisesRegex(ValueError, "disabled"):
            manager.rotate_after_failure(
                self.paths,
                reason="test",
                force_switch=True,
            )

        runtime_token = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "alice-token",
            json.loads(runtime_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        state = manager.load_state(self.paths)
        self.assertEqual("alice", state["active"])
        self.assertEqual("idle", state["switch_runtime"]["status"])

    def test_run_active_uses_a_private_ephemeral_session_and_holds_the_manager_lock(self):
        alice = self.make_profile("run-alice", token="alice-token")
        manager.import_current(self.paths, "alice", alice)
        fake_agy = self.work / "fake-agy"
        report = self.work / "run-report.json"
        fake_agy.write_text(
            """#!/usr/bin/env python3
import fcntl
import json
import os
import sys
fd = os.open(os.environ['AGY_MANAGER_TEST_LOCK'], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    lock_held = False
except BlockingIOError:
    lock_held = True
with open(os.environ['AGY_MANAGER_TEST_REPORT'], 'w', encoding='utf-8') as handle:
    json.dump({'home': os.environ['HOME'], 'args': sys.argv[1:], 'lock_held': lock_held}, handle)
sys.exit(17)
""",
            encoding="utf-8",
        )
        fake_agy.chmod(0o755)

        with patch.dict(
            os.environ,
            {
                "AGY_MANAGER_TEST_LOCK": str(self.paths.lock_file),
                "AGY_MANAGER_TEST_REPORT": str(report),
            },
            clear=False,
        ):
            result = manager.run_active(self.paths, str(fake_agy), ["--marker"])

        self.assertEqual(17, result)
        observed = json.loads(report.read_text(encoding="utf-8"))
        session_home = Path(observed["home"])
        self.assertNotEqual(self.paths.runtime_dir, session_home)
        self.assertEqual(self.paths.root, session_home.parent)
        self.assertTrue(session_home.name.startswith(".run-session-"))
        self.assertFalse(session_home.exists())
        self.assertEqual(["--marker"], observed["args"])
        self.assertTrue(observed["lock_held"])
        self.assertIsNone(manager.load_state(self.paths)["live_dir"])

    def test_run_active_sanitizes_binary_start_failures(self):
        alice = self.make_profile("run-failure-alice")
        manager.import_current(self.paths, "alice", alice)

        with patch.object(
            manager.subprocess,
            "run",
            side_effect=FileNotFoundError("/tmp/private-missing-agy"),
        ):
            with self.assertRaisesRegex(ValueError, "Unable to start agy") as caught:
                manager.run_active(self.paths, "missing-agy")

        self.assertNotIn("/tmp/private-missing-agy", str(caught.exception))

    def test_public_api_exports_the_isolated_runner(self):
        from agy_profile_linux import run_active

        self.assertIs(manager.run_active, run_active)

    def test_cli_switch_uses_live_switch_by_default(self):
        with (
            patch.object(cli, "switch_live_account", return_value="alice") as live_switch,
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "switch", "bob"],
            ),
        ):
            self.assertEqual(0, cli.main())

        live_switch.assert_called_once_with(
            cli.build_paths(self.paths.root),
            "bob",
            close_running=False,
            close_timeout_seconds=10.0,
        )

    def test_cli_switch_can_request_graceful_close(self):
        with (
            patch.object(cli, "switch_live_account", return_value="alice") as live_switch,
            patch.object(
                sys,
                "argv",
                [
                    "agy-profile-linux",
                    "--root",
                    str(self.paths.root),
                    "switch",
                    "bob",
                    "--close",
                    "--close-timeout-seconds",
                    "20",
                ],
            ),
        ):
            self.assertEqual(0, cli.main())

        live_switch.assert_called_once_with(
            cli.build_paths(self.paths.root),
            "bob",
            close_running=True,
            close_timeout_seconds=20.0,
        )

    def test_cli_switch_can_select_the_isolated_runtime_explicitly(self):
        with (
            patch.object(cli, "switch_account", return_value="alice") as isolated_switch,
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "switch", "bob", "--isolated"],
            ),
        ):
            self.assertEqual(0, cli.main())

        isolated_switch.assert_called_once_with(cli.build_paths(self.paths.root), "bob")

    def test_cli_run_forwards_arguments_and_preserves_the_child_exit_code(self):
        with (
            patch.object(cli, "run_active", return_value=17) as run,
            patch.object(
                sys,
                "argv",
                [
                    "agy-profile-linux",
                    "--root",
                    str(self.paths.root),
                    "run",
                    "--agy-binary",
                    "fake-agy",
                    "--",
                    "--marker",
                ],
            ),
        ):
            self.assertEqual(17, cli.main())

        received_paths, received_binary, received_args = run.call_args.args
        self.assertEqual(self.paths.root, received_paths.root)
        self.assertEqual("fake-agy", received_binary)
        self.assertEqual(["--marker"], received_args)

    def test_login_uses_an_isolated_home_and_preserves_an_unmanaged_live_profile(self):
        alice = self.make_profile("alice", token="alice-token")
        live_home = self.make_profile("unmanaged-live", token="live-token")
        live_dir = live_home / ".gemini"
        manager.import_current(self.paths, "alice", alice)
        login_homes = []

        class FakePopen:
            def __init__(self, _args, **kwargs):
                home = Path(kwargs["env"]["HOME"])
                login_homes.append(home)
                profile = home / ".gemini" / "antigravity-cli"
                profile.mkdir(parents=True, exist_ok=True)
                (profile / "antigravity-oauth-token").write_text(
                    json.dumps(
                        {
                            "auth_method": "oauth",
                            "token": {
                                "access_token": "bob-token",
                                "refresh_token": "bob-refresh",
                                "expiry": "2999-01-01T00:00:00+00:00",
                            },
                        }
                    ),
                    encoding="utf-8",
                )

            def poll(self):
                return 0

        with (
            patch.object(manager.os, "isatty", return_value=True),
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "Popen", FakePopen),
            patch.object(
                manager,
                "resolve_login_profile_identity",
                return_value={"account_name": None, "source": "unavailable"},
            ),
        ):
            self.assertEqual("bob", manager.login_account(self.paths, "bob", "fake-agy"))

        self.assertEqual(1, len(login_homes))
        login_home = login_homes[0]
        self.assertNotEqual(live_dir.parent, login_home)
        self.assertEqual(self.paths.root, login_home.parent)
        self.assertTrue(login_home.name.startswith(".login-"))
        self.assertFalse(login_home.exists())
        live_token = live_dir / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "live-token",
            json.loads(live_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )
        self.assertEqual("alice", manager.load_state(self.paths)["active"])
        saved_bob = self.paths.accounts_dir / "bob" / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "bob-token",
            json.loads(saved_bob.read_text(encoding="utf-8"))["token"]["access_token"],
        )

    def test_identity_probe_never_runs_agy_in_the_live_home(self):
        source = self.make_profile("probe-source", token="source-token")
        live_home = self.make_profile("probe-live", token="live-token")
        live_dir = live_home / ".gemini"
        homes = []

        def fake_run(_args, **kwargs):
            homes.append(Path(kwargs["env"]["HOME"]))
            return SimpleNamespace(returncode=0, stdout="user@example.com\n", stderr="")

        with (
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "run", side_effect=fake_run),
        ):
            identity = manager.probe_profile_identity_via_usage(
                source,
                agy_binary="fake-agy",
                scratch_root=self.paths.root,
            )

        self.assertEqual("user@example.com", identity["account_name"])
        self.assertEqual(1, len(homes))
        probe_home = homes[0]
        self.assertNotEqual(live_home, probe_home)
        self.assertEqual(self.paths.root, probe_home.parent)
        self.assertTrue(probe_home.name.startswith(".usage-probe-"))
        self.assertFalse(probe_home.exists())
        live_token = live_dir / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "live-token",
            json.loads(live_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )

    def test_identity_probe_sanitizes_process_failures(self):
        source = self.make_profile("probe-failure", token="source-token")

        with (
            patch.object(manager, "resolve_agy_binary", return_value="missing-agy"),
            patch.object(
                manager.subprocess,
                "run",
                side_effect=FileNotFoundError("/tmp/private-missing-agy"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "Unable to execute agy usage probe") as caught:
                manager.probe_profile_identity_via_usage(
                    source,
                    agy_binary="missing-agy",
                    scratch_root=self.paths.root,
                )

        self.assertNotIn("/tmp/private-missing-agy", str(caught.exception))

    def test_model_lookup_sanitizes_process_failures(self):
        source = self.make_profile("models-failure", token="source-token")
        manager.import_current(self.paths, "alice", source)

        with (
            patch.object(manager, "resolve_agy_binary", return_value="missing-agy"),
            patch.object(
                manager.subprocess,
                "run",
                side_effect=FileNotFoundError("/tmp/private-missing-agy"),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "Unable to execute agy models") as caught:
                manager.list_models(self.paths, "alice", agy_binary="missing-agy")

        self.assertNotIn("/tmp/private-missing-agy", str(caught.exception))

    def test_model_lookup_never_runs_agy_in_an_unmanaged_live_home(self):
        alice = self.make_profile("model-alice", token="alice-token")
        bob = self.make_profile("model-bob", token="bob-token")
        live_home = self.make_profile("model-live", token="live-token")
        live_dir = live_home / ".gemini"
        manager.import_current(self.paths, "alice", alice)
        manager.import_current(self.paths, "bob", bob)
        homes = []

        def fake_run(_args, **kwargs):
            homes.append(Path(kwargs["env"]["HOME"]))
            return SimpleNamespace(returncode=0, stdout="Google Gemini 3\n", stderr="")

        with (
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "run", side_effect=fake_run),
        ):
            result = manager.list_models(self.paths, "bob", agy_binary="fake-agy")

        self.assertEqual("bob", result["account"])
        self.assertEqual(1, len(homes))
        model_home = homes[0]
        self.assertNotEqual(live_dir.parent, model_home)
        self.assertEqual(self.paths.root, model_home.parent)
        self.assertTrue(model_home.name.startswith(".models-"))
        self.assertFalse(model_home.exists())
        live_token = live_dir / "antigravity-cli" / "antigravity-oauth-token"
        self.assertEqual(
            "live-token",
            json.loads(live_token.read_text(encoding="utf-8"))["token"]["access_token"],
        )

    def test_import_does_not_contact_google_with_the_saved_access_token(self):
        source = self.make_profile("private-import")

        with patch.object(
            manager,
            "_best_effort_live_identity",
            side_effect=AssertionError("unexpected network identity lookup"),
        ):
            manager.add_account(self.paths, "private", source)

        self.assertTrue((self.paths.accounts_dir / "private").is_dir())

    def test_persisted_project_id_is_owner_private(self):
        home = self.work / "project-home"
        manager._persist_project_id(home, "project-id")

        project_file = home / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt"
        self.assertEqual(0o600, project_file.stat().st_mode & 0o777)
        self.assertEqual(0o700, (home / ".gemini").stat().st_mode & 0o777)
        self.assertEqual(0o700, project_file.parent.stat().st_mode & 0o777)

    def test_usage_refresh_keeps_isolated_project_state_owner_private(self):
        alice = self.make_profile("refresh-alice", project_id="cached-project")
        manager.import_current(self.paths, "alice", alice)
        runtime_project = self.paths.runtime_dir / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt"
        runtime_project.chmod(0o644)

        def fake_cloudcode_request(_token, path, _payload):
            if path == manager.CODE_ASSIST_LOAD_PATH:
                return {
                    "cloudaicompanionProject": "refreshed-project",
                    "planInfo": {},
                    "availablePromptCredits": 0,
                }
            if path == manager.CODE_ASSIST_QUOTA_SUMMARY_PATH:
                return {"groups": [{"displayName": "Gemini", "buckets": []}]}
            raise AssertionError(path)

        with (
            patch.object(manager, "_cloudcode_request", side_effect=fake_cloudcode_request),
            patch.object(manager, "_best_effort_live_identity", return_value=None),
        ):
            manager.refresh_account_usage(self.paths)

        stored_project = self.paths.accounts_dir / "alice" / ".gemini" / "antigravity-cli" / "cache" / "default_project_id.txt"
        self.assertEqual(0o600, runtime_project.stat().st_mode & 0o777)
        self.assertEqual(0o600, stored_project.stat().st_mode & 0o777)
        self.assertEqual("refreshed-project", stored_project.read_text(encoding="utf-8").strip())

    def test_models_command_does_not_expose_child_output_on_failure(self):
        source = self.make_profile("models-output-redaction")
        manager.import_current(self.paths, "alice", source)
        marker = "SYNTHETIC_DO_NOT_LEAK"

        def fake_run(_args, **_kwargs):
            return SimpleNamespace(returncode=1, stdout=marker, stderr=marker)

        with (
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "run", side_effect=fake_run),
        ):
            with self.assertRaisesRegex(ValueError, "agy models") as caught:
                manager.list_models(self.paths, "alice", agy_binary="fake-agy")

        self.assertNotIn(marker, str(caught.exception))

    def test_models_command_drops_unrecognized_child_output(self):
        source = self.make_profile("models-success-redaction")
        manager.import_current(self.paths, "alice", source)
        marker = "SYNTHETIC_DO_NOT_LEAK"

        def fake_run(_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=marker + "\nGoogle Gemini 3\n", stderr="")

        with (
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "run", side_effect=fake_run),
        ):
            payload = manager.list_models(self.paths, "alice", agy_binary="fake-agy")

        self.assertNotIn(marker, json.dumps(payload))
        self.assertEqual(["Google Gemini 3"], [item["name"] for item in payload["models"]])

    def test_usage_probe_omits_untrusted_child_output(self):
        source = self.make_profile("probe-output-redaction")
        marker = "SYNTHETIC_DO_NOT_LEAK"

        def fake_run(_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=marker, stderr="")

        with (
            patch.object(manager, "resolve_agy_binary", return_value="fake-agy"),
            patch.object(manager.subprocess, "run", side_effect=fake_run),
        ):
            identity = manager.probe_profile_identity_via_usage(
                source,
                agy_binary="fake-agy",
                scratch_root=self.paths.root,
            )

        self.assertNotIn("raw_hint", identity)
        self.assertNotIn(marker, json.dumps(identity))

    def test_proxy_metadata_rejects_embedded_credentials(self):
        source = self.make_profile("proxy-redaction")
        manager.import_current(self.paths, "alice", source)
        marker = "SYNTHETIC_DO_NOT_LEAK"

        with self.assertRaisesRegex(ValueError, "without credentials"):
            manager.set_account_proxy(
                self.paths,
                "alice",
                url=f"http://user:{marker}@proxy.example:8080",
            )

        self.assertNotIn(marker, json.dumps(manager.get_status_snapshot(self.paths)))

    def test_cloudcode_error_does_not_expose_upstream_body(self):
        marker = "SYNTHETIC_DO_NOT_LEAK"
        error = manager.urllib.error.HTTPError(
            "https://example.invalid",
            403,
            "Forbidden",
            hdrs=Message(),
            fp=io.BytesIO(json.dumps({"error": {"message": marker}}).encode("utf-8")),
        )

        with patch.object(manager.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(ValueError, "HTTP 403") as caught:
                manager._cloudcode_request("synthetic-token", "/synthetic", {})

        self.assertNotIn(marker, str(caught.exception))

    def test_log_identity_rejects_symlinked_log_directory(self):
        source = self.make_profile("log-symlink")
        profile = source / ".gemini" / "antigravity-cli"
        outside = self.work / "outside-log"
        outside.mkdir()
        (outside / "latest.log").write_text(
            "applyAuthResult: email=attacker@example.invalid\n", encoding="utf-8"
        )
        os.symlink(outside, profile / "log", target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            manager.detect_profile_identity(source)

    def test_log_identity_rejects_oversize_log_file(self):
        source = self.make_profile("log-oversize")
        log_dir = source / ".gemini" / "antigravity-cli" / "log"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "latest.log").write_bytes(b"x" * (manager.MAX_IDENTITY_LOG_BYTES + 1))

        with self.assertRaisesRegex(ValueError, "size limit"):
            manager.detect_profile_identity(source)

    def test_nested_manager_locks_track_all_held_roots(self):
        other_paths = manager.build_paths(self.work / "other-manager")
        with manager.manager_lock(self.paths):
            with manager.manager_lock(other_paths):
                with manager.manager_lock(self.paths):
                    self.assertTrue(True)

    def test_cloudcode_network_failures_are_sanitized(self):
        marker = "SYNTHETIC_DO_NOT_LEAK"
        with patch.object(
            manager.urllib.request,
            "urlopen",
            side_effect=manager.urllib.error.URLError(marker),
        ):
            with self.assertRaisesRegex(ValueError, "Cloud Code request failed") as caught:
                manager._cloudcode_request("synthetic-token", "/synthetic", {})

        self.assertNotIn(marker, str(caught.exception))

    def test_refresh_holds_the_manager_lock_during_cloudcode_requests(self):
        source = self.make_profile("refresh-lock")
        manager.import_current(self.paths, "alice", source)
        lock_observations = []

        def fake_cloudcode_request(_token, path, _payload):
            probe_fd = os.open(self.paths.lock_file, os.O_RDWR)
            try:
                try:
                    import fcntl
                    fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (BlockingIOError, OSError):
                    lock_observations.append((path, True))
                else:
                    lock_observations.append((path, False))
                    fcntl.flock(probe_fd, fcntl.LOCK_UN)
            finally:
                os.close(probe_fd)
            if path == manager.CODE_ASSIST_LOAD_PATH:
                return {"cloudaicompanionProject": "refresh-project", "planInfo": {}}
            return {"groups": []}

        with (
            patch.object(manager, "_cloudcode_request", side_effect=fake_cloudcode_request),
            patch.object(manager, "_best_effort_live_identity", return_value=None),
        ):
            manager.refresh_account_usage(self.paths)

        self.assertEqual(
            [(manager.CODE_ASSIST_LOAD_PATH, True), (manager.CODE_ASSIST_QUOTA_SUMMARY_PATH, True)],
            lock_observations,
        )

    def test_refresh_failure_metadata_does_not_store_untrusted_error_text(self):
        source = self.make_profile("failure-error-redaction")
        manager.import_current(self.paths, "alice", source)
        marker = "SYNTHETIC_DO_NOT_LEAK"

        manager._persist_refresh_failure(self.paths, "alice", marker)

        payload = manager.get_status_snapshot(self.paths)
        self.assertNotIn(marker, json.dumps(payload))
        self.assertEqual(
            "Usage refresh failed. Retry later or complete an interactive login.",
            payload["accounts"]["alice"]["last_live_check_error"],
        )

    def test_caller_failure_reason_is_not_persisted_or_displayed(self):
        source = self.make_profile("reason-redaction")
        manager.import_current(self.paths, "alice", source)
        marker = "SECRET_REASON_TOKEN"

        manager.mark_bad(self.paths, "alice", marker, 0)
        payload = manager.get_status_snapshot(self.paths)
        rendered = manager.format_status(self.paths)

        self.assertNotIn(marker, json.dumps(payload))
        self.assertNotIn(marker, rendered)
        self.assertEqual("caller_reported_failure", payload["accounts"]["alice"]["last_error"])

    def test_login_startup_error_does_not_expose_binary_path(self):
        missing = self.work / "private-binary-name"
        for startup_error in (FileNotFoundError, PermissionError):
            with self.subTest(startup_error=startup_error.__name__):
                with patch.object(manager.os, "isatty", return_value=True), patch.object(
                    manager.subprocess, "Popen", side_effect=startup_error
                ):
                    with self.assertRaisesRegex(ValueError, "not found or is not executable") as caught:
                        manager.login_account(self.paths, "alice", str(missing))

                self.assertNotIn(str(missing), str(caught.exception))

    def test_deprecated_warmup_is_disabled_without_executing_agy(self):
        with patch.object(manager.subprocess, "run", side_effect=AssertionError("agy was executed")):
            with self.assertRaisesRegex(ValueError, "disabled"):
                manager._run_agy_warmup(self.work, "fake-agy", 1)

    def test_usage_refresh_refuses_expired_credentials_without_running_agy_unsafe_mode(self):
        expired = self.make_profile(
            "expired",
            expiry="2000-01-01T00:00:00+00:00",
        )
        manager.import_current(self.paths, "expired", expired)

        with patch.object(manager, "_run_agy_warmup", side_effect=AssertionError("unsafe warmup invoked")):
            with self.assertRaisesRegex(ValueError, "interactive login"):
                manager.refresh_account_usage(self.paths, "expired")
    def test_close_live_agy_rechecks_pids_before_signaling(self):
        with (
            patch.object(manager, "_running_agy_pids", side_effect=[[1234], [], []]),
            patch.object(manager.os, "kill") as kill,
        ):
            closed = manager.close_live_agy(live_home=self.work / "live", timeout_seconds=0.1)

        self.assertEqual(1, closed)
        kill.assert_not_called()

    def test_cli_redacts_absolute_paths_from_value_errors(self):
        marker = "/secret/private-state"
        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "status", "--json"],
            ),
            patch.object(cli, "get_status_snapshot", side_effect=ValueError(f"Unsafe path: {marker}")),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as caught:
                cli.main()

        self.assertEqual(2, caught.exception.code)
        self.assertNotIn(marker, stderr.getvalue())
        self.assertIn("Unsafe path: [path]", stderr.getvalue())

    def test_cli_sanitizes_unexpected_os_errors_without_traceback(self):
        marker = "/secret/private-state"
        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "status", "--json"],
            ),
            patch.object(cli, "get_status_snapshot", side_effect=OSError(marker)),
            redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as caught:
                cli.main()

        self.assertEqual(2, caught.exception.code)
        self.assertIn("operation failed due to an operating-system error", stderr.getvalue())
        self.assertNotIn(marker, stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_dashboard_refresh_worker_sanitizes_unexpected_errors(self):
        marker = "/secret/private-refresh"
        result_queue = SimpleQueue()
        with patch.object(cli, "refresh_account_usage", side_effect=OSError(marker)):
            thread = cli._start_usage_refresh_worker(self.paths, "alice", result_queue)
            thread.join(timeout=2)

        result = result_queue.get_nowait()
        self.assertFalse(result["ok"])
        self.assertEqual("Usage refresh failed.", result["error"])
        self.assertNotIn(marker, result["error"])

    def test_cli_verify_accounts_returns_nonzero_for_unhealthy_account(self):
        manager.ensure_layout(self.paths)
        profile = self.paths.accounts_dir / "bad" / ".gemini" / "antigravity-cli"
        profile.mkdir(parents=True)
        (profile / "antigravity-oauth-token").write_text('{"token": {}}', encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["agy-profile-linux", "--root", str(self.paths.root), "verify-accounts"],
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = cli.main()

        self.assertEqual(1, exit_code)
        self.assertIn("bad: missing_auth", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
