"""Unit tests for Git hooks and doctor automation in agent-link-cli."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestGitHooksAndDoctor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name)
        # Initialize disposable repo
        subprocess.check_call(["git", "init"], cwd=self.repo_dir)
        subprocess.check_call(["git", "config", "user.name", "Test Runner"], cwd=self.repo_dir)
        subprocess.check_call(["git", "config", "user.email", "test@runner.local"], cwd=self.repo_dir)
        subprocess.check_call(["git", "branch", "-M", "main"], cwd=self.repo_dir)

        # Copy .githooks
        project_hooks = Path(".githooks")
        target_hooks = self.repo_dir / ".githooks"
        target_hooks.mkdir(parents=True, exist_ok=True)
        for h in project_hooks.iterdir():
            if h.is_file():
                dest = target_hooks / h.name
                shutil.copyfile(h, dest)
                dest.chmod(0o755)

        subprocess.check_call(["git", "config", "--local", "core.hooksPath", ".githooks"], cwd=self.repo_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pre_commit_blocks_conflict_markers(self):
        bad_file = self.repo_dir / "conflict.txt"
        bad_file.write_text("line 1\n<<<<<<< HEAD\nconflict\n=======\nresolved\n>>>>>>> branch\n")
        subprocess.check_call(["git", "add", "conflict.txt"], cwd=self.repo_dir)

        proc = subprocess.run(
            ["git", "commit", "-m", "bad commit"],
            cwd=self.repo_dir,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("conflict marker", proc.stdout + proc.stderr)

    def test_pre_push_ignores_delete_only_ref(self):
        pre_push_script = self.repo_dir / ".githooks" / "pre-push"
        delete_stdin = "refs/heads/foo 0000000000000000000000000000000000000000 refs/heads/foo 1111111111111111111111111111111111111111\n"
        proc = subprocess.run(
            [str(pre_push_script)],
            input=delete_stdin,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Delete-only push detected", proc.stdout)

    def test_doctor_script_passes(self):
        proc = subprocess.run(
            [sys.executable, "scripts/doctor.py"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("All environment and repository checks passed!", proc.stdout)


if __name__ == "__main__":
    unittest.main()
