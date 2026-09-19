#!/usr/bin/env python3
"""Configures tracked git hooks (.githooks) for agent-link-cli."""

import os
import subprocess
import sys
from pathlib import Path


def main():
    print("🔧 [agent-link-cli] Installing tracked Git hooks (.githooks)...")
    try:
        current = subprocess.check_output(
            ["git", "config", "--local", "--get", "core.hooksPath"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        current = ""

    if current and current != ".githooks":
        print(f"⚠️  Existing core.hooksPath detected: '{current}'")
        print("    Integrating with .githooks...")

    subprocess.check_call(["git", "config", "--local", "core.hooksPath", ".githooks"])

    hooks_dir = Path(".githooks")
    if hooks_dir.exists():
        for hook_file in hooks_dir.iterdir():
            if hook_file.is_file():
                try:
                    hook_file.chmod(0o755)
                except Exception:
                    pass

    print("✅ Git hooks successfully configured: core.hooksPath = .githooks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
