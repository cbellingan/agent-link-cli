#!/usr/bin/env python3
"""Doctor script for verifying agent-link-cli development environment and configuration."""

import os
import subprocess
import sys
from pathlib import Path


def main():
    print("🩺 ========================================================")
    print("🩺 agent-link-cli Environment Doctor")
    print("🩺 ========================================================")

    issues = 0

    # 1. Python version check (>= 3.9)
    v = sys.version_info
    if v.major >= 3 and v.minor >= 9:
        print(f"✅ Python runtime: {v.major}.{v.minor}.{v.micro} (>= 3.9 supported)")
    else:
        print(f"❌ Python runtime: {v.major}.{v.minor}.{v.micro} (Python 3.9+ required)")
        issues += 1

    # 2. Cryptography check
    try:
        import cryptography
        print(f"✅ Cryptography library installed: v{cryptography.__version__}")
    except ImportError:
        print("❌ 'cryptography' package not found. Run 'pip install cryptography'")
        issues += 1

    # 3. Git hooks check
    try:
        hooks_path = subprocess.check_output(
            ["git", "config", "--local", "--get", "core.hooksPath"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        hooks_path = ""

    if hooks_path == ".githooks":
        print("✅ Git hooks configured: core.hooksPath is .githooks")
    else:
        print(f"⚠️  Git hooks not configured (core.hooksPath is '{hooks_path or 'unset'}'). Run 'python3 scripts/install_hooks.py'")
        issues += 1

    hooks = ["pre-commit", "pre-push", "post-merge"]
    for hook in hooks:
        hp = Path(".githooks") / hook
        if hp.exists():
            if os.access(hp, os.X_OK):
                print(f"   ✓ Hook '.githooks/{hook}' is executable")
            else:
                print(f"   ⚠️  Hook '.githooks/{hook}' is missing executable permission (+x)")
                issues += 1

    # 4. Unit tests check
    if os.environ.get("AGENT_LINK_DOCTOR_RUNNING"):
        print("✅ Unit tests check skipped inside nested test invocation")
    else:
        print("🧪 Running core cryptographic unit tests...")
        env = {**os.environ, "AGENT_LINK_DOCTOR_RUNNING": "1"}
        test_res = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_crypto.py"],
            capture_output=True,
            text=True,
            env=env,
        )
        if test_res.returncode == 0:
            print("✅ Core cryptographic tests passed (all tests green)")
        else:
            print(f"❌ Unit tests failed:\n{test_res.stderr}")
            issues += 1

    print("🩺 ========================================================")
    if issues == 0:
        print("🎉 All environment and repository checks passed!")
        return 0
    else:
        print(f"⚠️  Doctor found {issues} item(s) requiring attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
