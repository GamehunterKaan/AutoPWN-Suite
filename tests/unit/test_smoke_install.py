# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The install smoke test used by CI and the release jobs must itself work and fail loudly."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "smoke_install.py"
VERSION = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)[1]


def smoke(version, *command):
    return subprocess.run([sys.executable, str(SCRIPT), version, *command], cwd=ROOT,
                          capture_output=True, text=True, timeout=180, check=False)


def test_source_launcher_passes_the_smoke_test():
    result = smoke(VERSION, sys.executable, "-m", "autopwn_suite")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "dashboard serves its sign-in page" in result.stdout


def test_wrong_version_fails_before_starting_anything():
    result = smoke("0.0.0", sys.executable, "-m", "autopwn_suite")
    assert result.returncode == 1
    assert "expected 'AutoPWN Suite v0.0.0'" in result.stderr
    assert "dashboard" not in result.stdout


def test_missing_arguments_print_usage():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 2
    assert "Usage:" in result.stderr
