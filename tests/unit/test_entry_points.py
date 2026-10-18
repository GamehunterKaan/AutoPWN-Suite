# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Every way of starting the CLI or importing the library reaches the same code."""
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import autopwn_suite
from autopwn_suite import cli

ROOT = Path(__file__).resolve().parents[2]
VERSION = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)[1]


def test_package_version_matches_pyproject():
    assert autopwn_suite.__version__ == VERSION


def test_pyproject_declares_the_console_script():
    scripts = (ROOT / "pyproject.toml").read_text(encoding="utf-8").split("[tool.poetry.scripts]", 1)[1].split("\n[", 1)[0]
    assert re.search(r'^autopwn-suite\s*=\s*"autopwn_suite\.cli:run"', scripts, re.MULTILINE)
    assert re.findall(r"^([\w-]+)\s*=", scripts, re.MULTILINE) == ["autopwn-suite"], "other scripts would land on every user's PATH"
    assert callable(cli.run)


@pytest.mark.parametrize("command", [
    [sys.executable, "-m", "autopwn_suite", "--version"],
    [sys.executable, str(ROOT / "autopwn.py"), "--version"],
])
def test_cli_launchers_report_the_package_version(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    assert f"AutoPWN Suite v{VERSION}" in result.stdout


def test_library_is_importable_from_the_package_and_the_root_shim():
    import api
    from autopwn_suite.api import AutoScanner

    assert autopwn_suite.AutoScanner is AutoScanner
    assert api.AutoScanner is AutoScanner


def test_unknown_package_attribute_is_an_attribute_error():
    with pytest.raises(AttributeError):
        autopwn_suite.NoSuchThing  # noqa: B018


def test_run_turns_ctrl_c_into_a_clean_exit():
    with patch("autopwn_suite.cli.main", side_effect=KeyboardInterrupt), pytest.raises(SystemExit, match=r"Ctrl\+C pressed"):
        cli.run()
