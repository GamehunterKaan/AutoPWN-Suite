# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Every way of starting the CLI or importing the library reaches the same code."""
import importlib.util
import io
import re
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

import autopwn_suite
from autopwn_suite import cli
from autopwn_suite.banners import print_banner

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


def load_launcher():
    spec = importlib.util.spec_from_file_location("autopwn_launcher", ROOT / "autopwn.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # not __main__: nothing is started
    return module


def test_the_container_entrypoint_exits_on_sigterm_because_pid_1_gets_no_default_action(monkeypatch):
    # `docker stop` sends SIGTERM to PID 1, which the kernel ignores unless the process installed a handler.
    launcher = load_launcher()
    handlers = {}
    monkeypatch.setattr(launcher, "os", SimpleNamespace(getpid=lambda: 1))
    monkeypatch.setattr(launcher, "signal", SimpleNamespace(
        SIGTERM=signal.SIGTERM, signal=lambda signum, handler: handlers.update({signum: handler})))

    launcher.exit_on_sigterm_as_pid_1()

    with pytest.raises(SystemExit) as stopped:
        handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert stopped.value.code == 128 + signal.SIGTERM


def test_any_other_process_keeps_the_default_sigterm_action(monkeypatch):
    launcher = load_launcher()
    handlers = {}
    monkeypatch.setattr(launcher, "os", SimpleNamespace(getpid=lambda: 4242))
    monkeypatch.setattr(launcher, "signal", SimpleNamespace(
        SIGTERM=signal.SIGTERM, signal=lambda signum, handler: handlers.update({signum: handler})))

    launcher.exit_on_sigterm_as_pid_1()

    assert handlers == {}


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


def _redirected_ansi_stream():
    """What Windows gives a program whose output is piped or redirected: a non-console stream in the ANSI code page."""
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_run_makes_redirected_windows_output_utf8_so_the_banner_prints(monkeypatch, stream_name):
    stream = _redirected_ansi_stream()
    monkeypatch.setattr(sys, stream_name, stream)
    monkeypatch.setattr(cli, "system", lambda: "Windows")
    monkeypatch.setattr("autopwn_suite.banners.get_terminal_width", lambda: 80)  # The narrow banner uses box-drawing characters.
    monkeypatch.setattr(cli, "main", lambda: print_banner(Console(file=getattr(sys, stream_name), color_system=None)))

    cli.run()

    stream.flush()
    assert "╔═╗" in stream.buffer.getvalue().decode("utf-8")


def test_run_leaves_the_output_encoding_alone_outside_windows(monkeypatch):
    stream = _redirected_ansi_stream()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(cli, "system", lambda: "Linux")

    with patch("autopwn_suite.cli.main"):
        cli.run()

    assert stream.encoding == "cp1252"


def test_run_leaves_a_windows_console_alone(monkeypatch):
    stream = _redirected_ansi_stream()
    stream.isatty = lambda: True
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(cli, "system", lambda: "Windows")

    with patch("autopwn_suite.cli.main"):
        cli.run()

    assert stream.encoding == "cp1252"
