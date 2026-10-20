# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Writable state lives in a per-user directory unless AUTOPWN_DATA_DIR says otherwise."""
from pathlib import Path

from autopwn_suite import paths
from autopwn_suite.vulnerability_db import database_path


def test_environment_variable_overrides_the_default(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    assert paths.data_dir() == tmp_path
    assert database_path() == (tmp_path / "vulnerabilities.sqlite3").resolve()


def test_empty_override_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", "")
    assert paths.data_dir() == paths.default_data_dir()


def test_linux_default_honors_an_absolute_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert paths.default_data_dir() == tmp_path / "autopwn-suite"


def test_linux_default_ignores_a_relative_xdg_data_home(monkeypatch, tmp_path):
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    assert paths.default_data_dir() == tmp_path / ".local" / "share" / "autopwn-suite"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert paths.default_data_dir() == tmp_path / ".local" / "share" / "autopwn-suite"


def test_macos_default_is_application_support(monkeypatch, tmp_path):
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert paths.default_data_dir() == tmp_path / "Library" / "Application Support" / "autopwn-suite"


def test_windows_default_is_local_app_data(monkeypatch, tmp_path):
    monkeypatch.setattr(paths.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert paths.default_data_dir() == tmp_path / "autopwn-suite"
    monkeypatch.delenv("LOCALAPPDATA")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert paths.default_data_dir() == tmp_path / "AppData" / "Local" / "autopwn-suite"


def test_importing_the_dashboard_does_not_need_a_writable_data_directory(monkeypatch, tmp_path):
    """--version and --help import the dashboard; an unwritable HOME or AUTOPWN_DATA_DIR must not break them."""
    import importlib

    import autopwn_suite.web_ui as web_ui

    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a directory is needed", encoding="utf-8")
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(blocker / "state"))
    try:
        importlib.reload(web_ui)
        assert web_ui._DATA_DIR == blocker / "state"
        assert not (blocker / "state").exists()
    finally:
        monkeypatch.undo()
        importlib.reload(web_ui)


def test_dashboard_creates_the_configured_data_directory(monkeypatch, tmp_path):
    import importlib

    target = tmp_path / "state"
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(target))
    import autopwn_suite.web_ui as web_ui

    importlib.reload(web_ui)
    assert web_ui._DATA_DIR == target
    assert target.is_dir()
