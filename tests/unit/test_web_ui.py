# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Tests for the web UI module."""
import errno
import json
import logging
import os
import stat
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.auth_helpers import authenticated_app

# Ensure project root on path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Helpers to import web_ui with Flask available ────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_web_ui_state(tmp_path, monkeypatch):
    """Reset all web_ui module-level state between tests and point data files
    at a temp directory so tests never touch real files."""
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))

    # Force re-import so _DATA_DIR picks up the env var
    for mod_name in list(sys.modules):
        if "web_ui" in mod_name:
            del sys.modules[mod_name]

    import autopwn_suite.web_ui as wu

    # Reset global state
    wu._scans.clear()
    wu._log_history.clear()
    wu._sse_subscribers.clear()
    wu._settings = {}
    wu._profiles = {}
    wu._schedules = {}
    wu._schedule_last_run.clear()

    yield wu

    # Cleanup
    for mod_name in list(sys.modules):
        if "web_ui" in mod_name:
            del sys.modules[mod_name]


@pytest.fixture
def wu(_isolate_web_ui_state):
    return _isolate_web_ui_state


def test_webhook_disable_survives_settings_reload(app, wu, monkeypatch):
    wu._settings = wu._deep_merge(wu._DEFAULT_SETTINGS, {
        "webhook": {"enabled": True, "url": "https://example.invalid/hook", "on_error": False}})
    wu._save_settings()
    client = app.test_client()
    response = client.put("/api/settings", json={"webhook": {"enabled": False}})
    assert response.status_code == 200
    saved = json.loads(wu._SETTINGS_FILE.read_text())
    assert saved["webhook"]["enabled"] is False
    assert saved["webhook"]["url"] == "https://example.invalid/hook"
    assert saved["webhook"]["on_error"] is False
    wu._settings.clear()
    wu._load_settings()
    assert client.get("/api/settings").get_json()["webhook"]["enabled"] is False
    post = Mock()
    monkeypatch.setattr(wu._requests, "post", post)
    assert client.post("/api/settings/test_webhook").status_code == 400
    post.assert_not_called()


@pytest.fixture
def app(wu):
    """Create a Flask test app."""
    # Ensure Flask globals are available in the re-imported module
    from flask import Flask, Response, jsonify, request, send_from_directory
    wu.Flask = Flask
    wu.Response = Response
    wu.jsonify = jsonify
    wu.request = request
    wu.send_from_directory = send_from_directory
    wu.FLASK_AVAILABLE = True

    wu._load_settings()
    static_dir = Path(__file__).parent.parent.parent / "autopwn_suite" / "web_ui_static"
    wu.__version__ = "test"
    flask_app = authenticated_app(wu, static_dir)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


# ═══════════════════════════════════════════════════════════════════════════════
# Input validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateTarget:
    def test_empty_target(self, wu):
        assert wu._validate_target("") == "'target' is required"

    def test_valid_ip(self, wu):
        assert wu._validate_target("192.168.1.1") is None

    def test_valid_cidr(self, wu):
        assert wu._validate_target("192.168.1.0/24") is None

    def test_valid_hostname(self, wu):
        assert wu._validate_target("example.com") is None

    def test_valid_range(self, wu):
        assert wu._validate_target("192.168.1.1, 192.168.1.2") is None

    def test_shell_injection_semicolon(self, wu):
        assert wu._validate_target("192.168.1.1; rm -rf /") is not None

    def test_shell_injection_pipe(self, wu):
        assert wu._validate_target("192.168.1.1 | cat /etc/passwd") is not None

    def test_shell_injection_backtick(self, wu):
        assert wu._validate_target("`whoami`") is not None

    def test_shell_injection_dollar(self, wu):
        assert wu._validate_target("$(whoami)") is not None


class TestStructuredNmapSettings:
    """The dashboard has no free-text Nmap options; it builds the arguments from structured fields it checks itself."""

    @pytest.mark.parametrize("ports", [
        "", "   ", "80", "22,80,443", "1-1000", "22,80,1-1000", "1-65535", "65535", "1,2,3,4,5", "80-80", "  22,80  ", "80\n", "\t80,443\n"])
    def test_a_port_specification_of_numbers_ranges_and_lists_is_accepted(self, wu, ports):
        assert wu._profile_config({"ports": ports})["ports"] == ports.strip()

    @pytest.mark.parametrize("ports", [
        "0", "65536", "99999", "100000", "1-65536", "0-10", "80-22", "-", "-p", "-80", "80-", "-80-90", "80--90", "1-2-3",
        ",80", "80,", "80,,443", "22, 80", "22 80", "80\t443", "80\n443", "T:80", "U:53", "T:80,U:53", "http",
        "80;id", "80|id", "80`id`", "$(id)", "80 -oN /etc/cron.d/x", "80 --script=x", "--script=banner", "-oN x", "-sV",
        "080", chr(0x668) + chr(0x660), chr(0xFF18) + chr(0xFF10), "80.5", "+80", "1e3", "0x50", "80/tcp", "*", "?", pytest.param("9" * 40, id="40-digits"), pytest.param(",".join(["80"] * 800), id="800-ports"),
        pytest.param("1-" + "9" * 60, id="range-of-60-digits")])
    def test_anything_else_in_the_ports_field_is_refused(self, wu, ports):
        with pytest.raises(ValueError, match="'ports'"):
            wu._profile_config({"ports": ports})

    @pytest.mark.parametrize("technique", ["", "-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX"])
    def test_every_technique_the_forms_offer_is_accepted(self, wu, technique):
        assert wu._profile_config({"scan_technique": technique})["scan_technique"] == technique

    def test_the_allowlist_is_exactly_what_the_forms_offer(self, wu):
        import re
        html = (PROJECT_ROOT / "autopwn_suite" / "web_ui_static" / "index.html").read_text(encoding="utf-8")
        for select in ("f-scantech", "pf-scantech"):
            block = re.search(rf'<select id="{select}".*?</select>', html, re.S).group(0)
            assert sorted(re.findall(r'<option value="(-s[A-Za-z])"', block)) == sorted(t for t in wu._SCAN_TECHNIQUES if t)

    @pytest.mark.parametrize("technique", [
        "-sV", "-sC", "-sL", "-sn", "-sI", "-sO", "-sY", "-sZ", "-ss", "sS", "-s", "-sS ", " -sS", "-sS -sV", "-sS\n", "-sSS",
        "--script=banner", "--script", "-oN /etc/cron.d/x", "-oN", "-iL", "-p 22", "-O", "-A", "-Pn", "-T5", "--version-intensity 9",
        "-sS;id", "$(id)", "-sS\u0000", chr(0x2212) + "sS", chr(0x2011) + "sS", "-" + chr(0x455) + "S", pytest.param("x" * 5000, id="5000-characters")])
    def test_a_technique_the_forms_do_not_offer_is_refused(self, wu, technique):
        with pytest.raises(ValueError, match="'scan_technique'"):
            wu._profile_config({"scan_technique": technique})

    @pytest.mark.parametrize("field,value", [("scan_technique", 5), ("scan_technique", None), ("scan_technique", ["-sS"]),
                                             ("ports", 80), ("ports", None), ("ports", [80]), ("ports", {"a": 1}),
                                             ("nmap_flags", None), ("nmap_flags", 0), ("nmap_flags", ["-sV"]),
                                             ("nmap_flags", {"a": 1}), ("nmap_flags", True)])
    def test_structured_fields_must_be_strings(self, wu, field, value):
        with pytest.raises(ValueError, match="must be a string"):
            wu._profile_config({field: value})

    @pytest.mark.parametrize("flags", ["", " ", "\t", " \n "])
    def test_an_empty_nmap_flags_stays_fine_and_is_stored_empty(self, wu, flags):
        assert wu._profile_config({"nmap_flags": flags})["nmap_flags"] == ""
        assert wu._profile_config({})["nmap_flags"] == ""

    @pytest.mark.parametrize("flags", [
        "-sS", "-p 80", "-oN /etc/cron.d/x", "-oN", "--oX out.xml", "-iL /etc/shadow", "--script=banner", "--script banner",
        "--script-args=a=b", "--script-args-file=x", "--excludefile hosts", "--datadir /tmp/x", "-6o out", "-A", "-T5",
        "--version-intensity 3", "--max-retries 2", "x", "-", "--", " -sS ", "-sS; rm -rf /", "-sV | cat /etc/passwd", "$(id)",
        "\xe9", chr(0x202E) + "-sS", pytest.param("-sS " * 500, id="repeated-technique"),
        pytest.param("A" * 100000, id="100000-characters")])
    def test_any_nmap_flags_text_is_refused_with_the_fixed_message(self, wu, flags):
        with pytest.raises(wu._OptionsRefused) as refused:
            wu._profile_config({"nmap_flags": flags})
        assert str(refused.value) == wu._NMAP_OPTIONS_REFUSED
        assert isinstance(refused.value, ValueError)

    def test_options_are_refused_whichever_source_carries_them(self, wu):
        with pytest.raises(wu._OptionsRefused):
            wu._profile_config({}, {"nmap_flags": "-sV --script banner"})  # as stored by an earlier release
        with pytest.raises(wu._OptionsRefused):
            wu._profile_config({"nmap_flags": "-sV"}, {"nmap_flags": ""})

    def test_options_are_refused_even_when_another_field_is_invalid_too(self, wu):
        with pytest.raises(wu._OptionsRefused):
            wu._profile_config({"nmap_flags": "-sV", "mode": "bad", "speed": 99})

    def test_a_profile_cannot_smuggle_options_through_the_structured_fields(self, wu):
        for field in ("scan_technique", "ports"):
            for value in ("-oN /etc/cron.d/x", "--script=http-fetch", "-sS --script banner", "-sS -oN x", "22 -oN x", "22,-oN"):
                with pytest.raises(ValueError):
                    wu._profile_config({field: value})

    @pytest.mark.parametrize("target", ["-oN", "-oN /etc/cron.d/x", "192.0.2.1 -oN", "192.0.2.1 --script=x", "192.0.2.1,-sS",
                                        "-iL hosts", "--excludefile=x", "  -sS", "192.0.2.1  -A", "192.0.2.1,\t-A"])
    def test_a_target_that_starts_an_nmap_option_is_refused(self, wu, target):
        assert wu._validate_target(target) is not None

    @pytest.mark.parametrize("target", ["192.0.2.1", "192.0.2.0/24", "192.0.2.1-20", "192.0.2.1 192.0.2.2", "192.0.2.1, 192.0.2.2",
                                        "host-1.example.test", "2001:db8::1", "a-b"])
    def test_ordinary_targets_with_dashes_inside_stay_accepted(self, wu, target):
        assert wu._validate_target(target) is None


# ═══════════════════════════════════════════════════════════════════════════════
# Deep merge
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeepMerge:
    def test_flat_merge(self, wu):
        result = wu._deep_merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}

    def test_override(self, wu):
        result = wu._deep_merge({"a": 1}, {"a": 2})
        assert result == {"a": 2}

    def test_nested_merge(self, wu):
        base = {"x": {"a": 1, "b": 2}}
        override = {"x": {"b": 3, "c": 4}}
        result = wu._deep_merge(base, override)
        assert result == {"x": {"a": 1, "b": 3, "c": 4}}

    def test_base_unchanged(self, wu):
        base = {"a": 1}
        wu._deep_merge(base, {"a": 2})
        assert base == {"a": 1}


# ═══════════════════════════════════════════════════════════════════════════════
# Settings persistence
# ═══════════════════════════════════════════════════════════════════════════════

class TestSettings:
    def test_load_creates_defaults(self, wu):
        wu._load_settings()
        assert wu._settings.get("email") is not None
        assert wu._settings.get("webhook") is not None

    def test_save_and_reload(self, wu):
        wu._load_settings()
        wu._settings["nist_api_key"] = "test-key-123"
        wu._save_settings()
        wu._settings = {}
        wu._load_settings()
        assert wu._settings["nist_api_key"] == "test-key-123"

    def test_get_setting_nested(self, wu):
        wu._load_settings()
        assert wu._get_setting("email", "enabled") is False

    def test_get_setting_missing(self, wu):
        wu._load_settings()
        result = wu._get_setting("nonexistent", "key")
        assert not result  # empty dict or None for missing keys

    def test_persisted_files_are_created_owner_only(self, wu, monkeypatch):
        """Settings hold the SMTP password, NVD key and webhook URL; an existing data directory may be 0755."""
        modes = []
        real_open = wu.os.open

        def recording_open(path, flags, mode=0o777, **kwargs):
            modes.append(mode)
            return real_open(path, flags, mode, **kwargs)

        monkeypatch.setattr(wu.os, "open", recording_open)
        previous = wu.os.umask(0o022)
        try:
            wu._load_settings()  # writes the defaults
            wu._save_profiles()
            wu._save_schedules()
        finally:
            wu.os.umask(previous)
        assert len(modes) == 3 and set(modes) == {0o600}
        if wu.os.name != "nt":
            for path in (wu._SETTINGS_FILE, wu._PROFILES_FILE, wu._SCHEDULES_FILE):
                assert path.stat().st_mode & 0o777 == 0o600


# ═══════════════════════════════════════════════════════════════════════════════
# Files an earlier release wrote with the process umask (AUTOPWN-SA-2026-007)
# ═══════════════════════════════════════════════════════════════════════════════

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def _warnings(caplog):
    return [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]


class TestExistingDataFilesAreRestricted:
    """Before 2.7.0 the settings, profiles, schedules and account files were created with the process umask (usually
    0644) and kept that mode until the next save, which for the settings is only when settings change."""

    @staticmethod
    def _plant(wu, mode):
        paths = [wu._SETTINGS_FILE, wu._PROFILES_FILE, wu._SCHEDULES_FILE, wu._DATA_DIR / wu.ACCOUNT_FILE]
        for path in paths:
            path.write_text('{"synthetic": "content"}', encoding="utf-8")
            path.chmod(mode)
        return paths

    @staticmethod
    def _age(path, seconds):
        stamp = time.time() - seconds
        os.utime(path, (stamp, stamp))

    @POSIX_ONLY
    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660, 0o664, 0o755])
    def test_a_file_that_group_or_others_can_access_becomes_owner_only(self, wu, caplog, mode):
        paths = self._plant(wu, mode)

        wu._tighten_data_files()

        for path in paths:
            assert _mode(path) == 0o600
            assert path.read_text(encoding="utf-8") == '{"synthetic": "content"}'
        message, = _warnings(caplog)  # one line for all four files, fixed text
        assert "0600" in message and str(wu._DATA_DIR) not in message and wu._SETTINGS_FILE.name not in message

    @POSIX_ONLY
    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o700])
    def test_an_owner_only_file_is_not_touched_or_reported(self, wu, caplog, mode):
        paths = self._plant(wu, mode)

        with patch.object(wu.os, "fchmod", wraps=wu.os.fchmod) as fchmod:
            wu._tighten_data_files()

        fchmod.assert_not_called()
        assert [_mode(path) for path in paths] == [mode] * 4
        assert _warnings(caplog) == []

    @POSIX_ONLY
    def test_a_missing_file_or_data_directory_is_not_an_error(self, wu, caplog, tmp_path):
        wu._tighten_data_files()
        wu._DATA_DIR = tmp_path / "does-not-exist"
        wu._tighten_data_files()
        assert _warnings(caplog) == []

    @POSIX_ONLY
    def test_files_that_hold_neither_secrets_nor_targets_are_left_alone(self, wu):
        other = wu._DATA_DIR / "vulnerability_database.sqlite"
        notes = wu._DATA_DIR / ".web_ui_notes.txt"
        for path in (other, notes):
            path.write_text("x", encoding="utf-8")
            path.chmod(0o644)

        wu._tighten_data_files()

        assert [_mode(other), _mode(notes)] == [0o644, 0o644]

    @POSIX_ONLY
    def test_the_leftover_of_an_interrupted_save_is_removed_when_it_is_old_and_restricted_when_it_may_be_running(self, wu, caplog):
        old_settings = wu._DATA_DIR / f".{wu._SETTINGS_FILE.name}.{'a' * 32}.tmp"
        old_account = wu._DATA_DIR / f".{wu.ACCOUNT_FILE}.{'b' * 32}.tmp"
        running = wu._DATA_DIR / f".{wu._PROFILES_FILE.name}.{'c' * 32}.tmp"
        unrelated = wu._DATA_DIR / f".other.json.{'d' * 32}.tmp"
        for path, mode in ((old_settings, 0o644), (old_account, 0o600), (running, 0o644), (unrelated, 0o644)):
            path.write_text("{}", encoding="utf-8")
            path.chmod(mode)
        for path in (old_settings, old_account, unrelated):
            self._age(path, 3600)

        wu._tighten_data_files()

        assert not old_settings.exists() and not old_account.exists()  # nothing is writing to them any more
        assert _mode(running) == 0o600  # a save in another process may still be about to rename it
        assert _mode(unrelated) == 0o644
        assert len(_warnings(caplog)) == 1

    @POSIX_ONLY
    def test_removing_an_old_owner_only_leftover_is_not_reported_as_a_fix(self, wu, caplog):
        leftover = wu._DATA_DIR / f".{wu._SETTINGS_FILE.name}.{'a' * 32}.tmp"
        leftover.write_text("{}", encoding="utf-8")
        leftover.chmod(0o600)
        self._age(leftover, 3600)

        wu._tighten_data_files()

        assert not leftover.exists() and _warnings(caplog) == []

    @POSIX_ONLY
    def test_a_chmod_that_fails_never_stops_startup_and_is_logged_once_with_fixed_text(self, wu, caplog):
        paths = self._plant(wu, 0o644)

        with patch.object(wu.os, "fchmod", side_effect=PermissionError(f"secret detail about {wu._DATA_DIR}")):
            wu._tighten_data_files()  # read-only file system, or a file that another account owns

        assert [_mode(path) for path in paths] == [0o644] * 4
        message, = _warnings(caplog)
        assert "Could not restrict" in message and "secret detail" not in message and str(wu._DATA_DIR) not in message
        assert "secret detail" not in caplog.text

    @POSIX_ONLY
    def test_one_file_that_cannot_be_restricted_does_not_leave_the_others_exposed(self, wu, caplog):
        paths = self._plant(wu, 0o644)
        real_fchmod = os.fchmod
        calls = []

        def fails_first(descriptor, mode):
            calls.append(mode)
            if len(calls) == 1:
                raise OSError("read-only file system")
            return real_fchmod(descriptor, mode)

        with patch.object(wu.os, "fchmod", fails_first):
            wu._tighten_data_files()

        assert sorted(_mode(path) for path in paths) == [0o600] * 3 + [0o644]
        assert len(_warnings(caplog)) == 2  # what was restricted, and that something could not be

    @POSIX_ONLY
    def test_a_symlink_is_not_followed(self, wu, caplog, tmp_path):
        outside = tmp_path / "outside" / "shared.json"
        outside.parent.mkdir()
        outside.write_text("{}", encoding="utf-8")
        outside.chmod(0o644)
        wu._SETTINGS_FILE.symlink_to(outside)

        wu._tighten_data_files()

        assert _mode(outside) == 0o644  # the target is not the dashboard's to change
        assert _warnings(caplog) == []

    @POSIX_ONLY
    @pytest.mark.parametrize("kind", ["directory", "fifo"])
    def test_what_is_not_a_regular_file_is_skipped(self, wu, caplog, kind):
        if kind == "directory":
            wu._SETTINGS_FILE.mkdir(mode=0o755)
            wu._SETTINGS_FILE.chmod(0o755)
        else:
            os.mkfifo(wu._SETTINGS_FILE, 0o644)  # opening it must not block

        wu._tighten_data_files()

        assert _mode(wu._SETTINGS_FILE) == (0o755 if kind == "directory" else 0o644)
        assert _warnings(caplog) == []

    @pytest.mark.skipif(os.name != "nt", reason="the Windows no-op")
    def test_windows_has_no_posix_modes_so_nothing_is_touched(self, wu, caplog):
        self._plant(wu, 0o644)
        with patch.object(wu.os, "open", side_effect=AssertionError("must not open anything")):
            wu._tighten_data_files()
        assert _warnings(caplog) == []

    def test_the_file_is_restricted_through_its_descriptor_without_following_symlinks(self, wu):
        from types import SimpleNamespace
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_mtime=time.time())
        with patch.object(wu.os, "open", return_value=7) as opened, patch.object(wu.os, "fstat", return_value=info), \
                patch.object(wu.os, "fchmod", create=True) as fchmod, patch.object(wu.os, "close") as close:
            assert wu._owner_only(Path("settings.json")) is True

        (path, flags), _ = opened.call_args
        assert path == Path("settings.json") and flags & os.O_RDONLY == os.O_RDONLY
        assert flags & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)
        fchmod.assert_called_once_with(7, 0o600)
        close.assert_called_once_with(7)

    @pytest.mark.parametrize("mode, kind", [(0o600, stat.S_IFREG), (0o400, stat.S_IFREG), (0o755, stat.S_IFDIR), (0o644, stat.S_IFIFO)])
    def test_an_owner_only_file_or_one_that_is_not_a_regular_file_is_left_alone(self, wu, mode, kind):
        from types import SimpleNamespace
        info = SimpleNamespace(st_mode=kind | mode, st_mtime=time.time())
        with patch.object(wu.os, "open", return_value=7), patch.object(wu.os, "fstat", return_value=info), \
                patch.object(wu.os, "fchmod", create=True) as fchmod, patch.object(wu.os, "close") as close:
            assert wu._owner_only(Path("settings.json")) is False

        fchmod.assert_not_called()
        close.assert_called_once_with(7)

    def test_a_missing_file_and_a_symlink_are_skipped_and_any_other_failure_is_raised(self, wu):
        for error, skipped in ((FileNotFoundError(), True), (OSError(errno.ELOOP, "too many levels of symbolic links"), True),
                               (PermissionError(errno.EACCES, "denied"), False)):
            with patch.object(wu.os, "open", side_effect=error):
                if skipped:
                    assert wu._owner_only(Path("settings.json")) is False
                else:
                    with pytest.raises(OSError):
                        wu._owner_only(Path("settings.json"))

    def test_an_old_temporary_file_is_deleted_a_young_one_is_not(self, wu):
        from types import SimpleNamespace
        for age, deleted in ((3600, True), (1, False)):
            info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_mtime=time.time() - age)
            with patch.object(wu.os, "open", return_value=7), patch.object(wu.os, "fstat", return_value=info), \
                    patch.object(wu.os, "fchmod", create=True) as fchmod, patch.object(wu.os, "unlink") as unlink, \
                    patch.object(wu.os, "close"):
                assert wu._owner_only(Path(".x.json.tmp"), discard_after=60) is True
            assert unlink.called is deleted and fchmod.called is not deleted

    def test_start_server_restricts_the_files_before_it_loads_them(self, wu, monkeypatch):
        order = []
        for name in ("_tighten_data_files", "_load_settings", "_load_profiles", "_load_schedules"):
            monkeypatch.setattr(wu, name, lambda name=name: order.append(name))

        class Stop(Exception):
            pass

        def stop(*args, **kwargs):
            raise Stop

        monkeypatch.setattr(wu, "_build_app", stop)
        with pytest.raises(Stop):
            wu.start_server(port=0)

        assert order == ["_tighten_data_files", "_load_settings", "_load_profiles", "_load_schedules"]

    @POSIX_ONLY
    @pytest.mark.parametrize("failing_chmod", [False, True])
    def test_the_dashboard_starts_with_old_files_restricted_and_also_when_that_fails(self, wu, monkeypatch, failing_chmod):
        from types import SimpleNamespace
        paths = [wu._SETTINGS_FILE, wu._PROFILES_FILE, wu._SCHEDULES_FILE]
        for path, content in zip(paths, ({"nist_api_key": "synthetic-key"}, {}, {}), strict=True):
            path.write_text(json.dumps(content), encoding="utf-8")
            path.chmod(0o644)
        served = {}

        def make_server(host, port, application, *args, **kwargs):
            served["application"] = application
            return SimpleNamespace(socket=SimpleNamespace(set_inheritable=lambda value: None), fileno=lambda: 0,
                                   log_startup=lambda: None, serve_forever=lambda: None)

        monkeypatch.setenv("WERKZEUG_SERVER_FD", "0")  # run_simple exports it; the monkeypatch restores it
        monkeypatch.setattr("werkzeug.serving.make_server", make_server)
        monkeypatch.setattr(wu, "_scheduler_loop", lambda: None)
        if failing_chmod:
            monkeypatch.setattr(wu.os, "fchmod", MagicMock(side_effect=PermissionError("not the owner")))

        wu.start_server(port=0)

        assert "application" in served
        assert wu._settings["nist_api_key"] == "synthetic-key"  # the file was still loaded
        assert {_mode(path) for path in paths} == ({0o644} if failing_chmod else {0o600})

    def test_a_copy_kept_of_an_unreadable_file_is_created_owner_only(self, wu, monkeypatch):
        """The profiles and schedules hold scan targets; the kept copy used to be created with the process umask."""
        original = json.dumps({"a": {"id": "a"}, "b": "not an object"})
        wu._PROFILES_FILE.write_text(original, encoding="utf-8")
        wu._PROFILES_FILE.chmod(0o644)
        real_open, modes = wu.os.open, []

        def recording_open(path, flags, mode=0o777, **kwargs):
            if ".corrupt-" in str(path):
                modes.append(mode)
            return real_open(path, flags, mode, **kwargs)

        monkeypatch.setattr(wu.os, "open", recording_open)
        previous = wu.os.umask(0o022)
        try:
            wu._load_profiles()
        finally:
            wu.os.umask(previous)

        kept, = wu._PROFILES_FILE.parent.glob(wu._PROFILES_FILE.name + ".corrupt-*")
        assert modes == [0o600] and kept.read_text(encoding="utf-8") == original
        if os.name != "nt":
            assert _mode(kept) == 0o600

    @POSIX_ONLY
    @pytest.mark.parametrize("restrict_first", [True, False])
    def test_a_file_moved_aside_keeps_the_mode_it_had(self, wu, restrict_first):
        """A rename keeps the original's mode: owner-only once the start-up restriction ran, otherwise what it was
        (docs/THREAT_MODEL.md, "Set-aside copies of unreadable files")."""
        for path in (wu._PROFILES_FILE, wu._SCHEDULES_FILE):
            path.write_text("{not json", encoding="utf-8")  # cannot be loaded, so it is moved, not copied
            path.chmod(0o644)
        if restrict_first:
            wu._tighten_data_files()

        wu._load_profiles()
        wu._load_schedules()

        for name in (wu._PROFILES_FILE.name, wu._SCHEDULES_FILE.name):
            kept, = wu._DATA_DIR.glob(name + ".corrupt-*")
            assert _mode(kept) == (0o600 if restrict_first else 0o644)


# ═══════════════════════════════════════════════════════════════════════════════
# Profiles persistence
# ═══════════════════════════════════════════════════════════════════════════════

class TestProfiles:
    def test_load_empty(self, wu):
        wu._load_profiles()
        assert wu._profiles == {}

    def test_save_and_reload(self, wu, tmp_path):
        wu._load_profiles()
        wu._profiles["p1"] = {"id": "p1", "name": "Test", "config": {"speed": 3}}
        wu._save_profiles()
        wu._profiles = {}
        wu._load_profiles()
        assert wu._profiles["p1"]["name"] == "Test"


# ═══════════════════════════════════════════════════════════════════════════════
# Schedules persistence
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchedules:
    def test_load_empty(self, wu):
        wu._load_schedules()
        assert wu._schedules == {}

    def test_save_and_reload(self, wu):
        wu._load_schedules()
        wu._schedules["s1"] = {
            "id": "s1", "name": "Daily",
            "last_run": "2025-01-01T00:00:00Z",
        }
        wu._save_schedules()
        wu._schedules = {}
        wu._schedule_last_run.clear()
        wu._load_schedules()
        assert wu._schedules["s1"]["name"] == "Daily"
        assert "s1" in wu._schedule_last_run

    def test_load_invalid_last_run(self, wu):
        wu._load_schedules()
        wu._schedules["s2"] = {"id": "s2", "last_run": "not-a-date"}
        wu._save_schedules()
        wu._schedules = {}
        wu._schedule_last_run.clear()
        wu._load_schedules()
        assert "s2" not in wu._schedule_last_run

    @pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"])
    def test_time_that_does_not_fit_utc_is_ignored_not_fatal(self, wu, stamp):
        # Converting these to UTC leaves the range datetime supports (OverflowError, not ValueError).
        assert wu._parse_utc(stamp) is None
        wu._SCHEDULES_FILE.write_text(json.dumps({
            "s1": {"id": "s1", "name": "Kept", "type": "daily", "last_run": stamp, "created_at": stamp}}), encoding="utf-8")
        wu._load_schedules()
        assert wu._schedules["s1"]["name"] == "Kept" and "s1" not in wu._schedule_last_run
        assert not list(wu._SCHEDULES_FILE.parent.glob("*.corrupt-*"))
        # The scheduler's check treats it as no creation time rather than raising every minute.
        assert isinstance(wu._should_fire({"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00",
                                           "created_at": stamp}), bool)


# ═══════════════════════════════════════════════════════════════════════════════
# ScanJob
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanJob:
    def test_create(self, wu):
        job = wu.ScanJob("id1", "192.168.1.1", {"target": "192.168.1.1"})
        assert job.status == "running"
        assert job.target == "192.168.1.1"

    def test_mark_done(self, wu):
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        assert job.status == "completed"
        assert job.finished_at != ""

    @pytest.mark.parametrize("status", ["completed", "partial", "stopped"])
    def test_only_a_completed_job_releases_its_resume_data(self, wu, status):
        job = wu.ScanJob("id1", "target", {})
        job._network_results["192.0.2.1"] = object()
        job._lookup_results[("192.0.2.1", 80, "tcp", "nginx 1")] = []
        job._web_checkpoints[("192.0.2.1", "http://192.0.2.1/")] = {"crawl": {}}
        job._targets = ["192.0.2.1"]
        job.mark_done(status)
        remaining = (len(job._network_results), len(job._lookup_results), len(job._web_checkpoints), job._targets)
        assert remaining == ((0, 0, 0, None) if status == "completed" else (1, 1, 1, ["192.0.2.1"]))
        assert job.to_dict()["can_resume"] is (status != "completed")

    def test_mark_error(self, wu):
        job = wu.ScanJob("id1", "target", {})
        job.mark_error("something failed")
        assert job.status == "error"
        assert job.error == "something failed"

    def test_stop_flag(self, wu):
        job = wu.ScanJob("id1", "target", {})
        assert not job.should_stop()
        job.request_stop()
        assert job.should_stop()
        assert job.status == "stopping"

    def test_get_or_create_host(self, wu):
        job = wu.ScanJob("id1", "target", {})
        h = job.get_or_create_host("192.168.1.1")
        assert h["ip"] == "192.168.1.1"
        # Same object returned on second call
        h2 = job.get_or_create_host("192.168.1.1")
        assert h is h2

    def test_mark_host_done(self, wu):
        job = wu.ScanJob("id1", "target", {})
        job.get_or_create_host("192.168.1.1")
        job.mark_host_done("192.168.1.1")
        hosts = job.hosts_list()
        assert hosts[0]["scan_status"] == "completed"

    def test_hosts_list(self, wu):
        job = wu.ScanJob("id1", "target", {})
        job.get_or_create_host("10.0.0.1")
        job.get_or_create_host("10.0.0.2")
        assert len(job.hosts_list()) == 2

    def test_to_dict(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "target"})
        job.get_or_create_host("10.0.0.1")
        d = job.to_dict()
        assert d["id"] == "id1"
        assert d["host_count"] == 1
        assert d["port_count"] == 0
        assert d["vuln_count"] == 0

    def test_to_dict_copies_the_config_while_holding_the_job_lock(self, wu):
        """The scan thread adds config keys under the lock; iterating them outside raised during /api/scans."""
        import threading
        held = []

        def held_by_this_thread():
            """Another thread cannot take the lock exactly when the calling thread holds it."""
            answer = []

            def probe():
                free = job._lock.acquire(blocking=False)
                if free:
                    job._lock.release()
                answer.append(not free)

            thread = threading.Thread(target=probe)
            thread.start()
            thread.join()
            return answer[0]

        class Config(dict):
            def items(self):
                held.append(held_by_this_thread())
                return super().items()

        job = wu.ScanJob("id1", "target", Config(target="target", api_key="secret"))
        assert job.to_dict()["config"] == {"target": "target"}
        assert held and all(held)

    def test_to_full_dict(self, wu):
        job = wu.ScanJob("id1", "target", {})
        h = job.get_or_create_host("10.0.0.1")
        h["ports"] = [{"port": 80, "service": "http", "product": "nginx", "version": "1.0"}]
        h["vulns"] = [{"cve": "CVE-2024-0001", "port": 80, "severity": "high"}]
        d = job.to_full_dict()
        assert len(d["hosts"]) == 1
        assert len(d["hosts"][0]["ports"]) == 1
        assert len(d["hosts"][0]["ports"][0]["vulnerabilities"]) == 1

    def test_to_full_dict_unmapped_vulns(self, wu):
        job = wu.ScanJob("id1", "target", {})
        h = job.get_or_create_host("10.0.0.1")
        h["ports"] = [{"port": 80, "service": "http", "product": "nginx", "version": "1.0"}]
        h["vulns"] = [{"cve": "CVE-2024-0001", "port": 443, "severity": "high"}]
        d = job.to_full_dict()
        assert "unmapped_vulnerabilities" in d["hosts"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# Global scan registry
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanRegistry:
    def test_register_and_get(self, wu):
        job = wu.ScanJob("id1", "target", {})
        wu._register_scan(job)
        assert wu._get_scan("id1") is job

    def test_get_missing(self, wu):
        assert wu._get_scan("nonexistent") is None

    def test_all_scans(self, wu):
        wu._register_scan(wu.ScanJob("a", "t", {}))
        wu._register_scan(wu.ScanJob("b", "t", {}))
        assert len(wu._all_scans()) == 2

    def test_prune_old_completed(self, wu):
        # Register more than _MAX_COMPLETED_SCANS completed scans
        for i in range(wu._MAX_COMPLETED_SCANS + 5):
            j = wu.ScanJob(f"id{i}", "t", {})
            j.mark_done()
            wu._register_scan(j)
        completed = [s for s in wu._all_scans() if s.status == "completed"]
        assert len(completed) <= wu._MAX_COMPLETED_SCANS


# ═══════════════════════════════════════════════════════════════════════════════
# Broadcast / SSE
# ═══════════════════════════════════════════════════════════════════════════════

class TestBroadcast:
    def test_broadcast_adds_to_history(self, wu):
        wu._broadcast({"msg": "test"})
        assert len(wu._log_history) == 1

    def test_broadcast_trims_history(self, wu):
        for i in range(wu._MAX_LOG_HISTORY + 100):
            wu._broadcast({"msg": f"msg{i}"})
        assert len(wu._log_history) <= wu._MAX_LOG_HISTORY

    def test_broadcast_to_subscribers(self, wu):
        import queue
        q = queue.Queue()
        wu._sse_subscribers.append(q)
        wu._broadcast({"msg": "hello"})
        assert q.get_nowait()["msg"] == "hello"

    def test_history_entries_get_consecutive_ids_and_progress_events_get_none(self, wu):
        import queue
        q = queue.Queue()
        wu._sse_subscribers.append(q)
        wu._broadcast({"msg": "a"})
        wu._broadcast({"level": "__scan_progress__", "msg": ""})
        wu._broadcast({"msg": "b"})
        first, progress, second = (q.get_nowait() for _ in range(3))
        assert "id" not in progress and not any(entry.get("level") == "__scan_progress__" for entry in wu._log_history)
        assert second["id"] == first["id"] + 1
        assert wu._log_history == [first, second]

    def test_the_caller_keeps_its_own_event_unchanged(self, wu):
        event = {"scan_id": "s", "level": "info", "msg": "m"}
        wu._broadcast(event)
        assert event == {"scan_id": "s", "level": "info", "msg": "m"}

    def test_ids_stay_unique_and_increasing_while_the_history_is_trimmed(self, wu):
        for number in range(wu._MAX_LOG_HISTORY + 25):
            wu._broadcast({"msg": str(number)})
        ids = [entry["id"] for entry in wu._log_history]
        assert len(ids) == wu._MAX_LOG_HISTORY
        assert ids == list(range(ids[0], ids[0] + len(ids)))

    def test_ids_of_a_restarted_dashboard_are_higher_than_any_issued_before(self, wu, monkeypatch):
        import importlib

        def start_at(microseconds):
            monkeypatch.setattr("time.time_ns", lambda: microseconds * 1000)
            sys.modules.pop("autopwn_suite.web_ui", None)
            return importlib.import_module("autopwn_suite.web_ui")

        first = start_at(1_800_000_000_000_000)
        for _ in range(3):
            first._broadcast({"msg": "before the restart"})
        restarted = start_at(1_800_000_060_000_000)
        restarted._broadcast({"msg": "after the restart"})
        assert restarted._log_history[-1]["id"] > first._log_history[-1]["id"]


# ═══════════════════════════════════════════════════════════════════════════════
# WebLogger / NullConsole
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebLogger:
    def test_logger_broadcasts(self, wu):
        logger = wu.WebLogger("scan1")
        logger.logger("info", "test message")
        assert len(wu._log_history) == 1
        assert wu._log_history[0]["msg"] == "test message"
        assert wu._log_history[0]["scan_id"] == "scan1"

    def test_logger_level_mapping(self, wu):
        logger = wu.WebLogger("scan1")
        logger.logger("error", "err")
        assert wu._log_history[0]["level"] == "error"

    def test_logger_unknown_level(self, wu):
        logger = wu.WebLogger("scan1")
        logger.logger("unknown_level", "msg")
        assert wu._log_history[0]["level"] == "info"


class TestNullConsole:
    def test_print_noop(self, wu):
        nc = wu.NullConsole()
        nc.print("anything")  # should not raise

    def test_status_context(self, wu):
        nc = wu.NullConsole()
        with nc.status("test"):
            pass  # should not raise


# ═══════════════════════════════════════════════════════════════════════════════
# Build nmap flags
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildNmapFlags:
    def test_empty_config(self, wu):
        assert wu._build_nmap_flags({}) == ""

    def test_scan_technique(self, wu):
        result = wu._build_nmap_flags({"scan_technique": "-sU"})
        assert "-sU" in result

    def test_ports(self, wu):
        result = wu._build_nmap_flags({"ports": "1-1000"})
        assert "-p 1-1000" in result

    def test_version_intensity(self, wu):
        result = wu._build_nmap_flags({"version_intensity": 5})
        assert "--version-intensity 5" in result

    def test_os_detection(self, wu):
        result = wu._build_nmap_flags({"os_detection": True})
        assert "-O" in result

    def test_free_text_flags_are_never_added(self, wu):
        assert wu._build_nmap_flags({"nmap_flags": "--script banner"}) == ""

    def test_all_combined(self, wu):
        result = wu._build_nmap_flags({
            "scan_technique": "-sW",
            "ports": "80-443",
            "version_intensity": 3,
            "os_detection": True,
        })
        assert result == "-sW -p 80-443 --version-intensity 3 -O"


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduler helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseIntervalMinutes:
    def test_minutes(self, wu):
        assert wu._parse_interval_minutes({"type": "interval", "interval_unit": "minutes", "interval_value": 30}) == 30

    def test_hours(self, wu):
        assert wu._parse_interval_minutes({"type": "interval", "interval_unit": "hours", "interval_value": 2}) == 120

    def test_days(self, wu):
        assert wu._parse_interval_minutes({"type": "interval", "interval_unit": "days", "interval_value": 1}) == 1440

    def test_daily(self, wu):
        assert wu._parse_interval_minutes({"type": "daily"}) == 1440

    def test_weekly(self, wu):
        assert wu._parse_interval_minutes({"type": "weekly"}) == 10080

    def test_unknown(self, wu):
        assert wu._parse_interval_minutes({"type": "unknown"}) is None


class TestShouldFire:
    def test_disabled(self, wu):
        sched = {"id": "s1", "enabled": False, "type": "interval"}
        assert not wu._should_fire(sched)

    def test_interval_first_run(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "interval",
                 "interval_unit": "hours", "interval_value": 1}
        assert wu._should_fire(sched)

    def test_interval_too_soon(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "interval",
                 "interval_unit": "hours", "interval_value": 1}
        with wu._schedule_last_run_lock:
            wu._schedule_last_run["s1"] = datetime.now(timezone.utc)
        assert not wu._should_fire(sched)

    def test_interval_elapsed(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "interval",
                 "interval_unit": "minutes", "interval_value": 5}
        with wu._schedule_last_run_lock:
            wu._schedule_last_run["s1"] = datetime.now(timezone.utc) - timedelta(minutes=10)
        assert wu._should_fire(sched)

    def test_daily_wrong_time(self, wu):
        now = datetime.now(timezone.utc)
        wrong_hour = (now.hour + 2) % 24
        sched = {"id": "s1", "enabled": True, "type": "daily",
                 "time_utc": f"{wrong_hour:02d}:00"}
        assert not wu._should_fire(sched)

    def test_daily_already_ran_today(self, wu):
        now = datetime.now(timezone.utc)
        sched = {"id": "s1", "enabled": True, "type": "daily",
                 "time_utc": f"{now.hour:02d}:{now.minute:02d}"}
        with wu._schedule_last_run_lock:
            wu._schedule_last_run["s1"] = now
        assert not wu._should_fire(sched)

    def test_daily_invalid_time(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "daily",
                 "time_utc": "invalid"}
        assert not wu._should_fire(sched)

    def test_weekly_wrong_day(self, wu):
        now = datetime.now(timezone.utc)
        wrong_day = (now.weekday() + 3) % 7
        sched = {"id": "s1", "enabled": True, "type": "weekly",
                 "weekday": wrong_day, "time_utc": f"{now.hour:02d}:{now.minute:02d}"}
        assert not wu._should_fire(sched)

    def test_weekly_invalid_time(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "weekly",
                 "weekday": 0, "time_utc": "bad"}
        assert not wu._should_fire(sched)

    def test_unknown_type(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "custom"}
        assert not wu._should_fire(sched)

    @pytest.fixture
    def fire_at(self, wu, monkeypatch):
        """Ask _should_fire with the clock at a chosen UTC time; the dates are Monday 2026-10-19 and earlier."""
        class InstanceOfDatetime(type):
            def __instancecheck__(cls, value):
                return isinstance(value, datetime)

        def ask(schedule, now, last=None):
            class Clock(datetime, metaclass=InstanceOfDatetime):
                @classmethod
                def now(cls, tz=None):
                    return now

            monkeypatch.setattr(wu, "datetime", Clock)
            wu._schedule_last_run.clear()
            if last is not None:
                wu._schedule_last_run[schedule["id"]] = last
            return wu._should_fire(schedule)
        return ask

    @staticmethod
    def utc(day, hour, minute, second=0):
        return datetime(2026, 10, day, hour, minute, second, tzinfo=timezone.utc)

    def test_daily_slot_survives_a_restart_or_a_slow_tick_within_the_catch_up_window(self, fire_at):
        daily = {"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00"}
        yesterday = self.utc(18, 2, 0, 5)
        assert fire_at(daily, self.utc(19, 1, 59, 50), yesterday) is False  # not yet
        assert fire_at(daily, self.utc(19, 2, 0, 20), yesterday) is True
        # The daemon restarted at 01:59:50 and came back at 02:00:40 (or later): the day used to be skipped.
        assert fire_at(daily, self.utc(19, 2, 1, 20), yesterday) is True
        assert fire_at(daily, self.utc(19, 2, 59, 0), yesterday) is True
        assert fire_at(daily, self.utc(19, 3, 1, 0), yesterday) is False  # too late to be useful; tomorrow instead
        assert fire_at(daily, self.utc(20, 2, 0, 10), yesterday) is True

    def test_daily_slot_runs_once(self, fire_at):
        daily = {"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00"}
        assert fire_at(daily, self.utc(19, 2, 30), self.utc(19, 2, 0, 10)) is False
        assert fire_at(daily, self.utc(19, 2, 30), self.utc(19, 2, 20)) is False  # run late by a catch-up, not twice

    def test_a_new_schedule_does_not_run_for_a_slot_that_passed_before_it_existed(self, fire_at):
        daily = {"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00",
                 "created_at": "2026-10-19T02:30:00Z", "last_run": ""}
        assert fire_at(daily, self.utc(19, 2, 45)) is False
        assert fire_at(daily, self.utc(20, 2, 0, 20)) is True
        assert fire_at({**daily, "created_at": "2026-10-19T01:50:00Z"}, self.utc(19, 2, 0, 20)) is True
        # A hand-written record without created_at still fires inside the window.
        assert fire_at({"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00"}, self.utc(19, 2, 10)) is True

    def test_a_schedule_enabled_again_or_retimed_waits_for_its_next_slot(self, fire_at):
        daily = {"id": "s1", "enabled": True, "type": "daily", "time_utc": "02:00",
                 "created_at": "2026-10-01T00:00:00Z", "armed_at": "2026-10-19T02:30:00Z"}
        yesterday = self.utc(18, 2, 0, 5)
        assert fire_at(daily, self.utc(19, 2, 45), yesterday) is False  # the 02:00 slot passed before it was armed
        assert fire_at(daily, self.utc(20, 2, 0, 20), yesterday) is True
        assert fire_at({**daily, "armed_at": "2026-10-19T01:59:00Z"}, self.utc(19, 2, 0, 20), yesterday) is True
        weekly = {**daily, "type": "weekly", "weekday": 0}
        assert fire_at(weekly, self.utc(19, 2, 45), self.utc(12, 2, 0, 5)) is False
        assert fire_at(weekly, self.utc(26, 2, 0, 20), self.utc(12, 2, 0, 5)) is True
        # A hand-edited value that is not a timestamp is ignored rather than raising.
        assert fire_at({**daily, "armed_at": "later"}, self.utc(19, 2, 10), yesterday) is True

    def test_weekly_slot_survives_a_restart_and_runs_once_a_week(self, fire_at):
        weekly = {"id": "s1", "enabled": True, "type": "weekly", "weekday": 0, "time_utc": "02:00"}
        last_week = self.utc(12, 2, 0, 5)
        assert fire_at(weekly, self.utc(19, 1, 59), last_week) is False
        assert fire_at(weekly, self.utc(19, 2, 0, 20), last_week) is True
        assert fire_at(weekly, self.utc(19, 2, 5, 0), last_week) is True  # missed the exact minute
        assert fire_at(weekly, self.utc(19, 3, 5, 0), last_week) is False
        assert fire_at(weekly, self.utc(20, 2, 0, 20), last_week) is False  # Tuesday is not the slot
        assert fire_at(weekly, self.utc(19, 2, 5, 0), self.utc(19, 2, 0, 20)) is False
        assert fire_at(weekly, self.utc(26, 2, 0, 20), self.utc(19, 2, 0, 20)) is True

    @pytest.mark.parametrize("kind", ["daily", "weekly"])
    def test_out_of_range_time_never_fires_or_raises(self, fire_at, kind):
        schedule = {"id": "s1", "enabled": True, "type": kind, "time_utc": "25:99"}
        assert fire_at(schedule, self.utc(19, 2, 0)) is False


# ═══════════════════════════════════════════════════════════════════════════════
# Notifications
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhook:
    def test_webhook_disabled(self, wu):
        wu._load_settings()
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        # Should not raise
        wu._send_webhook(job)

    def test_webhook_sends(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": True, "on_error": True, "on_vuln_found": True,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock()
            wu._send_webhook(job)
            mock_req.post.assert_called_once()

    def test_webhook_skips_when_no_matching_condition(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": False, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock()
            wu._send_webhook(job)
            mock_req.post.assert_not_called()


class TestEmail:
    def test_email_disabled(self, wu):
        wu._load_settings()
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        wu._send_email(job)  # Should not raise

    def test_email_missing_host(self, wu):
        wu._load_settings()
        wu._settings["email"]["enabled"] = True
        wu._settings["email"]["to_addr"] = "test@test.com"
        # smtp_host is empty
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        wu._send_email(job)  # Should return early, not raise

    def test_email_skips_no_condition(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": False, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with patch("smtplib.SMTP") as mock_smtp:
            wu._send_email(job)
            mock_smtp.assert_not_called()

    def test_email_sends_on_complete(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        job.mark_done()

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_error_does_not_raise(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with patch("smtplib.SMTP", side_effect=Exception("conn refused")):
            wu._send_email(job)  # Should broadcast warning, not raise

    def test_email_failure_is_logged_as_the_class_only(self, wu):
        """SMTP replies and host names reach every dashboard client through the log, so only the class name is shown."""
        import smtplib
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        reply = b"5.7.8 Authentication failed for u at mx7.internal.example SECRETDETAIL"
        with patch("smtplib.SMTP", side_effect=smtplib.SMTPAuthenticationError(535, reply)):
            wu._send_email(job)
        messages = [entry["msg"] for entry in wu._log_history]
        assert "[*] Email notification failed: SMTPAuthenticationError" in messages
        assert not any("SECRETDETAIL" in message or "internal.example" in message for message in messages)


# ═══════════════════════════════════════════════════════════════════════════════
# Flask API endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPIScans:
    def test_list_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_start_scan_missing_target(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_start_scan_invalid_target(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "$(rm -rf /)"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_start_scan_invalid_speed(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "speed": 10}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_start_scan_invalid_mode(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "mode": "invalid"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_start_scan_invalid_scan_type(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "scan_type": "bad"}),
                           content_type="application/json")
        assert resp.status_code == 400

    @patch("autopwn_suite.web_ui._launch_scan")
    @pytest.mark.parametrize("flags", [
        "; whoami", "-oN /etc/cron.d/x", "--oX out.xml", "-iL /etc/shadow", "-6o out", "--appe", "--script=http-fetch",
        "--script http-put --script-args http-put.url=/x,http-put.file=/etc/passwd", "-sS", "-sV -O", "-p 22", "-T5",
        pytest.param("-sS " * 300, id="repeated-technique"), "\u00e9\u4e2d\u202e", "x"])
    def test_start_scan_refuses_any_nmap_flags_text(self, mock_launch, client, flags):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "nmap_flags": flags}),
                           content_type="application/json")
        assert resp.status_code == 400
        assert resp.get_json() == {"error": "Nmap options are not accepted; use the scan technique, ports and detection settings"}
        mock_launch.assert_not_called()

    @patch("autopwn_suite.web_ui._launch_scan")
    @pytest.mark.parametrize("extra", [{}, {"nmap_flags": ""}, {"nmap_flags": "  "}])
    def test_start_scan_without_flags_text_is_accepted(self, mock_launch, client, wu, extra):
        mock_launch.return_value = wu.ScanJob("test-id", "192.168.1.1", {})
        resp = client.post("/api/scan/start", json={"target": "192.168.1.1", "scan_technique": "-sT", "ports": "22,80", **extra})
        assert resp.status_code == 200
        assert mock_launch.call_args.args[0]["nmap_flags"] == "-sT -p 22,80"

    @patch("autopwn_suite.web_ui._launch_scan")
    def test_start_scan_builds_the_arguments_from_the_structured_fields_only(self, mock_launch, client, wu):
        mock_launch.return_value = wu.ScanJob("test-id", "192.168.1.1", {})
        resp = client.post("/api/scan/start", json={
            "target": "192.168.1.1", "scan_technique": "-sU", "ports": "53,161,1000-2000", "version_intensity": 4,
            "os_detection": True, "host_timeout": 90, "speed": 4})
        assert resp.status_code == 200
        config = mock_launch.call_args.args[0]
        assert config["nmap_flags"] == "-sU -p 53,161,1000-2000 --version-intensity 4 -O"

    @patch("autopwn_suite.web_ui._launch_scan")
    @pytest.mark.parametrize("body", [
        {"scan_technique": "-sS --script=banner"}, {"scan_technique": "--script=banner"}, {"scan_technique": "-oN x"},
        {"ports": "22 -oN /etc/cron.d/x"}, {"ports": "22,80;id"}, {"ports": "--script=banner"}, {"ports": "70000"},
        {"version_intensity": "9 -oN x"}, {"version_intensity": "-oN"}, {"version_intensity": 10}, {"version_intensity": -1},
        {"speed": "3 -oN x"}, {"host_timeout": "30 --script=x"}, {"mode": "evade -oN x"}, {"scan_type": "arp -oN x"},
        {"os_detection": "-oN x"}, {"os_detection": "true"}])
    def test_start_scan_refuses_structured_values_that_would_carry_an_option(self, mock_launch, client, body):
        resp = client.post("/api/scan/start", json={"target": "192.168.1.1", **body})
        assert resp.status_code == 400
        mock_launch.assert_not_called()

    @patch("autopwn_suite.web_ui._launch_scan")
    @pytest.mark.parametrize("target", ["-oN", "-oN /etc/cron.d/x", "192.168.1.1 --script=x", "192.168.1.1,-A"])
    def test_start_scan_refuses_a_target_that_starts_an_option(self, mock_launch, client, target):
        resp = client.post("/api/scan/start", json={"target": target})
        assert resp.status_code == 400
        mock_launch.assert_not_called()

    def test_start_scan_negative_timeout(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "host_timeout": -1}),
                           content_type="application/json")
        assert resp.status_code == 400

    @patch("autopwn_suite.web_ui._launch_scan")
    def test_start_scan_success(self, mock_launch, client, wu):
        mock_job = wu.ScanJob("test-id", "192.168.1.1", {})
        mock_launch.return_value = mock_job
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1"}),
                           content_type="application/json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["scan_id"] == "test-id"

    def test_stop_scan_not_found(self, client):
        resp = client.post("/api/scan/stop",
                           data=json.dumps({"scan_id": "nonexistent"}),
                           content_type="application/json")
        assert resp.status_code == 404

    def test_stop_scan_already_done(self, client, wu):
        job = wu.ScanJob("done1", "t", {})
        job.mark_done()
        wu._register_scan(job)
        resp = client.post("/api/scan/stop",
                           data=json.dumps({"scan_id": "done1"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_stop_scan_success(self, client, wu):
        job = wu.ScanJob("run1", "t", {})
        wu._register_scan(job)
        resp = client.post("/api/scan/stop",
                           data=json.dumps({"scan_id": "run1"}),
                           content_type="application/json")
        assert resp.status_code == 200
        assert job.should_stop()

    def test_scan_detail_not_found(self, client):
        resp = client.get("/api/scans/nonexistent")
        assert resp.status_code == 404

    def test_scan_detail_found(self, client, wu):
        job = wu.ScanJob("det1", "target", {})
        wu._register_scan(job)
        resp = client.get("/api/scans/det1")
        assert resp.status_code == 200
        assert resp.get_json()["id"] == "det1"

    def test_scan_download_not_found(self, client):
        resp = client.get("/api/scans/nonexistent/download")
        assert resp.status_code == 404

    def test_scan_download(self, client, wu):
        job = wu.ScanJob("dl1", "target", {})
        wu._register_scan(job)
        resp = client.get("/api/scans/dl1/download")
        assert resp.status_code == 200
        assert "attachment" in resp.headers.get("Content-Disposition", "")


class TestAPIHosts:
    def test_hosts_empty(self, client):
        resp = client.get("/api/hosts")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_hosts_with_scan(self, client, wu):
        job = wu.ScanJob("h1", "target", {})
        job.get_or_create_host("10.0.0.1")
        wu._register_scan(job)
        resp = client.get("/api/hosts")
        assert len(resp.get_json()) == 1


class TestAPILog:
    def test_log_empty(self, client):
        resp = client.get("/api/log")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_log_with_entries(self, client, wu):
        wu._broadcast({"msg": "test log"})
        resp = client.get("/api/log")
        assert len(resp.get_json()) == 1

    def test_log_entries_carry_the_id_a_stream_resumes_after(self, client, wu):
        for number in range(3):
            wu._broadcast({"msg": f"entry {number}"})
        ids = [row["id"] for row in client.get("/api/log").get_json()]
        assert ids == list(range(ids[0], ids[0] + 3))


def _sse_entries(stream, count):
    """Read `count` numbered entries from an open event stream, skipping heartbeat comments."""
    chunks = iter(stream.response)
    entries = []
    for _ in range(count + 2):  # a stream with nothing to send yields a heartbeat per second; never wait for ever
        for frame in next(chunks).decode().split("\n\n"):
            if frame.startswith("id: "):
                header, data = frame.split("\n", 1)
                assert data.startswith("data: ")
                entries.append((int(header[len("id: "):]), json.loads(data[len("data: "):])))
        if len(entries) >= count:
            break
    assert len(entries) == count, entries
    return entries


class TestAPIEvents:
    def _history(self, wu, count=4):
        for number in range(count):
            wu._broadcast({"msg": f"history {number}"})
        return [row["id"] for row in wu._log_history]

    def test_stream_replays_what_was_logged_after_the_given_id_and_then_goes_live(self, client, wu):
        ids = self._history(wu)
        stream = client.get(f"/api/events?after={ids[1]}", buffered=False)
        try:
            wu._broadcast({"msg": "live"})
            received = _sse_entries(stream, 3)
        finally:
            stream.close()
        assert [(entry_id, entry["msg"]) for entry_id, entry in received] == [
            (ids[2], "history 2"), (ids[3], "history 3"), (ids[3] + 1, "live")]
        assert all(entry["id"] == entry_id for entry_id, entry in received)
        assert not wu._sse_subscribers

    def test_reconnect_header_wins_over_the_first_connect_parameter(self, client, wu):
        ids = self._history(wu)
        stream = client.get(f"/api/events?after={ids[0]}", headers={"Last-Event-ID": str(ids[2])}, buffered=False)
        try:
            assert [entry["msg"] for _, entry in _sse_entries(stream, 1)] == ["history 3"]
        finally:
            stream.close()

    def test_an_entry_logged_while_the_replay_is_being_read_arrives_once_and_in_order(self, client, wu):
        ids = self._history(wu)
        stream = client.get("/api/events?after=0", buffered=False)
        try:
            wu._broadcast({"msg": "during the replay"})
            received = _sse_entries(stream, len(ids) + 1)
        finally:
            stream.close()
        assert [entry_id for entry_id, _ in received] == ids + [ids[-1] + 1]
        assert received[-1][1]["msg"] == "during the replay"

    def test_an_id_this_process_never_issued_replays_the_retained_history(self, client, wu):
        ids = self._history(wu, 2)
        stream = client.get(f"/api/events?after={ids[-1] + 10**9}", buffered=False)
        try:
            assert [entry_id for entry_id, _ in _sse_entries(stream, 2)] == ids
        finally:
            stream.close()

    def test_a_malformed_resume_point_means_live_only(self, client, wu):
        self._history(wu, 2)
        stream = client.get("/api/events?after=nonsense", headers={"Last-Event-ID": "-1"}, buffered=False)
        try:
            wu._broadcast({"msg": "live"})
            assert [entry["msg"] for _, entry in _sse_entries(stream, 1)] == ["live"]
        finally:
            stream.close()

    def test_resume_point_accepts_only_short_ascii_digits(self, wu):
        assert wu._resume_point(None, "42") == 42
        assert wu._resume_point("7", "42") == 7
        assert wu._resume_point("junk", "42") == 42
        for value in (None, "", " 1", "1 ", "+1", "-1", "1.5", "1e3", "0x10", "١٢٣", "²", "9" * 19, "1\n2"):
            assert wu._resume_point(value) is None, value

    def test_a_head_request_does_not_leave_a_subscriber_behind(self, client, wu):
        assert client.head("/api/events").status_code == 200
        assert not wu._sse_subscribers

    def test_stream_sends_only_new_entries_because_the_page_loads_history_from_api_log(self, client, wu):
        for number in range(3):
            wu._broadcast({"msg": f"history {number}"})
        assert [row["msg"] for row in client.get("/api/log").get_json()] == ["history 0", "history 1", "history 2"]
        stream = client.get("/api/events", buffered=False)
        try:
            wu._broadcast({"msg": "live"})
            chunks = iter(stream.response)
            received = next(chunks) + next(chunks)  # the test client has already consumed one heartbeat
            assert b"live" in received and b"history" not in received
        finally:
            stream.close()
        assert not wu._sse_subscribers

    def test_head_request_does_not_leave_a_subscriber_behind(self, client, wu):
        """A HEAD response is never iterated, so nothing would ever remove the queue it registered."""
        response = client.head("/api/events")
        assert response.status_code == 200 and response.mimetype == "text/event-stream"
        assert not wu._sse_subscribers


class TestNestedJSONBodies:
    """Deeply nested JSON must be malformed input, never a server error (RecursionError is not a ValueError)."""

    @pytest.mark.parametrize("path", ["/api/profiles", "/api/scan/start", "/api/schedules", "/api/scan/stop"])
    @pytest.mark.parametrize("body", ["[" * 200000, '{"a":' * 50000], ids=["lists", "objects"])
    def test_post_is_rejected_without_a_server_error(self, client, path, body):
        response = client.post(path, data=body, content_type="application/json")
        assert response.status_code in (400, 404)

    def test_put_is_handled_without_a_server_error(self, client):
        for path in ("/api/settings", "/api/profiles/missing", "/api/schedules/missing"):
            assert client.put(path, data="[" * 200000, content_type="application/json").status_code in (200, 400, 404)

    def test_a_settings_file_nested_too_deeply_is_preserved_and_defaults_load(self, wu):
        wu._SETTINGS_FILE.write_text("[" * 200000, encoding="utf-8")
        wu._load_settings()
        assert wu._settings["email"]["enabled"] is False
        assert wu._SETTINGS_FILE.read_text(encoding="utf-8") == "[" * 200000


class TestAPISettings:
    def test_get_settings(self, client):
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "email" in data
        assert "webhook" in data

    def test_get_settings_masks_password(self, client, wu):
        wu._settings["email"]["password"] = "secret123"
        resp = client.get("/api/settings")
        assert resp.get_json()["email"]["password"] == "••••••••"

    def test_put_settings(self, client):
        resp = client.put("/api/settings",
                          data=json.dumps({"nist_api_key": "new-key"}),
                          content_type="application/json")
        assert resp.status_code == 200

    def test_put_settings_preserves_masked_password(self, client, wu):
        wu._settings["email"]["password"] = "real-secret"
        client.put("/api/settings",
                   data=json.dumps({"email": {"password": "••••••••"}}),
                   content_type="application/json")
        assert wu._settings["email"]["password"] == "real-secret"


class TestAPIProfiles:
    def test_list_empty(self, client):
        resp = client.get("/api/profiles")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_profile(self, client):
        resp = client.post("/api/profiles",
                           data=json.dumps({"name": "Fast Scan", "speed": 5}),
                           content_type="application/json")
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "Fast Scan"
        assert data["config"]["speed"] == 5

    def test_create_profile_no_name(self, client):
        resp = client.post("/api/profiles",
                           data=json.dumps({"speed": 5}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_update_profile(self, client, wu):
        # Create first
        resp = client.post("/api/profiles",
                           data=json.dumps({"name": "Test"}),
                           content_type="application/json")
        pid = resp.get_json()["id"]
        # Update
        resp = client.put(f"/api/profiles/{pid}",
                          data=json.dumps({"name": "Updated", "speed": 4}),
                          content_type="application/json")
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "Updated"

    def test_update_profile_not_found(self, client):
        resp = client.put("/api/profiles/nonexistent",
                          data=json.dumps({"name": "X"}),
                          content_type="application/json")
        assert resp.status_code == 404

    def test_delete_profile(self, client):
        resp = client.post("/api/profiles",
                           data=json.dumps({"name": "ToDelete"}),
                           content_type="application/json")
        pid = resp.get_json()["id"]
        resp = client.delete(f"/api/profiles/{pid}")
        assert resp.status_code == 200
        resp = client.get("/api/profiles")
        assert len(resp.get_json()) == 0

    def test_delete_profile_not_found(self, client):
        resp = client.delete("/api/profiles/nonexistent")
        assert resp.status_code == 404


class TestAPISchedules:
    def _create_profile(self, client):
        resp = client.post("/api/profiles",
                           data=json.dumps({"name": "Profile"}),
                           content_type="application/json")
        return resp.get_json()["id"]

    def test_list_empty(self, client):
        resp = client.get("/api/schedules")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_schedule(self, client):
        pid = self._create_profile(client)
        resp = client.post("/api/schedules",
                           data=json.dumps({
                               "name": "Daily Scan",
                               "target": "192.168.1.0/24",
                               "profile_id": pid,
                               "type": "daily",
                               "time_utc": "02:00",
                           }),
                           content_type="application/json")
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "Daily Scan"
        assert data["last_run"] == ""

    def test_create_schedule_no_target(self, client):
        pid = self._create_profile(client)
        resp = client.post("/api/schedules",
                           data=json.dumps({"profile_id": pid}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_create_schedule_no_profile(self, client):
        resp = client.post("/api/schedules",
                           data=json.dumps({"target": "192.168.1.1"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_create_schedule_invalid_profile(self, client):
        resp = client.post("/api/schedules",
                           data=json.dumps({"target": "192.168.1.1", "profile_id": "bad"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_update_schedule(self, client):
        pid = self._create_profile(client)
        resp = client.post("/api/schedules",
                           data=json.dumps({
                               "target": "10.0.0.0/24",
                               "profile_id": pid,
                           }),
                           content_type="application/json")
        sid = resp.get_json()["id"]
        resp = client.put(f"/api/schedules/{sid}",
                          data=json.dumps({"name": "Updated"}),
                          content_type="application/json")
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "Updated"

    def _daily_schedule(self, client, wu, minutes_ago, **fields):
        """A daily schedule created long ago whose slot passed minutes_ago, so it is owed a catch-up run."""
        slot = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        resp = client.post("/api/schedules", json={"target": "192.0.2.10", "profile_id": self._create_profile(client),
                                                   "type": "daily", "time_utc": slot.strftime("%H:%M"), **fields})
        assert resp.status_code == 201
        sid = resp.get_json()["id"]
        wu._schedules[sid]["created_at"] = "2026-01-01T00:00:00Z"
        return sid

    def test_enabling_a_schedule_again_does_not_run_the_slot_it_missed(self, client, wu):
        sid = self._daily_schedule(client, wu, 30, enabled=False)
        assert client.put(f"/api/schedules/{sid}", json={"enabled": True}).status_code == 200
        assert "armed_at" in wu._schedules[sid]
        assert not wu._should_fire(wu._schedules[sid])
        # Edits that leave the schedule on and its timing alone keep the catch-up they were owed.
        other = self._daily_schedule(client, wu, 30)
        assert client.put(f"/api/schedules/{other}", json={"name": "Renamed", "enabled": True,
                                                           "armed_at": "2000-01-01T00:00:00Z"}).status_code == 200
        assert "armed_at" not in wu._schedules[other]  # and a request cannot set it
        assert wu._should_fire(wu._schedules[other])

    @pytest.mark.parametrize("kind", ["daily", "weekly"])
    def test_retiming_a_schedule_does_not_run_a_slot_that_passed_before_the_edit(self, client, wu, kind):
        sid = self._daily_schedule(client, wu, 30)
        assert wu._should_fire(wu._schedules[sid])
        passed = datetime.now(timezone.utc) - timedelta(minutes=20)
        change = {"time_utc": passed.strftime("%H:%M")}
        if kind == "weekly":
            change.update(type="weekly", weekday=passed.weekday())
        assert client.put(f"/api/schedules/{sid}", json=change).status_code == 200
        assert not wu._should_fire(wu._schedules[sid])

    def test_update_schedule_not_found(self, client):
        resp = client.put("/api/schedules/nonexistent",
                          data=json.dumps({"name": "X"}),
                          content_type="application/json")
        assert resp.status_code == 404

    def test_delete_schedule(self, client):
        pid = self._create_profile(client)
        resp = client.post("/api/schedules",
                           data=json.dumps({
                               "target": "10.0.0.1",
                               "profile_id": pid,
                           }),
                           content_type="application/json")
        sid = resp.get_json()["id"]
        resp = client.delete(f"/api/schedules/{sid}")
        assert resp.status_code == 200

    def test_delete_schedule_not_found(self, client):
        resp = client.delete("/api/schedules/nonexistent")
        assert resp.status_code == 404


class TestAPITestEmail:
    def test_email_disabled(self, client, wu):
        wu._settings["email"]["enabled"] = False
        resp = client.post("/api/settings/test_email")
        assert resp.status_code == 400

    def test_email_send_success(self, client, wu):
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
        }
        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            resp = client.post("/api/settings/test_email")
            assert resp.status_code == 200

    def test_email_send_failure(self, client, wu):
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
        }
        with patch("smtplib.SMTP", side_effect=Exception("fail")):
            with patch("logging.exception"):
                resp = client.post("/api/settings/test_email")
                assert resp.status_code == 500

    def test_email_failure_is_logged_as_the_class_only(self, client, wu, caplog):
        """The SMTP reply names hosts and accounts; the server log gets the class name like every delivery path."""
        import smtplib
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
        }
        reply = b"5.7.8 Authentication failed for u at mx7.internal.example SECRETDETAIL"
        with patch("smtplib.SMTP", side_effect=smtplib.SMTPAuthenticationError(535, reply)):
            resp = client.post("/api/settings/test_email")
        assert resp.status_code == 500 and resp.get_json() == {"error": "Failed to send test email"}
        assert "Failed to send test email: SMTPAuthenticationError" in caplog.text
        assert "SECRETDETAIL" not in caplog.text and "internal.example" not in caplog.text


class TestAPITestWebhook:
    def test_webhook_disabled(self, client, wu):
        wu._settings["webhook"] = {"enabled": False, "url": ""}
        resp = client.post("/api/settings/test_webhook")
        assert resp.status_code == 400

    def test_webhook_send_success(self, client, wu):
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock(return_value=mock_response)
            resp = client.post("/api/settings/test_webhook")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status_code"] == 200

    def test_webhook_send_failure(self, client, wu):
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
        }
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock(side_effect=Exception("timeout"))
            resp = client.post("/api/settings/test_webhook")
            assert resp.status_code == 500


class TestAPIProfileEdgeCases:
    def test_create_profile_with_all_options(self, client):
        resp = client.post("/api/profiles",
                           data=json.dumps({
                               "name": "Full Profile",
                               "mode": "evade",
                               "speed": 2,
                               "scan_type": "arp",
                               "scan_technique": "-sU",
                               "ports": "1-1000",
                               "version_intensity": 5,
                               "os_detection": True,
                               "host_timeout": 300,
                               "scan_ports": True,
                               "scan_vulns": False,
                               "skip_discovery": True,
                           }),
                           content_type="application/json")
        assert resp.status_code == 201
        cfg = resp.get_json()["config"]
        assert cfg["mode"] == "evade"
        assert cfg["scan_technique"] == "-sU"
        assert cfg["version_intensity"] == 5
        assert cfg["os_detection"] is True
        assert cfg["skip_discovery"] is True
        assert cfg["nmap_flags"] == ""

    def test_update_profile_boolean_and_intensity_fields(self, client):
        # Create
        resp = client.post("/api/profiles",
                           data=json.dumps({"name": "Updatable"}),
                           content_type="application/json")
        pid = resp.get_json()["id"]
        # Update with boolean and version_intensity
        resp = client.put(f"/api/profiles/{pid}",
                          data=json.dumps({
                              "scan_ports": False,
                              "os_detection": True,
                              "version_intensity": 7,
                              "host_timeout": 500,
                          }),
                          content_type="application/json")
        assert resp.status_code == 200
        cfg = resp.get_json()["config"]
        assert cfg["scan_ports"] is False
        assert cfg["os_detection"] is True
        assert cfg["version_intensity"] == 7
        assert cfg["host_timeout"] == 500


class TestAPIVersion:
    def test_version(self, client):
        resp = client.get("/api/version")
        assert resp.status_code == 200
        assert "version" in resp.get_json()


class TestAPIFavicon:
    def test_favicon(self, client):
        resp = client.get("/favicon.ico")
        assert resp.status_code == 200


class TestAPIIndex:
    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# Notify helper
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotify:
    def test_notify_spawns_threads(self, wu):
        job = wu.ScanJob("n1", "target", {})
        job.mark_done()
        wu._load_settings()
        # Should not raise even with no settings configured
        wu._notify(job)


# ═══════════════════════════════════════════════════════════════════════════════
# Email with hosts and vulns (covers HTML generation paths)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailContent:
    def _setup_email(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": True, "on_error": True, "on_vuln_found": True,
        }

    def test_email_with_hosts_and_vulns(self, wu):
        self._setup_email(wu)
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        h = job.get_or_create_host("10.0.0.1")
        h["ports"] = [{"port": 80, "service": "http", "product": "nginx", "version": "1.0"}]
        h["vulns"] = [{"cve": "CVE-2024-0001", "severity": "high", "cvss": 7.5, "description": "test", "port": 80}]
        job.mark_done()

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_with_error(self, wu):
        self._setup_email(wu)
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        job.mark_error("scan failed")

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_evasion_mode(self, wu):
        self._setup_email(wu)
        job = wu.ScanJob("id1", "target", {"mode": "evade"})
        job.mark_done()

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_with_nmap_flags(self, wu):
        self._setup_email(wu)
        job = wu.ScanJob("id1", "target", {
            "mode": "normal", "speed": 3, "host_timeout": 240,
            "nmap_flags": "-p 80-443 -O"
        })
        job.mark_done()

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_no_hosts(self, wu):
        self._setup_email(wu)
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        job.mark_done()

        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# Webhook edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookEdgeCases:
    def test_webhook_on_error(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": False, "on_error": True, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_error("failed")
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock()
            wu._send_webhook(job)
            mock_req.post.assert_called_once()
            payload = mock_req.post.call_args[1]["json"]
            assert payload["event"] == "scan_error"

    def test_webhook_on_vuln_found(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": False, "on_error": False, "on_vuln_found": True,
        }
        job = wu.ScanJob("id1", "target", {})
        h = job.get_or_create_host("10.0.0.1")
        h["vulns"] = [{"cve": "CVE-2024-0001"}]
        job.mark_done()
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock()
            wu._send_webhook(job)
            mock_req.post.assert_called_once()

    def test_webhook_delivery_failure(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with patch.object(wu, "_requests") as mock_req:
            mock_req.post = MagicMock(side_effect=Exception("timeout"))
            wu._send_webhook(job)
            # Should broadcast a warning, not raise
            assert any("Webhook delivery failed" in e.get("msg", "") for e in wu._log_history)

    def test_webhook_no_requests_library(self, wu):
        wu._load_settings()
        wu._settings["webhook"] = {
            "enabled": True, "url": "http://example.com/hook",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        orig = wu.REQUESTS_AVAILABLE
        wu.REQUESTS_AVAILABLE = False
        try:
            job = wu.ScanJob("id1", "target", {})
            job.mark_done()
            wu._send_webhook(job)  # Should return early, not raise
        finally:
            wu.REQUESTS_AVAILABLE = orig


@contextmanager
def _answering_webhook(status):
    """A 127.0.0.1 webhook that answers every POST with ``status`` and points at a second 127.0.0.1 sink.

    Yields the webhook URL, the bodies the webhook received and the bodies the sink received.
    """
    hook_bodies, sink_bodies = [], []

    class Sink(BaseHTTPRequestHandler):
        bodies = sink_bodies

        def do_POST(self):
            self.bodies.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)

    class Hook(Sink):
        bodies = hook_bodies

        def do_POST(self):
            self.bodies.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self.send_response(status)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/collect")
            self.send_header("Content-Length", "0")
            self.end_headers()

    hook = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    servers = [sink, hook]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{hook.server_port}/hook", hook_bodies, sink_bodies
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


class TestWebhookRedirects:
    """A 307/308 would make requests POST the event again to whatever host the Location names."""

    @pytest.fixture(autouse=True)
    def _loopback_without_proxy(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        monkeypatch.setenv("no_proxy", "127.0.0.1")

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_a_redirect_is_a_failed_delivery_and_is_not_followed(self, wu, status):
        wu._load_settings()
        job = wu.ScanJob("id1", "target", {})
        job.mark_done()
        with _answering_webhook(status) as (url, hook_bodies, sink_bodies):
            wu._settings["webhook"] = {"enabled": True, "url": url, "on_complete": True, "on_error": False, "on_vuln_found": False}
            wu._send_webhook(job)
        assert len(hook_bodies) == 1
        assert sink_bodies == [], "the redirect target must never receive the event"
        assert any(f"Webhook delivery failed: HTTPError (HTTP {status})" in e.get("msg", "") for e in wu._log_history)

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_the_test_webhook_route_reports_a_redirect_as_a_failure(self, client, wu, status):
        with _answering_webhook(status) as (url, hook_bodies, sink_bodies):
            wu._settings["webhook"] = {"enabled": True, "url": url}
            response = client.post("/api/settings/test_webhook")
        assert response.status_code == 500
        assert len(hook_bodies) == 1
        assert sink_bodies == [], "the redirect target must never receive the event"

    @pytest.mark.parametrize("status", [200, 204])
    def test_a_2xx_answer_is_still_a_delivery(self, client, wu, status):
        with _answering_webhook(status) as (url, hook_bodies, sink_bodies):
            wu._settings["webhook"] = {"enabled": True, "url": url}
            response = client.post("/api/settings/test_webhook")
        assert response.status_code == 200
        assert response.get_json() == {"ok": True, "status_code": status}
        assert len(hook_bodies) == 1 and sink_bodies == []


class TestAPIWebhookNoRequests:
    def test_test_webhook_no_requests(self, client, wu):
        wu._settings["webhook"] = {"enabled": True, "url": "http://example.com"}
        orig = wu.REQUESTS_AVAILABLE
        wu.REQUESTS_AVAILABLE = False
        try:
            resp = client.post("/api/settings/test_webhook")
            assert resp.status_code == 500
        finally:
            wu.REQUESTS_AVAILABLE = orig


# ═══════════════════════════════════════════════════════════════════════════════
# Start server validation
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# _run_scan (mocked external dependencies)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunScan:
    def test_run_scan_nmap_not_found(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "192.168.1.1"})
        wu._register_scan(job)
        with patch("shutil.which", return_value=None):
            wu._run_scan(job)
        assert job.status == "error"
        assert "nmap not found" in job.error

    def test_run_scan_no_hosts_found(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "192.168.1.1", "mode": "normal", "speed": 3, "host_timeout": 240})
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.web_ui.is_root", return_value=False, create=True), \
             patch("autopwn_suite.scanner.DiscoverHosts", return_value=[]):
            # Need to mock the imports that happen inside _run_scan
            import autopwn_suite.utils as mu
            with patch.object(mu, "is_root", return_value=False, create=True):
                wu._run_scan(job)
        assert job.status == "completed"

    def test_run_scan_stopped_by_user(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "192.168.1.1", "mode": "normal", "speed": 3, "host_timeout": 240})
        wu._register_scan(job)
        job.request_stop()  # Pre-stop
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            wu._run_scan(job)
        assert job.status == "stopped"

    def test_run_scan_noise_mode_fallback(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "192.168.1.1", "mode": "noise", "speed": 3, "host_timeout": 240, "skip_discovery": True, "scan_ports": False})
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            wu._run_scan(job)
        assert job.status == "completed"
        assert any("Noise mode" in e.get("msg", "") for e in wu._log_history)

    def test_run_scan_skip_discovery(self, wu):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_nm.__getitem__ = MagicMock(return_value={
            "addresses": {"ipv4": "192.168.1.1"},
            "vendor": {},
            "osmatch": [{"name": "Linux"}],
        })

        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "skip_discovery": True,
            "scan_ports": True, "scan_vulns": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.scanner.PortScan", return_value=mock_nm), \
             patch("autopwn_suite.scanner.AnalyseScanResults", return_value=[]):
            wu._run_scan(job)
        assert job.status == "completed"

    def test_run_scan_port_scan_exception(self, wu):
        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "skip_discovery": True,
            "scan_ports": True, "scan_vulns": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.scanner.PortScan", side_effect=Exception("nmap error")):
            wu._run_scan(job)
        assert job.status == "partial"
        assert job.hosts_list()[0]["scan_status"] == "error"
        assert any("Port scan failed" in e.get("msg", "") for e in wu._log_history)

    def test_run_scan_system_exit(self, wu):
        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "skip_discovery": True,
            "scan_ports": True, "scan_vulns": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.scanner.PortScan", side_effect=SystemExit("nmap not installed")):
            wu._run_scan(job)
        assert job.status == "partial"

    def test_run_scan_with_ports_and_vulns(self, wu):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_nm.__getitem__ = MagicMock(return_value={
            "addresses": {"ipv4": "192.168.1.1"},
            "vendor": {},
            "osmatch": [],
        })

        mock_cve = MagicMock()
        mock_cve.CVEID = "CVE-2024-0001"
        mock_cve.description = "Test vuln"
        mock_cve.severity = "HIGH"
        mock_cve.severity_score = 7.5

        port_array = [["192.168.1.1", 80, "http", "nginx", "1.0"]]

        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "skip_discovery": True,
            "scan_ports": True, "scan_vulns": True,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.scanner.PortScan", return_value=mock_nm), \
             patch("autopwn_suite.scanner.AnalyseScanResults", return_value=port_array), \
             patch("autopwn_suite.searchvuln.GenerateKeyword", return_value="nginx 1.0"), \
             patch("autopwn_suite.nist_search.searchCVE", return_value=[mock_cve]):
            wu._run_scan(job)

        assert job.status == "completed"
        hosts = job.hosts_list()
        assert len(hosts) == 1
        assert len(hosts[0]["ports"]) == 1
        assert len(hosts[0]["vulns"]) == 1

    def test_run_scan_evade_mode_non_root(self, wu):
        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "evade", "speed": 3,
            "host_timeout": 240, "skip_discovery": True, "scan_ports": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            wu._run_scan(job)
        assert any("Root required" in e.get("msg", "") for e in wu._log_history)

    def test_run_scan_discovery_exception(self, wu):
        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "scan_ports": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("autopwn_suite.scanner.DiscoverHosts", side_effect=Exception("fail")):
            wu._run_scan(job)
        # Should fall back to scanning target directly
        assert job.status == "partial"


class TestStartServer:
    def test_no_flask(self, wu):
        wu.FLASK_AVAILABLE = False
        with pytest.raises(RuntimeError, match="Flask is not installed"):
            wu.start_server()

    def test_no_index_html(self, wu, tmp_path):
        wu.FLASK_AVAILABLE = True
        wu._STATIC_DIR = tmp_path / "nonexistent_static"
        wu._STATIC_DIR.mkdir()
        with pytest.raises(FileNotFoundError):
            wu.start_server()

    def test_flask_debug_environment_cannot_enable_the_unauthenticated_debugger(self, wu, monkeypatch):
        """FLASK_DEBUG=1 must not wrap the dashboard in Werkzeug's /console debugger, which sits outside sign-in."""
        from types import SimpleNamespace

        from werkzeug.debug import DebuggedApplication
        from werkzeug.test import Client

        served = {}

        def make_server(host, port, application, *args, **kwargs):
            served["application"] = application
            return SimpleNamespace(socket=SimpleNamespace(set_inheritable=lambda value: None), fileno=lambda: 0,
                                   log_startup=lambda: None, serve_forever=lambda: None)

        monkeypatch.setenv("FLASK_DEBUG", "1")
        monkeypatch.setenv("WERKZEUG_SERVER_FD", "0")  # run_simple exports it; the monkeypatch restores it
        monkeypatch.setattr("werkzeug.serving.make_server", make_server)
        monkeypatch.setattr(wu, "_scheduler_loop", lambda: None)
        wu.start_server(port=0)
        application = served["application"]
        assert not isinstance(application, DebuggedApplication)
        assert application.debug is False
        console = Client(application).get("/console", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        assert console.status_code == 302 and console.headers["Location"].endswith("/login")
        assert b"Interactive Console" not in console.data


# ═══════════════════════════════════════════════════════════════════════════════
# _log helper
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogHelper:
    def test_log_default_level(self, wu):
        job = wu.ScanJob("id1", "target", {})
        wu._log(job, "test message")
        assert wu._log_history[-1]["level"] == "info"
        assert wu._log_history[-1]["msg"] == "test message"

    def test_log_custom_level(self, wu):
        job = wu.ScanJob("id1", "target", {})
        wu._log(job, "error msg", "error")
        assert wu._log_history[-1]["level"] == "error"


# ═══════════════════════════════════════════════════════════════════════════════
# _launch_scan
# ═══════════════════════════════════════════════════════════════════════════════

class TestLaunchScan:
    def test_launch_scan_registers_job(self, wu):
        with patch.object(wu, "_run_scan"):
            job = wu._launch_scan({"target": "192.168.1.1"})
            assert wu._get_scan(job.id) is job
            assert job.target == "192.168.1.1"
            assert job.status == "running"


def test_scan_snapshot_is_detached_and_redacts_api_key(wu):
    job = wu.ScanJob("snapshot", "10.0.0.1", {"api_key": "secret", "speed": 3})
    host = job.get_or_create_host("10.0.0.1")
    host["ports"] = [{"port": 80, "protocol": "tcp"}]
    snapshot = job.hosts_list()
    host["ports"][0]["port"] = 443
    assert snapshot[0]["ports"][0]["port"] == 80
    assert "api_key" not in job.to_full_dict()["config"]
    assert job.config["api_key"] == "secret"


def test_export_separates_same_port_tcp_and_udp_findings(wu):
    job = wu.ScanJob("protocols", "10.0.0.1", {})
    host = job.get_or_create_host("10.0.0.1")
    host["ports"] = [{"port": 53, "protocol": p} for p in ("tcp", "udp")]
    host["vulns"] = [{"port": 53, "protocol": p, "cve": f"CVE-{p}"} for p in ("tcp", "udp")]
    ports = job.to_full_dict()["hosts"][0]["ports"]
    assert [p["vulnerabilities"][0]["cve"] for p in ports] == ["CVE-tcp", "CVE-udp"]


def test_latest_host_replaces_old_ports_instead_of_merging(client, wu):
    old = wu.ScanJob("old", "10.0.0.1", {})
    old.started_at = "2026-01-01T00:00:00Z"
    old.get_or_create_host("10.0.0.1")["ports"] = [{"port": 80}, {"port": 443}]
    new = wu.ScanJob("new", "10.0.0.1", {})
    new.started_at = "2026-01-02T00:00:00Z"
    new.get_or_create_host("10.0.0.1")["ports"] = [{"port": 443}]
    wu._register_scan(new)
    wu._register_scan(old)
    hosts = client.get("/api/hosts").get_json()
    assert len(hosts) == 1
    assert hosts[0]["scan_id"] == "new"
    assert hosts[0]["ports"] == [{"port": 443}]


def test_failed_attempt_keeps_last_actual_observation(client, wu):
    observed = wu.ScanJob("observed", "10.0.0.1", {})
    observed.started_at = "2026-01-01T00:00:00Z"
    host = observed.get_or_create_host("10.0.0.1")
    host.update(ports=[{"port": 443}], observed_at=observed.started_at, scan_status="completed")
    failed = wu.ScanJob("failed", "10.0.0.1", {})
    failed.started_at = "2026-01-02T00:00:00Z"
    failed.get_or_create_host("10.0.0.1")["scan_status"] = "error"
    wu._register_scan(observed)
    wu._register_scan(failed)
    hosts = client.get("/api/hosts").get_json()
    assert hosts[0]["ports"] == [{"port": 443}]
    assert hosts[0]["scan_id"] == "observed"
    assert hosts[0]["latest_attempt"]["scan_status"] == "error"


def test_hostname_or_range_scan_records_actual_ips(wu):
    nm = Mock()
    nm.all_hosts.return_value = ["10.0.0.1", "10.0.0.2"]
    data = {ip: {"addresses": {"ipv4": ip}, "tcp": {80: {"state": "open", "name": "http", "product": "", "version": ""}}}
            for ip in nm.all_hosts.return_value}
    nm.__getitem__ = Mock(side_effect=lambda ip: data[ip])
    job = wu.ScanJob("range", "10.0.0.0/24", {"target": "10.0.0.0/24", "skip_discovery": True, "scan_vulns": False})
    with patch("shutil.which", return_value="nmap"), patch("autopwn_suite.scanner.PortScan", return_value=nm), patch.object(wu, "_notify"):
        wu._run_scan(job)
    assert job.status == "completed"
    assert {h["ip"] for h in job.hosts_list()} == set(data)
    assert all(h["ports"][0]["port"] == 80 for h in job.hosts_list())


def test_vulnerability_lookup_failure_is_partial_not_clean(wu):
    nm = Mock()
    nm.all_hosts.return_value = ["10.0.0.1"]
    nm.__getitem__ = Mock(return_value={"addresses": {}, "tcp": {80: {"state": "open", "name": "http", "product": "nginx", "version": "1.0"}}})
    job = wu.ScanJob("lookup", "10.0.0.1", {"target": "10.0.0.1", "skip_discovery": True})
    with patch("shutil.which", return_value="nmap"), patch("autopwn_suite.scanner.PortScan", return_value=nm), \
         patch("autopwn_suite.nist_search.searchCVE", side_effect=RuntimeError("NVD unavailable")), patch.object(wu, "_notify"):
        wu._run_scan(job)
    assert job.status == "partial"
    assert job.hosts_list()[0]["lookup_status"] == "partial"


def test_no_observation_is_partial(wu):
    nm = Mock()
    nm.all_hosts.return_value = []
    nm.__getitem__ = Mock(side_effect=KeyError)
    job = wu.ScanJob("empty", "10.0.0.1", {"target": "10.0.0.1", "skip_discovery": True})
    with patch("shutil.which", return_value="nmap"), patch("autopwn_suite.scanner.PortScan", return_value=nm), patch.object(wu, "_notify"):
        wu._run_scan(job)
    assert job.status == "partial"
    assert job.hosts_list()[0]["scan_status"] == "not_observed"


def test_early_exit_notifies_exactly_once(wu):
    job = wu.ScanJob("missing", "10.0.0.1", {"target": "10.0.0.1"})
    with patch("shutil.which", return_value=None), patch.object(wu, "_notify") as notify:
        wu._run_scan(job)
    notify.assert_called_once_with(job)


def test_bad_job_config_reaches_terminal_error(wu):
    job = wu.ScanJob("bad", "10.0.0.1", {"target": "10.0.0.1", "speed": "invalid"})
    with patch.object(wu, "_notify"):
        wu._run_scan(job)
    assert job.status == "error"
    assert job.finished_at


def test_interrupted_save_preserves_existing_document(wu):
    wu._SETTINGS_FILE.write_text('{"nist_api_key": "previous"}', encoding="utf-8")
    wu._settings = {"nist_api_key": "next"}
    with patch.object(wu.os, "replace", side_effect=OSError("interrupted")):
        with pytest.raises(OSError):
            wu._save_settings()
    assert json.loads(wu._SETTINGS_FILE.read_text(encoding="utf-8")) == {"nist_api_key": "previous"}
    assert not list(wu._DATA_DIR.glob("*.tmp"))


def test_corrupt_settings_are_preserved_for_recovery(wu):
    wu._SETTINGS_FILE.write_text('{"email":', encoding="utf-8")
    wu._load_settings()
    assert wu._settings["email"]["enabled"] is False
    assert wu._SETTINGS_FILE.read_text(encoding="utf-8") == '{"email":'


def test_loaded_settings_do_not_mutate_defaults(wu):
    wu._load_settings()
    wu._settings["email"]["smtp_host"] = "custom"
    assert wu._DEFAULT_SETTINGS["email"]["smtp_host"] == ""


@pytest.mark.parametrize("body", [["bad"], "bad", 7])
def test_nonobject_requests_return_client_error(client, body):
    assert client.post("/api/scan/start", json=body).status_code == 400


@pytest.mark.parametrize("body", [{"target": 7}, {"target": "10.0.0.1", "nmap_flags": ["-sU"]},
                                  {"target": "10.0.0.1", "scan_vulns": "false"},
                                  {"target": "10.0.0.1", "speed": 2.5}])
def test_scan_field_type_errors_return_400(client, body):
    assert client.post("/api/scan/start", json=body).status_code == 400


def test_settings_object_shape_errors_return_400(client):
    assert client.put("/api/settings", json={"email": []}).status_code == 400


def test_slow_event_subscriber_does_not_block_scan_logging(wu):
    import queue
    subscriber = queue.Queue(maxsize=2)
    wu._sse_subscribers.append(subscriber)
    for i in range(4):
        wu._broadcast({"msg": str(i)})
    assert [subscriber.get_nowait()["msg"] for _ in range(2)] == ["2", "3"]
    assert [event["msg"] for event in wu._log_history] == ["0", "1", "2", "3"]


def test_webhook_http_failure_is_reported(client, wu):
    from requests.exceptions import HTTPError
    wu._settings["webhook"] = {"enabled": True, "url": "https://example.invalid/hook", "on_complete": True}
    job = wu.ScanJob("hook", "10.0.0.1", {})
    job.mark_done()
    response = Mock(status_code=500)
    response.raise_for_status.side_effect = HTTPError("500")
    with patch.object(wu._requests, "post", return_value=response):
        wu._send_webhook(job)
        assert client.post("/api/settings/test_webhook").status_code == 500
    assert any("Webhook delivery failed" in entry["msg"] for entry in wu._log_history)


def test_webhook_failures_do_not_leak_the_url_into_the_log_api_or_server_log(client, wu, caplog):
    """The webhook URL is a credential and requests quotes it in its error messages."""
    from requests.exceptions import HTTPError
    url = "https://hooks.example.invalid/services/T000/B000/SECRETTOKEN"
    wu._settings["webhook"] = {"enabled": True, "url": url, "on_complete": True}
    job = wu.ScanJob("hook", "192.0.2.1", {})
    job.mark_done()
    error = HTTPError(f"404 Client Error: Not Found for url: {url}", response=Mock(status_code=404))
    with patch.object(wu._requests, "post", side_effect=error), caplog.at_level("DEBUG"):
        wu._send_webhook(job)
        assert client.post("/api/settings/test_webhook").status_code == 500
    served = client.get("/api/log").get_data(as_text=True)
    assert "Webhook delivery failed: HTTPError (HTTP 404)" in served
    assert "SECRETTOKEN" not in served
    assert "Failed to send test webhook: HTTPError (HTTP 404)" in caplog.text
    assert "SECRETTOKEN" not in caplog.text and "Traceback" not in caplog.text


def test_ssl_email_uses_bounded_connection_for_notification_and_test(client, wu):
    wu._settings["email"] = {"enabled": True, "smtp_host": "mail.example.invalid", "smtp_port": 465,
                             "to_addr": "to@example.invalid", "from_addr": "from@example.invalid", "on_complete": True}
    job = wu.ScanJob("mail", "10.0.0.1", {})
    job.mark_done()
    with patch.object(wu.smtplib, "SMTP_SSL") as ssl, patch.object(wu.smtplib, "SMTP") as plain:
        wu._send_email(job)
        assert client.post("/api/settings/test_email").status_code == 200
        assert ssl.call_count == 2
        assert ssl.call_args.kwargs["timeout"] == 30
        assert ssl.return_value.__enter__.return_value.sendmail.call_count == 2
        ssl.return_value.__enter__.return_value.starttls.assert_not_called()
        plain.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# _NullStatus methods
# ═══════════════════════════════════════════════════════════════════════════════

class TestNullStatus:
    def test_start_stop(self, wu):
        ns = wu._NullStatus()
        ns.start()
        ns.stop()
        ns.update("something")

    def test_context_manager(self, wu):
        ns = wu._NullStatus()
        with ns:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Settings load error path
# ═══════════════════════════════════════════════════════════════════════════════

class TestSettingsLoadError:
    def test_load_corrupted_file(self, wu, tmp_path):
        settings_file = wu._SETTINGS_FILE
        settings_file.write_text("not valid json!!!", encoding="utf-8")
        wu._load_settings()
        # Should fall back to defaults
        assert wu._settings.get("email") is not None

    def test_load_profiles_corrupted(self, wu):
        wu._PROFILES_FILE.write_text("{invalid json", encoding="utf-8")
        wu._load_profiles()
        assert wu._profiles == {}

    def test_load_schedules_corrupted(self, wu):
        wu._SCHEDULES_FILE.write_text("{bad", encoding="utf-8")
        wu._load_schedules()
        assert wu._schedules == {}

    @pytest.mark.parametrize("kind", ["profiles", "schedules"])
    def test_unreadable_file_is_kept_and_logged_before_the_next_save(self, wu, caplog, kind):
        path = getattr(wu, f"_{kind.upper()}_FILE")
        path.write_text("{truncated", encoding="utf-8")
        getattr(wu, f"_load_{kind}")()
        assert getattr(wu, f"_{kind}") == {}
        kept = list(path.parent.glob(path.name + ".corrupt-*"))
        assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == "{truncated"
        assert path.name in caplog.text and kept[0].name in caplog.text
        getattr(wu, f"_save_{kind}")()  # the first save used to destroy the only copy
        assert kept[0].read_text(encoding="utf-8") == "{truncated"

    @pytest.mark.parametrize("kind", ["profiles", "schedules"])
    def test_one_invalid_entry_does_not_drop_the_others(self, wu, caplog, kind):
        path = getattr(wu, f"_{kind.upper()}_FILE")
        original = json.dumps({"a": {"id": "a"}, "b": "not an object", "c": {"id": "c"}})
        path.write_text(original, encoding="utf-8")
        getattr(wu, f"_load_{kind}")()
        assert sorted(getattr(wu, f"_{kind}")) == ["a", "c"]
        kept = list(path.parent.glob(path.name + ".corrupt-*"))
        assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == original
        assert "Skipped 1 invalid entries" in caplog.text and kept[0].name in caplog.text
        getattr(wu, f"_save_{kind}")()
        assert sorted(json.loads(path.read_text(encoding="utf-8"))) == ["a", "c"]
        assert kept[0].read_text(encoding="utf-8") == original

    @pytest.mark.parametrize("kind", ["profiles", "schedules"])
    def test_restarts_do_not_pile_up_copies_of_the_same_partial_file(self, wu, caplog, kind):
        path = getattr(wu, f"_{kind.upper()}_FILE")
        original = json.dumps({"a": {"id": "a"}, "b": "not an object"})
        path.write_text(original, encoding="utf-8")
        earlier = path.with_name(path.name + ".corrupt-20200101T000000Z")
        earlier.write_text(original, encoding="utf-8")  # kept by a previous start
        getattr(wu, f"_load_{kind}")()
        assert sorted(getattr(wu, f"_{kind}")) == ["a"]
        assert list(path.parent.glob(path.name + ".corrupt-*")) == [earlier]
        assert f"already kept as {earlier.name}" in caplog.text
        # A different file, though, is copied: nothing a person edited is ever left unkept.
        path.write_text(json.dumps({"a": {"id": "a"}, "c": 3}), encoding="utf-8")
        getattr(wu, f"_load_{kind}")()
        assert len(list(path.parent.glob(path.name + ".corrupt-*"))) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Email with duplicate -O flag dedup
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailFlagDedup:
    def test_email_dedup_os_flag(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        # nmap_flags contains -O which is also in cmd_base
        job = wu.ScanJob("id1", "target", {
            "mode": "normal", "speed": 3, "host_timeout": 240,
            "nmap_flags": "-O -p 80"
        })
        job.mark_done()
        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# Email vuln_found trigger
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailVulnTrigger:
    def test_email_sends_on_vuln_found(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": False, "on_error": False, "on_vuln_found": True,
        }
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        h = job.get_or_create_host("10.0.0.1")
        h["vulns"] = [{"cve": "CVE-2024-0001"}]
        job.mark_done()
        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()

    def test_email_sends_on_error(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "u", "password": "p", "from_addr": "f@t.com",
            "to_addr": "t@t.com",
            "on_complete": False, "on_error": True, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        job.mark_error("something broke")
        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# Email with no auth credentials
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailNoAuth:
    def test_email_no_username_password(self, wu):
        wu._load_settings()
        wu._settings["email"] = {
            "enabled": True, "smtp_host": "smtp.test.com", "smtp_port": 587,
            "username": "", "password": "",
            "from_addr": "f@t.com", "to_addr": "t@t.com",
            "on_complete": True, "on_error": False, "on_vuln_found": False,
        }
        job = wu.ScanJob("id1", "target", {"mode": "normal", "speed": 3, "host_timeout": 240})
        job.mark_done()
        mock_srv = MagicMock()
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__ = Mock(return_value=mock_srv)
            mock_smtp.return_value.__exit__ = Mock(return_value=False)
            wu._send_email(job)
            mock_srv.sendmail.assert_called_once()
            mock_srv.login.assert_not_called()
