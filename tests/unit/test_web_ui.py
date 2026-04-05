"""Tests for the web UI module."""
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

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

    import modules.web_ui as wu

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


@pytest.fixture
def app(wu):
    """Create a Flask test app."""
    # Ensure Flask globals are available in the re-imported module
    from flask import Flask, Response, jsonify, request, send_from_directory
    from flask_cors import CORS
    wu.Flask = Flask
    wu.Response = Response
    wu.jsonify = jsonify
    wu.request = request
    wu.send_from_directory = send_from_directory
    wu.CORS = CORS
    wu.FLASK_AVAILABLE = True

    wu._load_settings()
    static_dir = Path(__file__).parent.parent.parent / "modules" / "web_ui_static"
    wu.__version__ = "test"
    flask_app = wu._build_app(static_dir)
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


class TestValidateNmapFlags:
    def test_empty_flags(self, wu):
        assert wu._validate_nmap_flags("") is None

    def test_valid_flags(self, wu):
        assert wu._validate_nmap_flags("-sS -sV -O -T 4") is None

    def test_valid_port_range(self, wu):
        assert wu._validate_nmap_flags("-p 1-1000 --version-intensity 3") is None

    def test_shell_injection(self, wu):
        assert wu._validate_nmap_flags("-sS; rm -rf /") is not None

    def test_pipe_injection(self, wu):
        assert wu._validate_nmap_flags("-sV | cat /etc/passwd") is not None


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

    def test_custom_flags(self, wu):
        result = wu._build_nmap_flags({"nmap_flags": "--script banner"})
        assert "--script banner" in result

    def test_all_combined(self, wu):
        result = wu._build_nmap_flags({
            "scan_technique": "-sW",
            "ports": "80-443",
            "version_intensity": 3,
            "os_detection": True,
            "nmap_flags": "--script banner",
        })
        assert "-sW" in result
        assert "-p 80-443" in result
        assert "--version-intensity 3" in result
        assert "-O" in result
        assert "--script banner" in result


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
            wu._schedule_last_run["s1"] = datetime.utcnow()
        assert not wu._should_fire(sched)

    def test_interval_elapsed(self, wu):
        sched = {"id": "s1", "enabled": True, "type": "interval",
                 "interval_unit": "minutes", "interval_value": 5}
        with wu._schedule_last_run_lock:
            wu._schedule_last_run["s1"] = datetime.utcnow() - timedelta(minutes=10)
        assert wu._should_fire(sched)

    def test_daily_wrong_time(self, wu):
        now = datetime.utcnow()
        wrong_hour = (now.hour + 2) % 24
        sched = {"id": "s1", "enabled": True, "type": "daily",
                 "time_utc": f"{wrong_hour:02d}:00"}
        assert not wu._should_fire(sched)

    def test_daily_already_ran_today(self, wu):
        now = datetime.utcnow()
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
        now = datetime.utcnow()
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

    def test_start_scan_invalid_flags(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "nmap_flags": "; whoami"}),
                           content_type="application/json")
        assert resp.status_code == 400

    def test_start_scan_negative_timeout(self, client):
        resp = client.post("/api/scan/start",
                           data=json.dumps({"target": "192.168.1.1", "host_timeout": -1}),
                           content_type="application/json")
        assert resp.status_code == 400

    @patch("modules.web_ui._launch_scan")
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
                               "nmap_flags": "--script banner",
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
             patch("modules.web_ui.is_root", return_value=False, create=True), \
             patch("modules.scanner.DiscoverHosts", return_value=[]):
            # Need to mock the imports that happen inside _run_scan
            import modules.utils as mu
            with patch.object(mu, "is_root", return_value=False, create=True):
                wu._run_scan(job)
        assert job.status == "completed"

    def test_run_scan_stopped_by_user(self, wu):
        job = wu.ScanJob("id1", "target", {"target": "192.168.1.1", "mode": "normal", "speed": 3, "host_timeout": 240})
        wu._register_scan(job)
        job.request_stop()  # Pre-stop
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            wu._run_scan(job)
        assert job.status in ("completed", "stopping")

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
             patch("modules.scanner.PortScan", return_value=mock_nm), \
             patch("modules.scanner.AnalyseScanResults", return_value=[]):
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
             patch("modules.scanner.PortScan", side_effect=Exception("nmap error")):
            wu._run_scan(job)
        assert job.status == "completed"
        assert any("Port scan failed" in e.get("msg", "") for e in wu._log_history)

    def test_run_scan_system_exit(self, wu):
        job = wu.ScanJob("id1", "target", {
            "target": "192.168.1.1", "mode": "normal", "speed": 3,
            "host_timeout": 240, "skip_discovery": True,
            "scan_ports": True, "scan_vulns": False,
        })
        wu._register_scan(job)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("modules.scanner.PortScan", side_effect=SystemExit("nmap not installed")):
            wu._run_scan(job)
        assert job.status == "completed"

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
             patch("modules.scanner.PortScan", return_value=mock_nm), \
             patch("modules.scanner.AnalyseScanResults", return_value=port_array), \
             patch("modules.searchvuln.GenerateKeyword", return_value="nginx 1.0"), \
             patch("modules.nist_search.searchCVE", return_value=[mock_cve]):
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
             patch("modules.scanner.DiscoverHosts", side_effect=Exception("fail")):
            wu._run_scan(job)
        # Should fall back to scanning target directly
        assert job.status == "completed"


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
