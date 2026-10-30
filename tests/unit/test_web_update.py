# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The dashboard's update check and self-update routes, with GitHub and git mocked."""
import importlib
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from autopwn_suite import update_checker as uc
from tests.auth_helpers import authenticated_app

STATUS = uc.UpdateStatus("release", "x/y", "2.8.0", "v2.9.0", "https://github.com/x/y/releases/tag/v2.9.0", True)
UPDATED = uc.UpdateResult("release", "x/y", "a" * 12, "b" * 12, "v2.9.0")
UNCHANGED = uc.UpdateResult("release", "x/y", "b" * 12, "b" * 12, "v2.9.0")


@pytest.fixture
def web(monkeypatch, tmp_path):
    pytest.importorskip("flask")
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))  # the saved update channel
    wu = importlib.import_module("autopwn_suite.web_ui")
    monkeypatch.setattr(wu, "__version__", "2.8.0", raising=False)  # set when the dashboard starts
    monkeypatch.setattr(wu, "_OFFLINE_ONLY", False)
    monkeypatch.setattr(wu, "_settings", {})
    monkeypatch.setattr(wu, "_SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(wu, "_scans", {})
    monkeypatch.setattr(wu, "_database_update", {"running": False, "message": "", "current": 0, "total": 0, "error": None})
    monkeypatch.setattr(wu, "_app_update", {"running": None, "checked_at": None, "status": None, "error": None,
                                            "error_code": None, "result": None})
    monkeypatch.setattr(wu, "_start_commit", "a" * 40)  # recorded when the dashboard starts
    monkeypatch.setattr(wu, "_update_hold_logged", False)
    monkeypatch.setattr(uc, "current_commit", lambda: "a" * 40)
    monkeypatch.setattr(wu, "_start_version", None)
    monkeypatch.setattr(uc, "install_method", lambda: "checkout")
    for name in ("check_for_updates", "apply_update"):
        monkeypatch.setattr(uc, name, lambda *a, **k: pytest.fail("contacted GitHub or ran git"))
    app = authenticated_app(wu)
    return wu, app.test_client()


def test_reading_the_update_status_contacts_neither_github_nor_git(web):
    _wu, client = web
    status = client.get("/api/update").get_json()
    assert status["channel"] == "release"
    assert status["checkout"] is True
    assert status["checked_at"] is None and status["status"] is None
    assert status["restart_required"] is False and status["offline_only"] is False


def test_a_check_stores_the_result_and_remembers_the_channel(web, monkeypatch):
    _wu, client = web
    check = MagicMock(return_value=STATUS)
    monkeypatch.setattr(uc, "check_for_updates", check)
    response = client.post("/api/update/check", json={"channel": "commit"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"]["update_available"] is True and body["status"]["latest"] == "v2.9.0"
    assert body["checked_at"] and body["error"] is None
    assert check.call_args.kwargs == {"channel": "commit", "branch": "main"}
    assert client.get("/api/update").get_json()["channel"] == "commit"


def test_a_check_without_a_channel_uses_the_saved_one(web, monkeypatch):
    _wu, client = web
    uc.resolve_update_channel("commit")
    check = MagicMock(return_value=STATUS)
    monkeypatch.setattr(uc, "check_for_updates", check)
    assert client.post("/api/update/check").status_code == 200
    assert check.call_args.kwargs["channel"] == "commit"


def test_the_request_cannot_choose_the_repository_or_branch(web, monkeypatch):
    _wu, client = web
    check, apply = MagicMock(return_value=STATUS), MagicMock(return_value=UPDATED)
    monkeypatch.setattr(uc, "check_for_updates", check)
    monkeypatch.setattr(uc, "apply_update", apply)
    body = {"channel": "commit", "repo": "attacker/fork", "branch": "pull/1/head"}
    assert client.post("/api/update/check", json=body).status_code == 200
    assert client.post("/api/update/apply", json=body).status_code == 200
    assert check.call_args.kwargs == {"channel": "commit", "branch": "main"}
    assert apply.call_args.kwargs == {"channel": "commit", "branch": "main"}


@pytest.mark.parametrize("channel", ["nightly", "", 1, True, ["release"], {"x": 1}])
def test_an_unknown_channel_is_refused_before_any_check_or_apply(web, channel):
    _wu, client = web
    for route in ("/api/update/check", "/api/update/apply"):
        response = client.post(route, json={"channel": channel})
        assert response.status_code == 400
        assert response.get_json()["code"] == "invalid_update_channel"
    assert client.get("/api/update").get_json()["channel"] == "release"


def test_a_failed_check_reports_fixed_text_and_is_not_left_running(web, monkeypatch):
    wu, client = web
    error = uc.UpdateCheckError("proxy http://user:hunter2@proxy.test refused", "update_unreachable")
    monkeypatch.setattr(uc, "check_for_updates", MagicMock(side_effect=error))
    body = client.post("/api/update/check").get_json()
    assert body["error_code"] == "update_unreachable"
    assert body["error"] == wu._APP_UPDATE_ERRORS["update_unreachable"]
    assert body["checked_at"] and body["status"] is None and body["running"] is None
    assert "hunter2" not in str(body)


def test_an_error_without_a_known_code_gets_the_generic_text(web, monkeypatch):
    _wu, client = web
    monkeypatch.setattr(uc, "apply_update", MagicMock(side_effect=uc.UpdateCheckError("private /home/path")))
    response = client.post("/api/update/apply")
    assert response.status_code == 409
    assert response.get_json() == {"error": "Could not apply the update.", "code": "update_failed"}


def test_every_update_error_code_has_fixed_text():
    import inspect
    import re
    codes = set(re.findall(r'"(update_[a-z_]+)"', inspect.getsource(uc))) - {"update_failed"}
    wu = importlib.import_module("autopwn_suite.web_ui")
    assert codes and codes <= set(wu._APP_UPDATE_ERRORS), sorted(codes - set(wu._APP_UPDATE_ERRORS))


def test_the_dashboard_translates_every_update_error_code():
    import inspect
    import re
    from pathlib import Path
    wu = importlib.import_module("autopwn_suite.web_ui")
    source = inspect.getsource(wu)
    routes = set(re.findall(r'"code": "((?:update|invalid_update|offline_blocked_app)_[a-z_]*)"', source))
    dictionary = (Path(wu.__file__).parent / "web_ui_static" / "i18n.js").read_text(encoding="utf-8")
    codes = set(wu._APP_UPDATE_ERRORS) | routes | {"update_failed", "update_in_progress", "update_restart_required"}
    assert len(routes) >= 6
    assert not [code for code in sorted(codes) if f"'err.{code}':" not in dictionary]


def test_an_applied_update_asks_for_a_restart_that_a_later_no_op_does_not_clear(web, monkeypatch):
    _wu, client = web

    def apply(**kwargs):
        monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
        return UPDATED
    monkeypatch.setattr(uc, "apply_update", apply)
    body = client.post("/api/update/apply", json={"channel": "release"}).get_json()
    assert body["restart_required"] is True
    assert body["result"] == {"mode": "release", "repo": "x/y", "previous": "a" * 12, "new": "b" * 12,
                              "ref": "v2.9.0", "dependencies_changed": False, "changed": True}
    monkeypatch.setattr(uc, "apply_update", MagicMock(return_value=UNCHANGED))
    body = client.post("/api/update/apply").get_json()
    assert body["result"]["changed"] is False
    assert body["restart_required"] is True


def test_applying_with_nothing_new_does_not_ask_for_a_restart(web, monkeypatch):
    _wu, client = web
    monkeypatch.setattr(uc, "apply_update", MagicMock(return_value=UNCHANGED))
    body = client.post("/api/update/apply").get_json()
    assert body["running"] is None and body["restart_required"] is False


def test_a_refused_apply_returns_the_code_and_fixed_text(web, monkeypatch):
    wu, client = web
    error = uc.UpdateCheckError("Working tree has uncommitted changes in /home/me/secret", "update_dirty_worktree")
    monkeypatch.setattr(uc, "apply_update", MagicMock(side_effect=error))
    response = client.post("/api/update/apply")
    assert response.status_code == 409
    assert response.get_json() == {"error": wu._APP_UPDATE_ERRORS["update_dirty_worktree"], "code": "update_dirty_worktree"}
    assert client.get("/api/update").get_json()["running"] is None


@pytest.mark.parametrize("busy, code", [
    ("scan", "update_blocked_scans"),
    ("verification", "update_blocked_verifications"),
    ("database", "update_blocked_db_update"),
    ("update", "update_already_running"),
])
def test_apply_waits_for_running_work(web, monkeypatch, busy, code):
    wu, client = web
    if busy == "scan":
        wu._scans["s"] = MagicMock(status="running")
    elif busy == "verification":
        monkeypatch.setattr(wu, "_web_verifications_running", 1)
    elif busy == "database":
        wu._database_update["running"] = True
    else:
        wu._app_update["running"] = "check"
    response = client.post("/api/update/apply")
    assert response.status_code == 409
    assert response.get_json()["code"] == code


def test_a_check_may_run_during_a_scan_but_not_during_another_check(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(uc, "check_for_updates", MagicMock(return_value=STATUS))
    wu._scans["s"] = MagicMock(status="running")
    assert client.post("/api/update/check").status_code == 200
    wu._app_update["running"] = "apply"
    assert client.post("/api/update/check").get_json()["code"] == "update_already_running"


def test_offline_mode_cannot_be_enabled_during_an_update(web):
    wu, client = web
    wu._app_update["running"] = "apply"
    response = client.put("/api/settings", json={"offline_mode": True})
    assert response.status_code == 409
    assert response.get_json()["code"] == "offline_blocked_app_update"


def test_a_checkout_moved_outside_the_dashboard_also_asks_for_a_restart(web, monkeypatch):
    _wu, client = web
    monkeypatch.setattr(uc, "current_commit", lambda: "c" * 40)  # --apply-update or a git pull meanwhile
    assert client.get("/api/update").get_json()["restart_required"] is True


def test_a_dashboard_not_started_from_a_checkout_never_asks_for_a_restart(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_start_commit", None)
    monkeypatch.setattr(uc, "current_commit", lambda: None)
    status = client.get("/api/update").get_json()
    assert status["restart_required"] is False and status["checkout"] is False


def test_the_dependency_flag_of_an_applied_update_reaches_the_page(web, monkeypatch):
    _wu, client = web
    changed = uc.UpdateResult("release", "x/y", "a" * 12, "b" * 12, "v2.9.0", dependencies_changed=True)
    monkeypatch.setattr(uc, "apply_update", MagicMock(return_value=changed))
    assert client.post("/api/update/apply").get_json()["result"]["dependencies_changed"] is True


def _stub_replayable_plan(monkeypatch):
    """Patch the modules the verify route imports at call time (sys.modules), not a stale package attribute."""
    monkeypatch.setattr(importlib.import_module("autopwn_suite.web.poc"), "build_plan", lambda finding: {"replayable": True})
    monkeypatch.setattr(importlib.import_module("autopwn_suite.web.poc_runtime"), "validate_plan", lambda plan: None)


def _start_scan(client):
    return client.post("/api/scan/start", json={"target": "192.0.2.10"})


def _resume_scan(client):
    return client.post("/api/scans/held/resume", json={})


def _verify_finding(client):
    return client.post("/api/web/findings/held/f1/verify", json={})


@pytest.mark.parametrize("request_run", [_start_scan, _resume_scan, _verify_finding])
@pytest.mark.parametrize("state, code", [("restart", "update_restart_required"), ("applying", "update_in_progress")])
def test_new_runs_wait_for_an_update_to_finish_and_for_the_restart(web, monkeypatch, request_run, state, code):
    wu, client = web
    if state == "restart":
        monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
    else:
        wu._app_update["running"] = "apply"
    wu._scans["held"] = MagicMock(status="stopped", web_finding=lambda finding_id: {"id": finding_id})
    _stub_replayable_plan(monkeypatch)
    monkeypatch.setattr(wu, "_register_scan", lambda job: pytest.fail("started a scan"))
    monkeypatch.setattr(wu.threading, "Thread", lambda *a, **k: pytest.fail("started a run"))
    response = request_run(client)
    assert response.status_code == 409
    assert response.get_json()["code"] == code


def test_scans_start_again_once_nothing_holds_them(web, monkeypatch):
    wu, client = web
    launch = MagicMock(return_value=MagicMock(id="s"))
    monkeypatch.setattr(wu, "_launch_scan", launch)
    assert _start_scan(client).status_code == 200
    launch.assert_called_once()


def test_scheduled_scans_are_postponed_with_one_log_line_until_the_hold_ends(web, monkeypatch):
    wu, _client = web
    notes = []
    monkeypatch.setattr(wu, "_scheduler_note", lambda level, message: notes.append(message))
    monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
    assert wu._scheduler_update_hold() is True
    assert wu._scheduler_update_hold() is True
    assert len(notes) == 1 and "Restart the dashboard" in notes[0]
    monkeypatch.setattr(uc, "current_commit", lambda: "a" * 40)
    assert wu._scheduler_update_hold() is False
    monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
    assert wu._scheduler_update_hold() is True
    assert len(notes) == 2


def test_the_scheduler_logs_again_when_an_applied_update_turns_into_a_pending_restart(web, monkeypatch):
    wu, _client = web
    notes = []
    monkeypatch.setattr(wu, "_scheduler_note", lambda level, message: notes.append(message))
    wu._app_update["running"] = "apply"
    assert wu._scheduler_update_hold() and wu._scheduler_update_hold()
    wu._app_update["running"] = None
    monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
    assert wu._scheduler_update_hold()
    assert len(notes) == 2 and "Wait for the update" in notes[0] and "Restart the dashboard" in notes[1]


def test_a_scan_cannot_start_once_an_apply_holds_the_mode_lock(web, monkeypatch):
    wu, _client = web
    monkeypatch.setattr(wu, "_register_scan", lambda job: pytest.fail("registered a scan during an apply"))
    wu._app_update["running"] = "apply"
    with pytest.raises(wu._UpdateHeld) as held:
        wu._launch_scan({"target": "192.0.2.10"})
    assert held.value.args[0] == "update_in_progress"


def test_a_settings_file_with_a_non_boolean_auto_check_is_set_aside(web, monkeypatch):
    wu, _client = web
    wu._SETTINGS_FILE.write_text('{"update_auto_check": 0}', encoding="utf-8")
    wu._load_settings()
    assert wu._settings.get("update_auto_check") is True  # the defaults, not the hand-edited 0


def _run_scheduler_once(wu, monkeypatch):
    """One pass of the scheduler over a schedule that is due and valid; returns the scans it launched."""
    launched = []
    monkeypatch.setattr(wu, "_scheduler_note", lambda *a: None)
    monkeypatch.setattr(wu, "_should_fire", lambda s: True)
    monkeypatch.setattr(wu, "_profiles", {"p1": {"id": "p1", "name": "Quick", "config": {}}})
    monkeypatch.setattr(wu, "_schedules", {"s1": {"id": "s1", "name": "Nightly", "target": "192.0.2.10",
                                                   "profile_id": "p1", "enabled": True, "type": "interval",
                                                   "interval_value": 1, "interval_unit": "hours"}})
    monkeypatch.setattr(wu, "_schedule_last_run", {})
    monkeypatch.setattr(wu, "_schedule_jobs", {})
    monkeypatch.setattr(wu, "_save_schedules", lambda: None)
    monkeypatch.setattr(wu, "_register_scan", lambda job: launched.append(job))
    monkeypatch.setattr(wu.threading, "Thread", MagicMock())
    monkeypatch.setattr(wu.time, "sleep", MagicMock(side_effect=[None, SystemExit]))
    with pytest.raises(SystemExit):
        wu._scheduler_loop()
    return launched


def test_a_due_schedule_runs_when_nothing_holds_it(web, monkeypatch):
    wu, _client = web
    assert len(_run_scheduler_once(wu, monkeypatch)) == 1
    assert "s1" in wu._schedule_last_run


@pytest.mark.parametrize("state", ["restart", "applying"])
def test_a_postponed_schedule_stays_due(web, monkeypatch, state):
    wu, _client = web
    if state == "restart":
        monkeypatch.setattr(uc, "current_commit", lambda: "b" * 40)
    else:
        wu._app_update["running"] = "apply"
    assert _run_scheduler_once(wu, monkeypatch) == []
    assert "s1" not in wu._schedule_last_run and wu._schedules["s1"]["enabled"] is True


def test_a_schedule_is_not_launched_when_an_apply_starts_after_the_scheduler_looked(web, monkeypatch):
    wu, _client = web
    checks = iter([None, ("update_in_progress", "Wait for the update to finish before starting scans or verifications.")])
    monkeypatch.setattr(wu, "_update_hold", lambda: next(checks, None))
    logged = []
    monkeypatch.setattr(wu, "_broadcast", lambda entry: logged.append(entry))
    monkeypatch.setattr(wu.logging, "exception", lambda *a, **k: pytest.fail("the hold was handled as a failed scheduled scan"))
    assert _run_scheduler_once(wu, monkeypatch) == []
    assert "s1" not in wu._schedule_last_run
    assert not [entry for entry in logged if entry.get("level") == "error"]


def test_automatic_checks_follow_the_setting_and_manual_checks_always_work(web, monkeypatch):
    _wu, client = web
    check = MagicMock(return_value=STATUS)
    monkeypatch.setattr(uc, "check_for_updates", check)
    assert client.get("/api/update").get_json()["auto_check"] is True
    assert client.post("/api/update/check", json={"automatic": True}).status_code == 200
    assert client.put("/api/settings", json={"update_auto_check": False}).status_code == 200
    assert client.get("/api/update").get_json()["auto_check"] is False
    response = client.post("/api/update/check", json={"automatic": True})
    assert response.status_code == 409 and response.get_json()["code"] == "update_auto_check_off"
    assert check.call_count == 1
    assert client.post("/api/update/check", json={"channel": "release"}).status_code == 200
    assert check.call_count == 2


@pytest.mark.parametrize("value", ["false", 0, 1, None, [], {}])
def test_the_auto_check_setting_must_be_a_boolean(web, value):
    _wu, client = web
    response = client.put("/api/settings", json={"update_auto_check": value})
    assert response.status_code == 400
    assert response.get_json()["code"] == "invalid_update_auto_check_type"


@pytest.mark.parametrize("body", [{"automatic": "yes"}, {"automatic": 1}, {"automatic": None}])
def test_the_automatic_flag_must_be_a_boolean(web, body):
    _wu, client = web
    assert client.post("/api/update/check", json=body).status_code == 400


def test_an_apply_cannot_be_automatic(web):
    _wu, client = web
    response = client.post("/api/update/apply", json={"automatic": True})
    assert response.status_code == 400 and response.get_json()["code"] == "invalid_update_channel"


class _ApplyClaimedWhileWaiting:
    """Stands in for _mode_lock: an apply is claimed by the time the request gets the lock, as when the request
    waited for it, so only a hold read inside the lock sees it."""

    def __init__(self, wu):
        self.wu, self.lock = wu, threading.RLock()

    def __enter__(self):
        self.lock.acquire()
        self.wu._app_update["running"] = "apply"
        return self

    def __exit__(self, *exc):
        self.lock.release()


@pytest.mark.parametrize("request_run", [_resume_scan, _verify_finding])
def test_resume_and_verify_read_the_hold_inside_the_mode_lock(web, monkeypatch, request_run):
    wu, client = web
    wu._scans["held"] = MagicMock(status="stopped", web_finding=lambda finding_id: {"id": finding_id},
                                  _lock=threading.RLock(), _web_findings={"f1": {}})
    _stub_replayable_plan(monkeypatch)
    monkeypatch.setattr(wu, "_mode_lock", _ApplyClaimedWhileWaiting(wu))
    monkeypatch.setattr(wu.threading, "Thread", lambda *a, **k: pytest.fail("started a run during an apply"))
    response = request_run(client)
    assert response.status_code == 409 and response.get_json()["code"] == "update_in_progress"


def test_an_automatic_check_is_due_only_six_hours_after_the_last_by_the_server_clock(web, monkeypatch):
    wu, client = web
    check = MagicMock(return_value=STATUS)
    monkeypatch.setattr(uc, "check_for_updates", check)
    assert client.get("/api/update").get_json()["check_due"] is True
    assert client.post("/api/update/check", json={"automatic": True}).status_code == 200
    assert client.get("/api/update").get_json()["check_due"] is False
    response = client.post("/api/update/check", json={"automatic": True})
    assert response.status_code == 409 and response.get_json()["code"] == "update_not_due"
    assert check.call_count == 1
    assert client.post("/api/update/check", json={"channel": "release"}).status_code == 200  # a click always checks
    wu._app_update["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=6, minutes=1)).isoformat()
    assert client.get("/api/update").get_json()["check_due"] is True
    assert client.post("/api/update/check", json={"automatic": True}).status_code == 200
    assert check.call_count == 3


def test_no_check_is_due_while_automatic_checks_are_off(web):
    _wu, client = web
    assert client.put("/api/settings", json={"update_auto_check": False}).status_code == 200
    assert client.get("/api/update").get_json()["check_due"] is False


def test_an_automatic_check_that_another_finished_meanwhile_is_not_run_again(web, monkeypatch):
    wu, client = web
    calls = []

    def finish_another_check_first(*args, **kwargs):
        # Another tab's check ran between this request's early due test and its claim.
        wu._app_update["checked_at"] = datetime.now(timezone.utc).isoformat()
        return True
    monkeypatch.setattr(wu, "_auto_check_due", finish_another_check_first)
    monkeypatch.setattr(uc, "check_for_updates", lambda *a, **k: calls.append(k) or STATUS)
    response = client.post("/api/update/check", json={"automatic": True})
    assert response.status_code == 409 and response.get_json()["code"] == "update_not_due"
    assert not calls and wu._app_update["running"] is None



def test_the_page_learns_how_this_copy_updates(web, monkeypatch):
    _wu, client = web
    status = client.get("/api/update").get_json()
    assert (status["install_method"], status["can_apply"], status["update_command"]) == (
        "checkout", True, "autopwn-suite --apply-update")
    monkeypatch.setattr(uc, "install_method", lambda: "docker")
    status = client.get("/api/update").get_json()
    assert (status["install_method"], status["can_apply"], status["update_command"]) == (
        "docker", False, "docker compose pull && docker compose up -d")


def test_a_package_installation_applies_from_the_dashboard(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(uc, "install_method", lambda: "pipx")
    monkeypatch.setattr(uc, "can_apply", lambda method: True)
    monkeypatch.setattr(wu, "_as_root", lambda: False)
    assert client.get("/api/update").get_json()["can_apply"] is True
    calls = []
    result = uc.UpdateResult("release", "x/y", "2.8.0", "9.9.9", "v9.9.9")
    monkeypatch.setattr(uc, "apply_update", lambda **k: calls.append(k) or result)
    status = client.post("/api/update/apply", json={}).get_json()
    assert calls and status["result"]["new"] == "9.9.9" and status["result"]["changed"] is True


def test_the_dashboard_never_runs_a_package_manager_as_root(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(uc, "install_method", lambda: "pip")
    monkeypatch.setattr(uc, "can_apply", lambda method: True)
    monkeypatch.setattr(wu, "_as_root", lambda: True)
    status = client.get("/api/update").get_json()
    assert status["can_apply"] is False and status["update_command"] == "sudo autopwn-suite --apply-update"
    response = client.post("/api/update/apply", json={})
    assert response.status_code == 409 and response.get_json()["code"] == "update_needs_cli"
    assert wu._app_update["running"] is None


def test_a_package_updated_under_the_dashboard_asks_for_a_restart(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_start_commit", None)
    monkeypatch.setattr(uc, "current_commit", lambda: None)
    monkeypatch.setattr(wu, "_start_version", "2.8.0")
    monkeypatch.setattr(uc, "installed_version", lambda: "2.8.0")
    assert client.get("/api/update").get_json()["restart_required"] is False
    monkeypatch.setattr(uc, "installed_version", lambda: "9.9.9")  # pipx upgrade from here or a terminal
    assert client.get("/api/update").get_json()["restart_required"] is True
