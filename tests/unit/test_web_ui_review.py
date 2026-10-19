# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Offline regressions for profile and schedule lifecycle failures."""

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from tests.auth_helpers import authenticated_app


@pytest.fixture
def wu_review(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    path = Path(__file__).parents[2] / "autopwn_suite" / "web_ui.py"
    spec = importlib.util.spec_from_file_location("autopwn_suite.web_ui", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__version__ = "test"
    module._load_settings()
    monkeypatch.setattr(module, "_launch_scan", Mock(return_value=SimpleNamespace(id="offline-job")))
    return module


@pytest.fixture
def client_review(wu_review):
    app = authenticated_app(wu_review)
    app.config["TESTING"] = True
    return app.test_client()


def _profile(client):
    response = client.post("/api/profiles", json={"name": "Offline profile"})
    assert response.status_code == 201
    return response.get_json()["id"]


def _schedule(client, profile_id):
    response = client.post("/api/schedules", json={
        "target": "192.0.2.10", "profile_id": profile_id,
        "type": "interval", "interval_value": 1, "interval_unit": "hours",
    })
    assert response.status_code == 201
    return response.get_json()["id"]


@pytest.mark.parametrize("endpoint", [
    "scan", "profile_create", "profile_update", "schedule_create", "schedule_update",
])
@pytest.mark.parametrize("failure", ["internal_details", "oversized_integer"])
def test_validation_errors_do_not_expose_exception_details(
    client_review, wu_review, monkeypatch, endpoint, failure,
):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    routes = {
        "scan": ("POST", "/api/scan/start", {"target": "192.0.2.10"}),
        "profile_create": ("POST", "/api/profiles", {"name": "Invalid"}),
        "profile_update": ("PUT", f"/api/profiles/{profile_id}", {}),
        "schedule_create": ("POST", "/api/schedules",
                            {"target": "192.0.2.10", "profile_id": profile_id}),
        "schedule_update": ("PUT", f"/api/schedules/{schedule_id}", {}),
    }
    method, path, body = routes[endpoint]
    profiles_before = json.loads(json.dumps(wu_review._profiles))
    schedules_before = json.loads(json.dumps(wu_review._schedules))
    is_schedule = endpoint.startswith("schedule")
    if failure == "internal_details":
        monkeypatch.setattr(
            wu_review, "_schedule_data" if is_schedule else "_profile_config",
            Mock(side_effect=ValueError("/private/config: secret-token-123")),
        )
    else:
        # Exercise an incidental int() exception through the real validators.
        import sys
        limit = sys.get_int_max_str_digits()
        if not limit:
            pytest.skip("Python integer conversion limit is disabled")
        body["interval_value" if is_schedule else "speed"] = "9" * (limit + 1)
    response = client_review.open(path, method=method, json=body)
    assert response.status_code == 400
    expected = "Invalid schedule configuration" if is_schedule else "Invalid scan configuration"
    assert response.get_json() == {"error": expected}
    assert wu_review._profiles == profiles_before
    assert wu_review._schedules == schedules_before
    wu_review._launch_scan.assert_not_called()


class _EndScheduler(BaseException):
    pass


def _one_scheduler_tick(module):
    with patch.object(module.time, "sleep", side_effect=[None, _EndScheduler()]):
        with pytest.raises(_EndScheduler):
            module._scheduler_loop()


def test_profile_preserves_zero_version_intensity(client_review, wu_review):
    response = client_review.post("/api/profiles", json={"name": "No probes", "version_intensity": 0})
    assert response.status_code == 201
    config = response.get_json()["config"]
    assert config["version_intensity"] == 0
    assert "--version-intensity 0" in wu_review._build_nmap_flags(config)


@pytest.mark.parametrize("field,value", [
    ("speed", "bad"), ("speed", 7), ("speed", 2.5),
    ("host_timeout", 0), ("version_intensity", 10),
    ("nmap_flags", ["-sV"]), ("mode", "bad"), ("scan_vulns", "false"),
    ("scan_type", False),
])
def test_profiles_reject_invalid_config_on_create_and_update(client_review, field, value):
    profile_id = _profile(client_review)
    response = client_review.post("/api/profiles", json={"name": "Invalid", field: value})
    assert response.status_code == 400
    response = client_review.put(f"/api/profiles/{profile_id}", json={field: value})
    assert response.status_code == 400


@pytest.mark.parametrize("field,value", [
    ("interval_value", 0), ("interval_value", "bad"), ("interval_unit", "years"),
    ("weekday", 7), ("time_utc", "25:00"), ("type", "bad"),
    ("profile_id", "missing"), ("target", "192.0.2.10;bad"), ("enabled", "false"),
])
def test_schedule_validation_is_shared_by_create_and_update(client_review, wu_review, field, value):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    original = json.loads(json.dumps(wu_review._schedules[schedule_id]))
    body = {"target": "192.0.2.10", "profile_id": profile_id, field: value}
    assert client_review.post("/api/schedules", json=body).status_code == 400
    assert client_review.put(f"/api/schedules/{schedule_id}", json={field: value}).status_code == 400
    assert wu_review._schedules[schedule_id] == original


def test_invalid_saved_schedule_cannot_starve_healthy_schedule(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    good = wu_review._schedules[schedule_id]
    wu_review._schedules = {
        "broken": {"id": "broken", "enabled": True, "interval_value": "bad"},
        schedule_id: good,
    }
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_called_once()
    assert wu_review._launch_scan.call_args.args[0]["target"] == "192.0.2.10"


def test_deleted_profile_disables_linked_schedules(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    assert client_review.delete(f"/api/profiles/{profile_id}").status_code == 200
    assert wu_review._schedules[schedule_id]["enabled"] is False
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()


def test_missing_saved_profile_does_not_fall_back_to_default_scan(client_review, wu_review):
    profile_id = _profile(client_review)
    _schedule(client_review, profile_id)
    wu_review._profiles.clear()
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()


REFUSED = {"error": "Nmap options are not accepted; use the scan technique, ports and detection settings"}
# What an earlier release accepted and stored: free-text options, among them file and NSE options.
STORED_OPTIONS = ["-sV -oN refused.txt", "--script banner", "--script http-put --script-args http-put.url=/x,http-put.file=/etc/passwd",
                  "-sS", "-p 22", " -T5 "]


@pytest.mark.parametrize("options", STORED_OPTIONS)
def test_stored_profile_with_nmap_options_disables_its_schedule_once_and_saving_it_again_removes_them(
        client_review, wu_review, caplog, options):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._profiles[profile_id]["config"]["nmap_flags"] = options
    for _ in range(3):
        _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()  # the options are neither applied nor dropped silently: nothing scans
    assert schedule_id not in wu_review._schedule_last_run
    assert wu_review._schedules[schedule_id]["enabled"] is False  # disabled once, not retried every minute
    assert json.loads(wu_review._SCHEDULES_FILE.read_text())[schedule_id]["enabled"] is False
    errors = [entry["msg"] for entry in wu_review._log_history if entry["level"] == "error"]
    assert len(errors) == 1 and "holds Nmap options, which the dashboard no longer accepts" in errors[0]
    assert options.strip() not in errors[0]  # the log names the reason, not the options
    assert [record.getMessage() for record in caplog.records if record.levelname == "WARNING"] == [
        f"Scheduled scan disabled after stored Nmap options (schedule '{schedule_id}')"]
    # Saving the profile again is the repair: the form has no options field, so the stored ones are replaced.
    repaired = client_review.put(f"/api/profiles/{profile_id}", json={"name": "Renamed", "scan_technique": "-sT", "ports": "22,80"})
    assert repaired.status_code == 200
    assert repaired.get_json()["config"]["nmap_flags"] == ""
    assert wu_review._profiles[profile_id]["config"]["nmap_flags"] == ""
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()  # repairing the profile does not switch the schedule back on
    assert client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": True}).status_code == 200
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_called_once()
    config = wu_review._launch_scan.call_args.args[0]
    assert config["nmap_flags"] == "-sT -p 22,80"  # built from the structured fields alone


def test_stored_profile_that_a_request_still_sends_options_for_is_refused_not_repaired(client_review, wu_review):
    profile_id = _profile(client_review)
    wu_review._profiles[profile_id]["config"]["nmap_flags"] = "--script banner"
    before = json.loads(json.dumps(wu_review._profiles))
    for options in ("--script banner", "-sV", "x"):
        response = client_review.put(f"/api/profiles/{profile_id}", json={"name": "Renamed", "nmap_flags": options})
        assert (response.status_code, response.get_json()) == (400, REFUSED)
    assert wu_review._profiles == before
    assert client_review.put(f"/api/profiles/{profile_id}", json={"name": "Renamed", "nmap_flags": ""}).status_code == 200
    assert wu_review._profiles[profile_id]["config"]["nmap_flags"] == ""


@pytest.mark.parametrize("flags", [
    "-oN /etc/cron.d/x", "--script=http-fetch", "-sS", "-sS -p 22", "\xe9" + chr(0x4E2D) + chr(0x202E) + "-sS", pytest.param("-sS " * 2000, id="repeated-technique"), pytest.param("A" * 200000, id="200000-characters"),
    "--script http-put --script-args-file=/etc/shadow", "; id", "$(id)"])
def test_profile_routes_refuse_any_nmap_flags_text_with_the_fixed_message(client_review, wu_review, flags):
    profile_id = _profile(client_review)
    before = json.loads(json.dumps(wu_review._profiles))
    created = client_review.post("/api/profiles", json={"name": "Options", "nmap_flags": flags})
    updated = client_review.put(f"/api/profiles/{profile_id}", json={"nmap_flags": flags})
    assert (created.status_code, created.get_json()) == (400, REFUSED)
    assert (updated.status_code, updated.get_json()) == (400, REFUSED)
    assert wu_review._profiles == before
    assert flags[:20] not in json.dumps(created.get_json()) + json.dumps(updated.get_json())


@pytest.mark.parametrize("flags", ["-sS", "--script=banner", "\xe9" + chr(0x4E2D), pytest.param("x" * 5000, id="5000-characters")])
def test_schedule_routes_refuse_nmap_flags_text_too(client_review, wu_review, flags):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    before = json.loads(json.dumps(wu_review._schedules))
    created = client_review.post("/api/schedules", json={"target": "192.0.2.10", "profile_id": profile_id, "nmap_flags": flags})
    updated = client_review.put(f"/api/schedules/{schedule_id}", json={"nmap_flags": flags})
    assert (created.status_code, created.get_json()) == (400, REFUSED)
    assert (updated.status_code, updated.get_json()) == (400, REFUSED)
    assert wu_review._schedules == before
    for blank in ("", "  "):
        assert client_review.put(f"/api/schedules/{schedule_id}", json={"nmap_flags": blank}).status_code == 200


def test_stored_schedule_that_carries_options_is_disabled_when_due_and_an_edit_removes_them(client_review, wu_review, caplog):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._schedules[schedule_id]["nmap_flags"] = "-oN refused.txt"
    for _ in range(2):
        _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()
    assert wu_review._schedules[schedule_id]["enabled"] is False
    assert [record.getMessage() for record in caplog.records if record.levelname == "WARNING"] == [
        f"Scheduled scan disabled after stored Nmap options (schedule '{schedule_id}')"]
    edited = client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": True})
    assert edited.status_code == 200 and "nmap_flags" not in edited.get_json()
    _one_scheduler_tick(wu_review)
    assert wu_review._launch_scan.call_args.args[0]["nmap_flags"] == ""


def _write_stored(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path.read_text(encoding="utf-8")


def test_loading_profiles_saved_with_nmap_options_keeps_them_and_a_copy_of_the_file(wu_review, caplog):
    path = wu_review._PROFILES_FILE
    original = _write_stored(path, {
        "ok": {"id": "ok", "name": "Fine", "config": {"scan_technique": "-sT", "ports": "22,80"}},
        "flags": {"id": "flags", "name": "Flags", "config": {"nmap_flags": "--script banner"}},
        "technique": {"id": "technique", "name": "Technique", "config": {"scan_technique": "-sS --script=banner"}},
        "ports": {"id": "ports", "name": "Ports", "config": {"ports": "22 -oN x"}},
        "shape": {"id": "shape", "name": "Shape", "config": "not an object"},
        "flagtype": {"id": "flagtype", "name": "Type", "config": {"nmap_flags": ["-sV"]}},
        "bare": {"id": "bare", "name": "No config at all"}})
    wu_review._load_profiles()
    assert sorted(wu_review._profiles) == ["bare", "flags", "flagtype", "ok", "ports", "shape", "technique"]  # none dropped
    kept = list(path.parent.glob(path.name + ".corrupt-*"))
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == original
    assert "Kept 5 profile(s)" in caplog.text and kept[0].name in caplog.text
    assert "--script banner" not in caplog.text  # the log carries counts and file names, not their content
    wu_review._load_profiles()  # a restart does not pile up copies of the same file
    assert list(path.parent.glob(path.name + ".corrupt-*")) == kept
    wu_review._save_profiles()
    assert kept[0].read_text(encoding="utf-8") == original


def test_loading_profiles_without_nmap_options_sets_nothing_aside(wu_review, caplog):
    path = wu_review._PROFILES_FILE
    _write_stored(path, {"ok": {"id": "ok", "config": {"scan_technique": "-sU", "ports": "53,161", "nmap_flags": "", "speed": 0}},
                         "blank": {"id": "blank", "config": {"nmap_flags": "  "}}})
    wu_review._load_profiles()
    assert sorted(wu_review._profiles) == ["blank", "ok"]
    assert not list(path.parent.glob(path.name + ".corrupt-*"))
    assert "refuses" not in caplog.text


def test_a_loaded_profile_with_options_cannot_start_a_scan_through_the_scheduler(client_review, wu_review):
    wu_review._PROFILES_FILE.write_text(json.dumps(
        {"p": {"id": "p", "name": "Old", "config": {"nmap_flags": "--script http-put", "scan_technique": "-sT"}}}), encoding="utf-8")
    wu_review._load_profiles()
    schedule = {"id": "s", "name": "Old schedule", "enabled": True, "profile_id": "p", "target": "192.0.2.10",
                "type": "interval", "interval_value": 1, "interval_unit": "hours"}
    wu_review._schedules = {"s": schedule}
    _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()
    assert wu_review._schedules["s"]["enabled"] is False


def test_loading_schedules_that_carry_options_keeps_them_and_a_copy_of_the_file(wu_review, caplog):
    path = wu_review._SCHEDULES_FILE
    original = _write_stored(path, {"a": {"id": "a", "profile_id": "p", "nmap_flags": "--script banner"},
                                    "b": {"id": "b", "profile_id": "p", "nmap_flags": ""},
                                    "c": {"id": "c", "profile_id": "p"}})
    wu_review._load_schedules()
    assert sorted(wu_review._schedules) == ["a", "b", "c"]
    kept = list(path.parent.glob(path.name + ".corrupt-*"))
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == original
    assert "Kept 1 schedule(s)" in caplog.text


def test_naive_saved_last_run_is_restored_as_utc(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._schedules[schedule_id]["last_run"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    wu_review._save_schedules()
    wu_review._schedule_last_run.clear()
    wu_review._load_schedules()
    assert wu_review._schedule_last_run[schedule_id].tzinfo == timezone.utc
    assert not wu_review._should_fire(wu_review._schedules[schedule_id])


def test_scheduler_failure_on_one_launch_does_not_block_next_schedule(client_review, wu_review):
    profile_id = _profile(client_review)
    first = _schedule(client_review, profile_id)
    second = _schedule(client_review, profile_id)
    wu_review._launch_scan.side_effect = [RuntimeError("offline failure"), SimpleNamespace(id="offline-job")]
    _one_scheduler_tick(wu_review)
    assert wu_review._launch_scan.call_count == 2
    assert first not in wu_review._schedule_last_run
    assert second in wu_review._schedule_last_run


def test_deleted_schedule_clears_last_run_cache(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._schedule_last_run[schedule_id] = datetime.now(timezone.utc)
    assert client_review.delete(f"/api/schedules/{schedule_id}").status_code == 200
    assert schedule_id not in wu_review._schedule_last_run


def test_disable_after_scheduler_snapshot_prevents_stale_launch(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)

    def disable_after_due_check(schedule):
        wu_review._schedules[schedule_id]["enabled"] = False
        return True

    with patch.object(wu_review, "_should_fire", side_effect=disable_after_due_check):
        _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()


@pytest.mark.parametrize("state", ["running", "stopping"])
def test_schedule_waits_for_its_own_unfinished_scan_and_logs_the_skip_once(client_review, wu_review, state):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    job = wu_review.ScanJob("first-run", "192.0.2.10", {})
    wu_review._register_scan(job)
    wu_review._launch_scan.return_value = SimpleNamespace(id="first-run")

    def due_again():
        wu_review._schedule_last_run[schedule_id] = datetime.now(timezone.utc) - timedelta(hours=2)

    _one_scheduler_tick(wu_review)
    assert wu_review._launch_scan.call_count == 1
    if state == "stopping":
        job.request_stop()
    for _ in range(3):  # three due ticks while the first scan is still unfinished
        due_again()
        _one_scheduler_tick(wu_review)
    assert wu_review._launch_scan.call_count == 1
    skips = [entry["msg"] for entry in wu_review._log_history if "previous scan is still running" in entry["msg"]]
    assert len(skips) == 1
    # Not every schedule starts when the scan ends: a daily or weekly slot is dropped after the catch-up window.
    assert "within an hour of its time, otherwise at its next time" in skips[0]
    job.mark_done("stopped")
    due_again()
    _one_scheduler_tick(wu_review)  # the finished scan no longer blocks the schedule
    assert wu_review._launch_scan.call_count == 2


def test_profile_edit_disables_the_schedules_it_no_longer_fits(client_review, wu_review, caplog):
    profile_id = _profile(client_review)
    cidr = client_review.post("/api/schedules", json={"target": "192.0.2.0/24", "profile_id": profile_id}).get_json()["id"]
    host = client_review.post("/api/schedules", json={"target": "example.test", "profile_id": profile_id}).get_json()["id"]
    # The schedules file loads any object, so a hand-edited name need not be a string.
    wu_review._schedules["edited"] = {"id": "edited", "enabled": True, "profile_id": profile_id, "name": 5,
                                      "target": "example.test", "type": "interval"}
    response = client_review.put(f"/api/profiles/{profile_id}", json={"scan_web": True, "scan_ports": False})
    assert response.status_code == 200
    # A CIDR range is not a web target, so that schedule would fail on every check; the other one still fits.
    assert wu_review._schedules[cidr]["enabled"] is False and wu_review._schedules[host]["enabled"] is True
    assert wu_review._schedules["edited"]["enabled"] is False
    assert json.loads(wu_review._SCHEDULES_FILE.read_text())[cidr]["enabled"] is False
    notices = [entry["msg"] for entry in wu_review._log_history if "Disabled after a profile edit" in entry["msg"]]
    assert len(notices) == 1 and f"{cidr[:8]}, 5." in notices[0]
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert [record.getMessage() for record in warnings] == [
        f"Scheduled scan disabled after a profile edit (schedule '{cidr}')",
        "Scheduled scan disabled after a profile edit (schedule 'edited')"]
    _one_scheduler_tick(wu_review)
    assert [call.args[0]["target"] for call in wu_review._launch_scan.call_args_list] == ["example.test"]


def test_schedule_that_fails_validation_is_disabled_instead_of_erroring_every_minute(client_review, wu_review, caplog):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._schedules[schedule_id]["target"] = "192.0.2.10;bad"
    for _ in range(3):
        _one_scheduler_tick(wu_review)
    wu_review._launch_scan.assert_not_called()
    assert wu_review._schedules[schedule_id]["enabled"] is False
    assert json.loads(wu_review._SCHEDULES_FILE.read_text())[schedule_id]["enabled"] is False
    errors = [entry["msg"] for entry in wu_review._log_history if entry["level"] == "error"]
    assert len(errors) == 1 and "disabled" in errors[0]
    # The server log (the only record for a headless daemon) names the schedule but carries no exception text.
    assert [record.getMessage() for record in caplog.records if record.levelname == "WARNING"] == [
        f"Scheduled scan disabled after a validation failure (schedule '{schedule_id}')"]


def test_a_value_error_from_launching_does_not_disable_the_schedule(client_review, wu_review, caplog):
    """Only a failed validation repeats until someone edits the schedule; a launch that failed is tried again."""
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._launch_scan.side_effect = ValueError("not a validation failure")
    _one_scheduler_tick(wu_review)
    assert wu_review._schedules[schedule_id]["enabled"] is True
    assert schedule_id not in wu_review._schedule_last_run
    assert not [record for record in caplog.records if record.levelname == "WARNING"]
    wu_review._launch_scan.side_effect = None
    _one_scheduler_tick(wu_review)  # not started, so it is still due
    assert wu_review._launch_scan.call_count == 2
    assert schedule_id in wu_review._schedule_last_run


def test_put_can_turn_off_an_invalid_schedule_but_not_turn_it_on(client_review, wu_review):
    profile_id = _profile(client_review)
    schedule_id = _schedule(client_review, profile_id)
    wu_review._schedules[schedule_id]["target"] = "192.0.2.10;bad"
    assert client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": True}).status_code == 400
    assert client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": False}).status_code == 200
    assert wu_review._schedules[schedule_id]["enabled"] is False
    assert wu_review._schedules[schedule_id]["target"] == "192.0.2.10;bad"  # nothing else was touched
    assert client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": True}).status_code == 400
    assert client_review.put(f"/api/schedules/{schedule_id}", json={"enabled": True, "target": "192.0.2.10"}).status_code == 200
    assert wu_review._schedules[schedule_id]["enabled"] is True


@pytest.mark.parametrize("how", ["dashboard toggle", "profile source"])
def test_scheduled_web_scan_is_skipped_in_offline_mode_instead_of_completing_empty(client_review, wu_review, how):
    body = {"name": "Site", "scan_ports": False, "scan_web": True}
    if how == "profile source":
        body["vulnerability_source"] = "offline"
    else:
        wu_review._settings["offline_mode"] = True
    profile_id = client_review.post("/api/profiles", json=body).get_json()["id"]
    schedule_id = client_review.post("/api/schedules", json={"target": "example.test", "profile_id": profile_id}).get_json()["id"]
    _one_scheduler_tick(wu_review)
    _one_scheduler_tick(wu_review)  # not due again until the next interval, so no second log line
    wu_review._launch_scan.assert_not_called()
    skips = [entry["msg"] for entry in wu_review._log_history if "web checks are disabled in offline mode" in entry["msg"]]
    assert len(skips) == 1
    assert wu_review._schedules[schedule_id]["enabled"] is True and wu_review._schedules[schedule_id]["last_run"] == ""
    wu_review._settings["offline_mode"] = False
    if how == "profile source":
        client_review.put(f"/api/profiles/{profile_id}", json={"vulnerability_source": "online"})
    wu_review._schedule_last_run.pop(schedule_id)
    _one_scheduler_tick(wu_review)  # once online, the same schedule runs
    wu_review._launch_scan.assert_called_once()
