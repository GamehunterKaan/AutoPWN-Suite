"""Offline regressions for profile and schedule lifecycle failures."""

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def wu_review(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    path = Path(__file__).parents[2] / "modules" / "web_ui.py"
    spec = importlib.util.spec_from_file_location("modules.web_ui", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__version__ = "test"
    module._load_settings()
    monkeypatch.setattr(module, "_launch_scan", Mock(return_value=SimpleNamespace(id="offline-job")))
    return module


@pytest.fixture
def client_review(wu_review):
    app = wu_review._build_app(wu_review._STATIC_DIR)
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
