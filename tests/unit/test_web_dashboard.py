# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import email
import email.policy
import html
import importlib
import json
import sys
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from autopwn_suite.nmap_progress import ScanCancelled
from autopwn_suite.web.options import normalize_options
from autopwn_suite.web.runtime import ScanContext, WebBudgetExceeded
from tests.auth_helpers import authenticated_app


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    sys.modules.pop("autopwn_suite.web_ui", None)
    wu = importlib.import_module("autopwn_suite.web_ui")
    wu._settings = {}
    wu._scans.clear()
    app = authenticated_app(wu)
    app.config["TESTING"] = True
    return wu, app.test_client()


@pytest.mark.unit
@pytest.mark.parametrize("bad", [{"request_budget": True}, {"timeout": 0}, {"max_depth": 20}, {"checks": {"sqli": "yes"}}, {"unknown": 1}, {"checks": {"unknown": True}}])
def test_web_controls_are_strictly_validated(dashboard, bad):
    wu, client = dashboard
    with patch.object(wu, "_launch_scan") as launch:
        assert client.post("/api/scan/start", json={"target": "192.0.2.1", "scan_web": True, "web_options": bad}).status_code == 400
    launch.assert_not_called()


@pytest.mark.unit
def test_profile_controls_merge_and_survive_schedule_validation(dashboard):
    wu, client = dashboard
    profile = client.post("/api/profiles", json={"name": "Web", "scan_ports": False, "scan_web": True,
        "web_options": {"request_budget": 90, "checks": {"sqli": False}}}).get_json()
    assert profile["config"]["scan_vulns"] is False
    updated = client.put("/api/profiles/" + profile["id"], json={"web_options": {"checks": {"cors": False}}}).get_json()
    assert updated["config"]["web_options"]["request_budget"] == 90
    assert not updated["config"]["web_options"]["checks"]["sqli"]
    assert not updated["config"]["web_options"]["checks"]["cors"]
    schedule = client.post("/api/schedules", json={"name": "Site", "target": "https://example.com/app?q=1", "profile_id": profile["id"]})
    assert schedule.status_code == 201


@pytest.mark.unit
def test_web_only_accepts_url_and_network_scans_reject_url(dashboard):
    wu, client = dashboard
    with patch.object(wu, "_launch_scan", return_value=MagicMock(id="job")) as launch:
        assert client.post("/api/scan/start", json={"target": "https://example.com:8443/app?q=1", "scan_web": True, "scan_ports": False}).status_code == 200
        assert launch.call_args.args[0]["skip_discovery"] is True
        assert client.post("/api/scan/start", json={"target": "https://example.com/app"}).status_code == 400
        assert client.post("/api/scan/start", json={"target": "https://user:secret@example.com/", "scan_web": True, "scan_ports": False}).status_code == 400


@pytest.mark.unit
def test_offline_policy_rejects_web_launch_and_skips_scheduled_web(dashboard):
    wu, client = dashboard
    wu._settings["offline_mode"] = True
    with patch.object(wu, "_launch_scan") as launch:
        assert client.post("/api/scan/start", json={"target": "example.com", "scan_web": True, "scan_ports": False}).status_code == 409
    launch.assert_not_called()
    job = wu.ScanJob("job", "example.com", {"scan_web": True, "vulnerability_source": "offline"})
    with patch("autopwn_suite.web.webvuln.webvuln") as web:
        assert wu._run_host_web(job, "example.com", ["example.com"], MagicMock(), MagicMock()) is False
    web.assert_not_called()
    assert job.hosts_list()[0]["web_status"] == "skipped_offline"


@pytest.mark.unit
def test_web_only_runs_without_nmap_and_exports_findings(dashboard):
    wu, client = dashboard
    config = wu._profile_config({"scan_web": True, "scan_ports": False}) | {"target": "https://example.com/"}
    job = wu.ScanJob("job", config["target"], config)
    result = {"id": "finding", "type": "CORS", "url": "https://example.com/", "details": {"title": "CORS"}, "evidence": "repeatable", "severity": "medium"}
    def scan(endpoint, log, console, **kwargs):
        kwargs["on_finding"](result)
        kwargs["on_complete"]({"status": "completed", "requests": 3, "target": endpoint, "issues": []})
        return [result]
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu.shutil, "which", return_value=None), patch.object(wu, "_notify"):
        wu._register_scan(job)
        wu._run_scan(job)
    assert job.status == "completed"
    assert client.get("/api/web/findings").get_json()[0]["id"] == "finding"
    assert client.get("/api/web/findings/job/finding").get_json()["host"] == "example.com"
    assert job.to_full_dict()["web_findings"][0]["id"] == "finding"


@pytest.mark.unit
def test_context_enforces_global_budget_and_cancellation():
    context = ScanContext("https://example.com/", MagicMock(), controls={"request_budget": 20})
    for _ in range(20):
        context.before()
    with pytest.raises(WebBudgetExceeded):
        context.before()
    assert context.requests == 20
    stopped = ScanContext("https://example.com/", MagicMock(), should_stop=lambda: True)
    with pytest.raises(ScanCancelled):
        stopped.before()


@pytest.mark.unit
def test_successful_web_checks_do_not_erase_failed_cve_coverage(dashboard):
    wu, _ = dashboard
    nm = MagicMock()
    nm.all_hosts.return_value = ["192.0.2.1"]
    nm.__getitem__.return_value = {"addresses": {}, "tcp": {80: {"state": "open", "name": "http", "product": "nginx", "version": "1.0"}}}
    config = wu._profile_config({"scan_web": True, "skip_discovery": True}) | {"target": "192.0.2.1"}
    job = wu.ScanJob("job", config["target"], config)
    def scan(endpoint, log, console, **kwargs):
        kwargs["on_complete"]({"status": "completed", "requests": 1, "target": endpoint, "issues": []})
        return []
    with patch.object(wu.shutil, "which", return_value="nmap"), patch("autopwn_suite.scanner.PortScan", return_value=nm), \
         patch("autopwn_suite.nist_search.searchCVE", side_effect=RuntimeError("NVD unavailable")), \
         patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        wu._run_scan(job)
    host = job.hosts_list()[0]
    assert job.status == "partial"
    assert host["web_status"] == "completed"
    assert host["lookup_status"] == "partial"
    assert host["scan_status"] == "partial"


@pytest.mark.unit
def test_markup_in_a_service_banner_does_not_fail_the_scan_job(dashboard):
    wu, _ = dashboard
    nm = MagicMock()
    nm.all_hosts.return_value = ["192.0.2.1"]
    nm.__getitem__.return_value = {"addresses": {}, "tcp": {21: {"state": "open", "name": "ftp", "product": "[/bold]", "version": "[/admin] 1.0"}}}
    config = wu._profile_config({"skip_discovery": True, "scan_vulns": False}) | {"target": "192.0.2.1"}
    job = wu.ScanJob("job", config["target"], config)
    with patch.object(wu.shutil, "which", return_value="nmap"), patch("autopwn_suite.scanner.PortScan", return_value=nm), patch.object(wu, "_notify"):
        wu._run_scan(job)
    assert job.status == "completed"
    assert [(port["product"], port["version"]) for port in job.hosts_list()[0]["ports"]] == [("[/bold]", "[/admin] 1.0")]


@pytest.mark.unit
def test_selected_header_only_check_makes_one_request_and_records_redacted_evidence(web_response):
    from autopwn_suite.web.webvuln import webvuln
    controls = normalize_options()
    controls["checks"] = {name: name == "headers" for name in controls["checks"]}
    found, summary = [], {}
    url = "http://example.com/?token=private-token"
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response("<html>Home</html>", url=url)) as get, patch("autopwn_suite.web.webvuln.crawl") as crawl, patch("autopwn_suite.web.webvuln.dirbust") as dirs:
        results = webvuln(url, MagicMock(), MagicMock(), controls=controls, on_finding=found.append, on_complete=summary.update)
    get.assert_called_once()
    crawl.assert_not_called()
    dirs.assert_not_called()
    assert results and found
    assert "private-token" not in str(results)
    assert all(item["reproduction"]["requests"][0]["redacted"] for item in results)
    assert summary["requests"] == 1


@pytest.mark.unit
def test_scan_evidence_removes_url_credentials_from_redirect_headers(web_response):
    context = ScanContext("http://example.com/", MagicMock())
    response = web_response(headers={"Location": "https://user:password@example.com/?token=secret#private"})
    response.autopwn_truncated = False
    record = context.capture(response, "GET", "http://example.com/", {}, context.before())
    assert record["response"]["headers"]["Location"] == "https://example.com/?token=REDACTED"


TYPED_TARGET = "https://example.com:8443/app?nick=hunter2&q=1#access_token=abc"
SHOWN_TARGET = "https://example.com:8443/app?nick=REDACTED&q=REDACTED"


def web_only_job(wu, target=TYPED_TARGET):
    config = wu._profile_config({"scan_web": True, "scan_ports": False}) | {"target": target}
    return wu.ScanJob("job", target, config)


@pytest.mark.unit
def test_scan_record_exports_show_a_redacted_target_and_the_scan_keeps_the_one_typed(dashboard):
    wu, client = dashboard
    job, scanned = web_only_job(wu), []
    def scan(endpoint, log, console, **kwargs):
        scanned.append(endpoint)
        kwargs["on_complete"]({"status": "partial", "requests": 1, "target": endpoint, "issues": []})
        return []
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        wu._register_scan(job)
        wu._run_scan(job)
    assert scanned == [TYPED_TARGET] and job.status == "partial"
    # Status JSON (the list the history is drawn from, and one scan) and the downloaded JSON report; the printable report is drawn from the first.
    listed, single, download = (client.get("/api/scans").get_json()[0], client.get("/api/scans/job").get_json(),
                                json.loads(client.get("/api/scans/job/download").data))
    for record in (listed, single, download):
        assert record["target"] == record["config"]["target"] == SHOWN_TARGET
        assert [row["endpoint"] for row in record["web_coverage"]] == [SHOWN_TARGET]
        assert record["web_coverage"][0]["target"] == SHOWN_TARGET
    assert "hunter2" not in client.get("/api/scans").get_data(as_text=True) + client.get("/api/scans/job/download").get_data(as_text=True)
    # The record the scan runs from is untouched, and so is what a second run reaches after Resume.
    assert job.target == job.config["target"] == TYPED_TARGET
    with patch.object(wu.threading, "Thread") as thread:
        assert client.post("/api/scans/job/resume", json={}).status_code == 200
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        thread.call_args.kwargs["target"](*thread.call_args.kwargs["args"])
    assert scanned == [TYPED_TARGET, TYPED_TARGET]
    assert job.target == job.config["target"] == TYPED_TARGET


@pytest.mark.unit
def test_network_scan_targets_are_shown_as_typed(dashboard):
    wu, client = dashboard
    job = wu.ScanJob("job", "192.0.2.0/24", wu._profile_config({}) | {"target": "192.0.2.0/24"})
    wu._register_scan(job)
    record = client.get("/api/scans/job").get_json()
    assert record["target"] == record["config"]["target"] == "192.0.2.0/24"


@pytest.mark.unit
def test_starting_a_web_scan_answers_with_a_redacted_target_and_launches_the_one_typed(dashboard):
    wu, client = dashboard
    with patch.object(wu, "_launch_scan", return_value=MagicMock(id="job")) as launch:
        response = client.post("/api/scan/start", json={"target": TYPED_TARGET, "scan_web": True, "scan_ports": False})
    assert response.status_code == 200 and launch.call_args.args[0]["target"] == TYPED_TARGET
    assert response.get_json()["message"] == "Scan started for " + SHOWN_TARGET


@pytest.mark.unit
def test_finding_and_coverage_endpoints_hide_every_value_of_the_target(dashboard):
    wu, client = dashboard
    job = web_only_job(wu)
    result = {"id": "finding", "type": "CORS", "url": "https://example.com:8443/app", "details": {"title": "CORS"}, "evidence": "repeatable", "severity": "medium"}
    def scan(endpoint, log, console, **kwargs):
        kwargs["on_finding"](result)
        kwargs["on_complete"]({"status": "completed", "requests": 3, "target": endpoint, "issues": []})
        return [result]
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        wu._register_scan(job)
        wu._run_scan(job)
    assert client.get("/api/web/findings").get_json()[0]["endpoint"] == SHOWN_TARGET
    assert client.get("/api/web/findings/job/finding").get_json()["endpoint"] == SHOWN_TARGET
    # A completed endpoint is recognized again by the same redacted form, so a resumed scan does not repeat it.
    with patch("autopwn_suite.web.webvuln.webvuln") as again:
        wu._run_host_web(job, "example.com", [TYPED_TARGET], MagicMock(), MagicMock())
    again.assert_not_called()


def deliver_notifications(wu, job, monkeypatch):
    """Send the webhook and the e-mail of a finished scan to stand-ins and return what they received."""
    job.mark_done("completed")
    wu._settings["webhook"] = {"enabled": True, "url": "https://hooks.example.invalid/notify", "on_complete": True}
    wu._settings["email"] = {"enabled": True, "smtp_host": "smtp.example.invalid", "to_addr": "ops@example.invalid",
                             "from_addr": "autopwn@example.invalid", "on_complete": True}
    posted, mails = [], []
    monkeypatch.setattr(wu._requests, "post", lambda url, **kwargs: posted.append(kwargs["json"]) or MagicMock(status_code=200))
    @contextmanager
    def smtp(cfg):
        server = MagicMock()
        server.sendmail.side_effect = lambda *args: mails.append(args[2])
        yield server
    monkeypatch.setattr(wu, "_smtp_connection", smtp)
    wu._deliver_webhook(job)
    wu._deliver_email(job)
    message = email.message_from_string(mails[0], policy=email.policy.default)
    return posted, message["Subject"], message.get_body(("html",)).get_content()


@pytest.mark.unit
def test_notifications_carry_the_redacted_target(dashboard, monkeypatch):
    wu, _ = dashboard
    posted, subject, body = deliver_notifications(wu, web_only_job(wu), monkeypatch)
    assert posted[0]["target"] == SHOWN_TARGET
    assert SHOWN_TARGET in subject and html.escape(SHOWN_TARGET) in body
    assert "hunter2" not in str(posted) + subject + body


BREAKERS = ["'", '"', "<", ">", "\u00a0", "\u2028", "\u3000"]


@pytest.mark.unit
@pytest.mark.parametrize("breaker", BREAKERS)
def test_a_breaker_character_in_the_typed_target_leaves_no_later_value_in_a_record_an_answer_or_a_notification(dashboard, monkeypatch, breaker):
    # The dashboard checks a web-only target against ASCII whitespace only, so these characters reach the job record.
    wu, client = dashboard
    typed = f"https://example.com:8443/app?nick=ZQ1{breaker}ZQ2&q=ZQ3#access_token=ZQ4"
    job = web_only_job(wu, typed)
    result = {"id": "finding", "type": "CORS", "url": "https://example.com:8443/app", "details": {"title": "CORS"}, "evidence": "repeatable", "severity": "medium"}
    def scan(endpoint, log, console, **kwargs):
        kwargs["on_finding"](result)
        kwargs["on_complete"]({"status": "completed", "requests": 3, "target": endpoint, "issues": []})
        return [result]
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        wu._register_scan(job)
        wu._run_scan(job)
    assert job.status == "completed" and job.target == job.config["target"] == typed
    # Job record: status JSON, the list the history is drawn from, the downloaded JSON report; and the finding rows.
    records = [client.get("/api/scans/job").get_json(), client.get("/api/scans").get_json()[0], json.loads(client.get("/api/scans/job/download").data)]
    for record in records:
        assert record["target"] == record["config"]["target"] == SHOWN_TARGET
        assert [(row["endpoint"], row["target"]) for row in record["web_coverage"]] == [(SHOWN_TARGET, SHOWN_TARGET)]
    findings = client.get("/api/web/findings")
    assert findings.get_json()[0]["endpoint"] == SHOWN_TARGET
    # The answer to starting a scan with this target, and the webhook, the e-mail subject and its report.
    with patch.object(wu, "_launch_scan", return_value=MagicMock(id="job2")) as launch:
        response = client.post("/api/scan/start", json={"target": typed, "scan_web": True, "scan_ports": False})
    assert response.status_code == 200 and launch.call_args.args[0]["target"] == typed
    assert response.get_json()["message"] == "Scan started for " + SHOWN_TARGET
    posted, subject, body = deliver_notifications(wu, job, monkeypatch)
    assert posted[0]["target"] == SHOWN_TARGET and SHOWN_TARGET in subject and html.escape(SHOWN_TARGET) in body
    assert "ZQ" not in json.dumps(records) + findings.get_data(as_text=True) + response.get_data(as_text=True) + str(posted) + subject + body


@pytest.mark.unit
@pytest.mark.parametrize("typed,shown", [
    (TYPED_TARGET, SHOWN_TARGET),
    ("https://example.com/app?nick=ZQ1'ZQ2&token=ZQ3", "https://example.com/app?nick=REDACTED&token=REDACTED"),
    ("https://example.com/app?nick=ZQ1\u3000ZQ2&token=ZQ3", "https://example.com/app?nick=REDACTED&token=REDACTED"),
])
def test_the_scheduler_log_line_hides_the_target_it_fired_and_launches_the_one_stored(dashboard, typed, shown):
    wu, _ = dashboard
    schedule = {"id": "sched-0001", "name": "Site", "target": typed, "profile_id": "profile", "enabled": True}
    wu._schedules.clear()
    wu._schedules[schedule["id"]] = dict(schedule)
    wu._profiles["profile"] = {"config": {"scan_web": True, "scan_ports": False}}
    class Stop(Exception):
        pass
    events = []
    with patch.object(wu.time, "sleep", side_effect=[None, Stop]), patch.object(wu, "_should_fire", return_value=True), \
         patch.object(wu, "_previous_run_active", return_value=False), patch.object(wu, "_schedule_data", return_value=schedule), \
         patch.object(wu, "_launch_scan", return_value=MagicMock(id="job")) as launch, patch.object(wu, "_save_schedules"), \
         patch.object(wu, "_broadcast", side_effect=events.append), pytest.raises(Stop):
        wu._scheduler_loop()
    assert launch.call_args.args[0]["target"] == typed
    assert [event["msg"] for event in events] == ["[*] Scheduled scan fired: Site → " + shown]


@pytest.mark.unit
def test_a_failed_web_check_or_scan_logs_and_records_the_class_of_the_exception_only(dashboard, caplog):
    # A request error quotes the URL it sent, query included, and so can the text of any other exception.
    wu, client = dashboard
    quoted = "HTTPConnectionPool(host='example.com'): Max retries exceeded with url: /app?token=ZQ1 (Caused by NewConnectionError)"
    with patch("autopwn_suite.web.webvuln.webvuln", side_effect=RuntimeError(quoted)), caplog.at_level("DEBUG"):
        failed = wu._run_host_web(web_only_job(wu), "example.com", [TYPED_TARGET], MagicMock(), MagicMock())
    assert failed and "Web application check failed (RuntimeError)" in caplog.text
    assert "ZQ1" not in caplog.text and "Traceback" not in caplog.text
    for index, (error, label) in enumerate([(RuntimeError(quoted), "Unexpected error (RuntimeError)"), (SystemExit(quoted), "Scan aborted (SystemExit)")]):
        job, events = web_only_job(wu), []
        job.id = f"failing{index}"
        wu._register_scan(job)
        with patch.object(wu, "_run_host_web", side_effect=error), patch.object(wu, "_notify"), patch.object(wu, "_broadcast", side_effect=events.append):
            wu._run_scan(job)
        record = client.get(f"/api/scans/failing{index}").get_json()
        assert record["status"] == "error" and record["error"] == label
        assert [event["msg"] for event in events if event.get("level") == "error"] == [f"[-] {label}."]
        assert "ZQ1" not in json.dumps(record) + str(events)
