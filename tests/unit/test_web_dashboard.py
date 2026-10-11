from copy import deepcopy
import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

from modules.nmap_progress import ScanCancelled
from modules.web.options import normalize_options
from modules.web.runtime import ScanContext, WebBudgetExceeded


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    sys.modules.pop("modules.web_ui", None)
    wu = importlib.import_module("modules.web_ui")
    wu._settings = {}
    wu._scans.clear()
    app = wu._build_app(wu._STATIC_DIR)
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
    with patch("modules.web.webvuln.webvuln") as web:
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
    with patch("modules.web.webvuln.webvuln", side_effect=scan), patch.object(wu.shutil, "which", return_value=None), patch.object(wu, "_notify"):
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
    with patch.object(wu.shutil, "which", return_value="nmap"), patch("modules.scanner.PortScan", return_value=nm), \
         patch("modules.nist_search.searchCVE", side_effect=RuntimeError("NVD unavailable")), \
         patch("modules.web.webvuln.webvuln", side_effect=scan), patch.object(wu, "_notify"):
        wu._run_scan(job)
    host = job.hosts_list()[0]
    assert job.status == "partial"
    assert host["web_status"] == "completed"
    assert host["lookup_status"] == "partial"
    assert host["scan_status"] == "partial"


@pytest.mark.unit
def test_selected_header_only_check_makes_one_request_and_records_redacted_evidence(web_response):
    from modules.web.webvuln import webvuln
    controls = normalize_options()
    controls["checks"] = {name: name == "headers" for name in controls["checks"]}
    found, summary = [], {}
    url = "http://example.com/?token=private-token"
    with patch("modules.web.webvuln.get", return_value=web_response("<html>Home</html>", url=url)) as get, patch("modules.web.webvuln.crawl") as crawl, patch("modules.web.webvuln.dirbust") as dirs:
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
