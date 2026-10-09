"""End-to-end scan orchestration using real local CVEs and mocked Nmap only."""
import importlib
import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests.unit.test_vulnerability_db import feed_server  # Shared tiny, verified annual feeds.


@pytest.fixture
def local_database(feed_server, monkeypatch):
    from modules.vulnerability_db import update_database
    path = feed_server[3]
    update_database(path)
    # Reads and offline scans must not even instantiate a downloader.
    monkeypatch.setattr("requests.Session", lambda: pytest.fail("Offline scan tried HTTP"))
    monkeypatch.setattr("modules.nist_search.get", lambda *a, **k: pytest.fail("Offline scan contacted NVD"))
    monkeypatch.setattr("requests.sessions.Session.request", lambda *a, **k: pytest.fail("Test tried a real HTTP request"))
    monkeypatch.setattr("nmap.PortScanner.__init__", lambda *a, **k: pytest.fail("Test tried real Nmap"))
    return path


def nmap_observation():
    result = MagicMock()
    result.all_hosts.return_value = ["192.168.1.10"]
    result.__getitem__.return_value = {"addresses": {"ipv4": "192.168.1.10"},
                                       "tcp": {22: {"state": "open", "name": "ssh",
                                                    "product": "OpenSSH", "version": "8.2p1"}}}
    return result


def test_python_api_scans_with_local_cves_and_no_http(local_database, monkeypatch):
    import api
    nm = nmap_observation()
    monkeypatch.setattr(api, "PortScanner", lambda: nm)
    scanner = api.AutoScanner()
    result = scanner.scan("192.168.1.10", offline=True, vuln_db=local_database)
    vulnerability = result["192.168.1.10"]["vulns"]["OpenSSH"]["CVE-2025-1234"]
    assert vulnerability["data_source"] == "offline"
    assert vulnerability["database_updated_at"]
    assert "-n" in nm.scan.call_args.kwargs["arguments"]


def test_cli_offline_scan_has_no_online_side_effects(local_database, monkeypatch):
    import autopwn
    from rich.console import Console
    monkeypatch.setattr(autopwn, "Console", lambda **kwargs: Console(file=io.StringIO(), **kwargs))
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--offline", "--vuln-db", str(local_database),
                                    "-t", "192.168.1.10", "-y", "--skip-discovery"])
    monkeypatch.setattr(autopwn, "check_nmap", MagicMock())
    monkeypatch.setattr(autopwn, "PortScan", MagicMock(return_value=nmap_observation()))
    monkeypatch.setattr(autopwn, "AnalyseScanResults", lambda *a: [["192.168.1.10", 22, "ssh", "OpenSSH", "8.2p1"]])
    monkeypatch.setattr(autopwn, "SaveOutput", MagicMock())
    for name in ("CheckConnection", "InitArgsAPI", "InitReport", "InitializeReport", "GetExploitsFromArray", "WebScan", "webvuln"):
        monkeypatch.setattr(autopwn, name, lambda *a, **k: pytest.fail("Offline CLI invoked " + name))
    autopwn.main()
    autopwn.SaveOutput.assert_called_once()
    assert "-n" in autopwn.PortScan.call_args.args[-1]


def test_database_management_commands_do_not_start_a_scan(local_database, monkeypatch):
    import autopwn
    from rich.console import Console
    monkeypatch.setattr(autopwn, "Console", lambda **kwargs: Console(file=io.StringIO(), **kwargs))
    scan = MagicMock()
    monkeypatch.setattr(autopwn, "StartScanning", scan)
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--vuln-db-status", "--vuln-db", str(local_database)])
    autopwn.main()
    updater = MagicMock(return_value={"count": 2, "path": str(local_database), "updated_at": "2026-10-09"})
    monkeypatch.setattr(autopwn, "update_database", updater)
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--update-vuln-db", "--vuln-db", str(local_database)])
    autopwn.main()
    updater.assert_called_once()
    scan.assert_not_called()
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--offline", "--update-vuln-db"])
    with pytest.raises(SystemExit, match="require internet"):
        autopwn.main()
    updater.assert_called_once()


def test_offline_discovery_disables_reverse_dns(monkeypatch):
    from modules.scanner import TestArp, TestPing, DiscoverHosts
    from modules.utils import ScanType
    scanner = importlib.import_module("modules.scanner")
    nm = nmap_observation()
    monkeypatch.setattr(scanner, "PortScanner", lambda: nm)
    TestPing("192.168.1.10", offline=True)
    assert "-n" in nm.scan.call_args.kwargs["arguments"]
    TestArp("192.168.1.10", offline=True)
    assert "-n" in nm.scan.call_args.kwargs["arguments"]
    assert DiscoverHosts("192.168.1.10", MagicMock(), ScanType.Ping, offline=True) == ["192.168.1.10"]
    assert "-n" in nm.scan.call_args.kwargs["arguments"]


def test_offline_missing_nmap_never_attempts_install(monkeypatch):
    utils = importlib.import_module("modules.utils")
    monkeypatch.setattr(utils, "check_call", MagicMock(side_effect=FileNotFoundError))
    installer = MagicMock()
    for name in ("install_nmap_windows", "install_nmap_linux", "install_nmap_mac"):
        monkeypatch.setattr(utils, name, installer)
    with pytest.raises(SystemExit, match="installed before"):
        utils.check_nmap(MagicMock(), offline=True)
    installer.assert_not_called()


@pytest.fixture
def web(monkeypatch, tmp_path):
    pytest.importorskip("flask")
    wu = importlib.import_module("modules.web_ui")
    monkeypatch.setattr(wu, "_VULNERABILITY_DB", tmp_path / "vulnerabilities.sqlite3")
    monkeypatch.setattr(wu, "_OFFLINE_ONLY", False)
    monkeypatch.setattr(wu, "_settings", {})
    monkeypatch.setattr(wu, "_SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(wu, "_scans", {})
    monkeypatch.setattr(wu, "_database_update", {"running": False, "message": "", "current": 0, "total": 0, "error": None})
    monkeypatch.setattr(wu, "_profiles", {})
    monkeypatch.setattr(wu, "_PROFILES_FILE", tmp_path / "profiles.json")
    app = wu._build_app(Path(wu.__file__).parent / "web_ui_static")
    app.config["TESTING"] = True
    return wu, app.test_client()


def test_web_offline_job_uses_database_and_skips_notifications(web, local_database, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_VULNERABILITY_DB", local_database)
    monkeypatch.setattr(wu.shutil, "which", lambda name: "nmap")
    scanner = importlib.import_module("modules.scanner")
    monkeypatch.setattr(scanner, "PortScan", MagicMock(return_value=nmap_observation()))
    monkeypatch.setattr(scanner, "AnalyseScanResults", lambda *a: [["192.168.1.10", 22, "ssh", "OpenSSH", "8.2p1", "tcp"]])
    notifications = MagicMock()
    monkeypatch.setattr(wu, "_send_email", notifications)
    monkeypatch.setattr(wu, "_send_webhook", notifications)
    job = wu.ScanJob("offline", "192.168.1.10", {"target": "192.168.1.10", "skip_discovery": True,
                                                 "vulnerability_source": "offline"})
    wu._run_scan(job)
    assert job.status == "completed"
    findings = job.hosts_list()[0]["vulns"]
    assert findings[0]["cve"] == "CVE-2025-1234" and findings[0]["data_source"] == "offline"
    assert job.config["vulnerability_source_used"] == "offline"
    assert job.config["vulnerability_database_updated_at"]
    notifications.assert_not_called()
    assert client.get("/api/vulnerability-database").json["count"] == 2
    export = client.get("/api/vulnerability-database/download")
    assert export.status_code == 200 and export.data == local_database.read_bytes()
    export.close()


def test_missing_local_database_rejected_before_launch(web, monkeypatch):
    wu, client = web
    launch = MagicMock()
    monkeypatch.setattr(wu, "_launch_scan", launch)
    response = client.post("/api/scan/start", json={"target": "192.168.1.10", "vulnerability_source": "offline"})
    assert response.status_code == 409 and "unavailable" in response.json["error"]
    launch.assert_not_called()
    assert client.get("/api/vulnerability-database/download").status_code == 409


def test_server_offline_policy_blocks_downloads_and_test_notifications(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_OFFLINE_ONLY", True)
    thread = MagicMock()
    monkeypatch.setattr(wu.threading, "Thread", thread)
    for route in ("/api/vulnerability-database/update", "/api/settings/test_email", "/api/settings/test_webhook"):
        assert client.post(route).status_code == 409
    thread.assert_not_called()


def test_server_offline_policy_overrides_online_request(web, local_database, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_OFFLINE_ONLY", True)
    monkeypatch.setattr(wu, "_VULNERABILITY_DB", local_database)
    launch = MagicMock(return_value=MagicMock(id="scan"))
    monkeypatch.setattr(wu, "_launch_scan", launch)
    assert client.post("/api/scan/start", json={"target": "192.168.1.10", "vulnerability_source": "online"}).status_code == 200
    assert launch.call_args.args[0]["vulnerability_source"] == "offline"


def test_database_update_requires_explicit_post_and_prevents_duplicate_jobs(web, monkeypatch):
    wu, client = web
    thread = MagicMock()
    monkeypatch.setattr(wu.threading, "Thread", thread)
    assert client.get("/api/vulnerability-database").status_code == 200
    thread.assert_not_called()
    assert client.post("/api/vulnerability-database/update").status_code == 202
    thread.assert_called_once()
    assert client.post("/api/vulnerability-database/update").status_code == 409


def test_update_error_is_reported_and_not_left_running(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "update_database", MagicMock(side_effect=OSError("private path details")))
    wu._database_update["running"] = True
    wu._update_vulnerability_database()
    status = client.get("/api/vulnerability-database").json
    assert not status["update"]["running"]
    assert "preserved" in status["update"]["error"]
    assert "private path" not in status["update"]["error"]


@pytest.mark.parametrize("source", ["bogus", {}, [], None, True])
def test_invalid_source_is_rejected(web, source):
    _, client = web
    response = client.post("/api/scan/start", json={"target": "192.168.1.10", "vulnerability_source": source})
    assert response.status_code == 400


def test_profiles_retain_offline_source(web):
    _, client = web
    response = client.post("/api/profiles", json={"name": "Airgap", "vulnerability_source": "offline"})
    assert response.status_code == 201
    assert response.json["config"]["vulnerability_source"] == "offline"


def test_dashboard_offline_toggle_persists_and_blocks_remote_actions(web, monkeypatch):
    wu, client = web
    assert client.put("/api/settings", json={"offline_mode": True}).status_code == 200
    assert client.get("/api/settings").json["offline_mode"] is True
    wu._settings.clear()
    wu._load_settings()
    assert wu._offline_enabled()
    assert client.get("/api/vulnerability-database").json["offline_only"] is True
    for route in ("/api/vulnerability-database/update", "/api/settings/test_email", "/api/settings/test_webhook"):
        assert client.post(route).status_code == 409
    threads = MagicMock()
    monkeypatch.setattr(wu.threading, "Thread", threads)
    job = wu.ScanJob("online", "192.168.1.10", {"vulnerability_source": "online"})
    wu._notify(job)
    threads.assert_not_called()
    assert client.put("/api/settings", json={"offline_mode": False}).status_code == 200
    assert not client.get("/api/vulnerability-database").json["offline_only"]


def test_dashboard_toggle_overrides_manual_and_scheduled_scan_sources(web, local_database, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_VULNERABILITY_DB", local_database)
    assert client.put("/api/settings", json={"offline_mode": True}).status_code == 200
    threads = MagicMock()
    monkeypatch.setattr(wu.threading, "Thread", threads)
    response = client.post("/api/scan/start", json={"target": "192.168.1.10", "vulnerability_source": "online"})
    assert response.status_code == 200
    assert wu._get_scan(response.json["scan_id"]).config["vulnerability_source"] == "offline"
    # The scheduler shares this launcher; the saved profile remains reusable online.
    profile_config = {"target": "192.168.1.10", "vulnerability_source": "online"}
    scheduled = wu._launch_scan(profile_config)
    assert scheduled.config["vulnerability_source"] == "offline"
    assert profile_config["vulnerability_source"] == "online"
    assert client.put("/api/settings", json={"offline_mode": False}).status_code == 200
    assert scheduled.config["vulnerability_source"] == "offline"


@pytest.mark.parametrize("value", ["true", 1, None, {}, []])
def test_dashboard_offline_toggle_requires_a_boolean(web, value):
    wu, client = web
    response = client.put("/api/settings", json={"offline_mode": value})
    assert response.status_code == 400
    assert not wu._offline_enabled()


def test_dashboard_cannot_override_cli_offline_mode(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_OFFLINE_ONLY", True)
    assert client.put("/api/settings", json={"offline_mode": False}).status_code == 200
    status = client.get("/api/vulnerability-database").json
    assert status["offline_only"] and status["offline_locked"]
    assert client.post("/api/vulnerability-database/update").status_code == 409


def test_switching_offline_waits_for_active_online_work(web):
    wu, client = web
    wu._database_update["running"] = True
    response = client.put("/api/settings", json={"offline_mode": True})
    assert response.status_code == 409 and "update to finish" in response.json["error"]
    assert not wu._offline_enabled()
    wu._database_update["running"] = False
    wu._scans["busy"] = wu.ScanJob("busy", "192.168.1.10", {"vulnerability_source": "auto"})
    response = client.put("/api/settings", json={"offline_mode": True})
    assert response.status_code == 409 and "online scans" in response.json["error"]
    assert not wu._offline_enabled()
    wu._scans["busy"].mark_done()
    assert client.put("/api/settings", json={"offline_mode": True}).status_code == 200


def test_failed_toggle_save_does_not_change_runtime_policy(web, monkeypatch):
    wu, client = web
    monkeypatch.setattr(wu, "_write_json", MagicMock(side_effect=OSError("disk full")))
    with pytest.raises(OSError):
        client.put("/api/settings", json={"offline_mode": True})
    assert not wu._offline_enabled()
