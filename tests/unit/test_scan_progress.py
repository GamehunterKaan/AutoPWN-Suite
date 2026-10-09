"""Real worker progress with simulated discovery, ports and CVE results."""
import importlib
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def progress_web(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    path = Path(__file__).parents[2] / "modules" / "web_ui.py"
    spec = importlib.util.spec_from_file_location("progress_web", path)
    wu = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wu)
    monkeypatch.setattr(wu, "_notify", MagicMock())
    monkeypatch.setattr(wu.shutil, "which", lambda _: "nmap")
    monkeypatch.setattr("requests.sessions.Session.request", lambda *a, **k: pytest.fail("Unexpected HTTP"))
    monkeypatch.setattr("nmap.PortScanner.__init__", lambda *a, **k: pytest.fail("Unexpected real Nmap"))
    return wu


def nmap_result(ip):
    nm = MagicMock()
    nm.all_hosts.return_value = [ip]
    nm.__getitem__.return_value = {"addresses": {"ipv4": ip}, "tcp": {}}
    return nm


def rows(ip):
    return [[ip, 22, "ssh", "OpenSSH", "8.2p1", "tcp"],
            [ip, 80, "http", "nginx", "1.0", "tcp"],
            [ip, 23, "telnet", "Linux telnetd", "Unknown", "tcp"]]


def test_worker_progress_follows_nmap_tasks_and_actual_lookup_counts(progress_web, monkeypatch):
    wu = progress_web
    scanner = importlib.import_module("modules.scanner")
    job = wu.ScanJob("progress", "192.0.2.0/24", {"target": "192.0.2.0/24"})
    events = []
    monkeypatch.setattr(wu, "_broadcast", lambda event: events.append(event))
    def discovery(*args, **kwargs):
        kwargs["progress"]("Ping Scan", 37.5)
        assert job.to_dict()["progress"]["percent"] == 37.5
        return ["192.0.2.1", "192.0.2.2"]
    def port_scan(ip, *args, **kwargs):
        kwargs["progress"]("SYN Stealth Scan", 42)
        kwargs["progress"]("Service scan", 80)
        return nmap_result(ip)
    monkeypatch.setattr(scanner, "DiscoverHosts", discovery)
    monkeypatch.setattr(scanner, "PortScan", port_scan)
    monkeypatch.setattr(scanner, "AnalyseScanResults", lambda nm, log, silent, ip: rows(ip))
    provider = MagicMock(source="online", local=None)
    observed = []
    def lookup(keyword, *args):
        observed.append(job.to_dict()["progress"])
        return []
    provider.search.side_effect = lookup
    monkeypatch.setattr(wu, "VulnerabilityLookup", lambda *args: provider)
    wu._run_scan(job)
    assert job.status == "completed"
    assert [p["percent"] for p in observed] == [0, 50, 0, 50]
    assert [p["completed"] for p in observed] == [0, 1, 0, 1]
    assert all(p["total"] == 2 for p in observed)  # Unknown versions are not lookup work.
    state = job.to_full_dict()["progress"]
    assert state["percent"] == 100 and state["targets_completed"] == state["targets_total"] == 2
    assert any(e.get("progress", {}).get("phase") == "discovery" for e in events)
    assert any(e.get("progress", {}).get("detail") == "Service scan" for e in events)
    provider.close.assert_called_once()


@pytest.mark.parametrize("status", ["stopped", "error", "partial"])
def test_terminal_jobs_keep_last_measured_progress(progress_web, status):
    wu = progress_web
    job = wu.ScanJob("freeze", "192.0.2.1", {})
    job.set_progress("port_scan", "Service scan", percent=37.5)
    if status == "error":
        job.mark_error("scan failed")
    else:
        job.mark_done(status)
    revision = job.to_dict()["progress"]["revision"]
    job.set_progress("port_scan", "Late statistics", percent=100)
    job.complete_target()
    assert job.to_dict()["progress"]["percent"] == 37.5
    assert job.to_dict()["progress"]["revision"] == revision
    copied = job.to_dict()["progress"]
    copied["percent"] = 0
    assert job.to_dict()["progress"]["percent"] == 37.5


def test_cancelled_nmap_keeps_progress_and_never_starts_lookups(progress_web, monkeypatch):
    wu = progress_web
    scanner = importlib.import_module("modules.scanner")
    job = wu.ScanJob("stop", "192.0.2.1", {"target": "192.0.2.1", "skip_discovery": True})
    provider = MagicMock(source="online", local=None)
    monkeypatch.setattr(wu, "VulnerabilityLookup", lambda *args: provider)
    def cancelled(*args, **kwargs):
        kwargs["progress"]("Service scan", 37.5)
        job.request_stop()
        raise wu.ScanCancelled("stopped")
    monkeypatch.setattr(scanner, "PortScan", cancelled)
    wu._run_scan(job)
    assert job.status == "stopped" and job.to_dict()["progress"]["percent"] == 37.5
    assert job.to_dict()["progress"]["targets_completed"] == 0
    provider.search.assert_not_called()
    provider.close.assert_called_once()


def test_failed_lookup_is_counted_and_finishes_with_partial_coverage(progress_web, monkeypatch):
    wu = progress_web
    scanner = importlib.import_module("modules.scanner")
    job = wu.ScanJob("partial", "192.0.2.1", {"target": "192.0.2.1", "skip_discovery": True})
    monkeypatch.setattr(scanner, "PortScan", lambda ip, *a, **k: nmap_result(ip))
    monkeypatch.setattr(scanner, "AnalyseScanResults", lambda *a: rows("192.0.2.1"))
    provider = MagicMock(source="online", local=None)
    provider.search.side_effect = [RuntimeError("NVD unavailable"), []]
    monkeypatch.setattr(wu, "VulnerabilityLookup", lambda *args: provider)
    wu._run_scan(job)
    assert job.status == "partial"
    progress = job.to_dict()["progress"]
    assert progress["completed"] == progress["total"] == 2
    assert progress["phase"] == "partial" and "incomplete" in progress["detail"]


def test_progress_events_reach_sse_without_filling_log_history(progress_web):
    wu = progress_web
    import queue
    subscriber = queue.Queue()
    wu._sse_subscribers.append(subscriber)
    job = wu.ScanJob("live", "192.0.2.1", {})
    job.set_progress("vulnerabilities", "Querying OpenSSH", percent=25, completed=1, total=4)
    event = subscriber.get_nowait()
    assert event["level"] == "__scan_progress__" and event["progress"]["percent"] == 25
    assert not wu._log_history


def test_scans_endpoint_exposes_progress_snapshot(progress_web):
    wu = progress_web
    pytest.importorskip("flask")
    job = wu.ScanJob("api", "192.0.2.1", {})
    wu._register_scan(job)
    job.set_progress("vulnerabilities", "Querying nginx", percent=50, completed=1, total=2)
    app = wu._build_app(wu._STATIC_DIR)
    progress = app.test_client().get("/api/scans").json[0]["progress"]
    assert progress["phase"] == "vulnerabilities" and progress["percent"] == 50
