"""Continuation must finish remaining work without erasing earlier evidence."""

from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from modules.nmap_progress import ScanCancelled
from modules.web.crawler import crawl
from modules.web.options import CHECKS, normalize_options
from modules.web.runtime import ScanContext
from modules.web.webvuln import webvuln
from tests.unit.test_web_dashboard import dashboard


def controls(*checks, **limits):
    return normalize_options({"speed": 5, "checks": {name: name in checks for name in CHECKS}, **limits})


def test_crawl_resumes_uncrawled_pages_and_retains_links_hidden_by_limits():
    root = "http://example.com/"
    graph = {root: {root + "a", root + "b"}, root + "a": {root + "c"}, root + "b": set(), root + "c": set()}
    state, calls = {}, []
    def links(url, log):
        calls.append(url)
        return graph[url]
    with patch("modules.web.crawler.link_finder", side_effect=links):
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            assert crawl(root, MagicMock(), max_pages=1, max_urls=2, max_depth=0) == {root}
        for _ in range(3):
            with ScanContext(root, MagicMock(), checkpoint=state).activate():
                found = crawl(root, MagicMock(), max_pages=1, max_urls=10, max_depth=5)
    assert found == set(graph)
    assert Counter(calls) == Counter({url: 1 for url in graph})


def test_endpoint_batches_reach_completed_without_retesting_finished_checks(web_response):
    root = "http://example.com/"
    urls = {root + f"page?id={i}" for i in range(6)}
    state, summaries = {}, []
    with patch("modules.web.webvuln.get", return_value=web_response(url=root)), \
         patch("modules.web.webvuln.crawl", return_value=urls), \
         patch("modules.web.webvuln.SQLIScanner") as sql, patch("modules.web.webvuln.XSSScanner") as xss:
        sql.return_value.test_sqli.return_value = []
        xss.return_value.test_xss.return_value = []
        for _ in range(3):
            webvuln(root, MagicMock(), MagicMock(), controls=controls("sqli", "xss", max_endpoints=2),
                    checkpoint=state, on_complete=summaries.append)
    assert [row["status"] for row in summaries] == ["partial", "partial", "completed"]
    assert sql.return_value.test_sqli.call_count == 6
    assert xss.return_value.test_xss.call_count == 6
    assert summaries[-1]["attempts"] == 3


def test_small_request_budget_progresses_between_parameters(web_response):
    url = "http://example.com/?file=one&path=two&include=three"
    state, summaries = {}, []
    with patch("modules.web.webvuln.get", side_effect=lambda *a, **kw: web_response(url=url)), \
         patch("modules.web.lfi.get", side_effect=lambda requested, **kw: web_response(url=requested)) as get, \
         patch("modules.web.webvuln.crawl", return_value={url}):
        for _ in range(2):
            webvuln(url, MagicMock(), MagicMock(), controls=controls("lfi", request_budget=20),
                    checkpoint=state, on_complete=summaries.append)
    assert [row["status"] for row in summaries] == ["partial", "completed"]
    assert summaries[0]["requests"] == 20
    assert summaries[1]["requests"] < 20
    # All nine probes for the first input were completed in attempt one.
    from urllib.parse import parse_qs, urlsplit
    first_input = [call.args[0] for call in get.call_args_list
                   if parse_qs(urlsplit(call.args[0]).query)["file"] != ["one"]]
    assert len(first_input) == 9


def test_failed_check_is_retried_while_successful_check_is_kept(web_response):
    url = "http://example.com/?id=1"
    state, summaries = {}, []
    def xss(url):
        from modules.web.runtime import ACTIVE
        if len(summaries) == 0:
            ACTIVE.get().issue("A web request failed; coverage is incomplete.")
        return []
    with patch("modules.web.webvuln.get", return_value=web_response(url=url)), \
         patch("modules.web.webvuln.crawl", return_value={url}), \
         patch("modules.web.webvuln.SQLIScanner") as sql, patch("modules.web.webvuln.XSSScanner") as scanner:
        sql.return_value.test_sqli.return_value = []
        scanner.return_value.test_xss.side_effect = xss
        for _ in range(2):
            webvuln(url, MagicMock(), MagicMock(), controls=controls("sqli", "xss"), checkpoint=state, on_complete=summaries.append)
    assert [row["status"] for row in summaries] == ["partial", "completed"]
    assert sql.return_value.test_sqli.call_count == 1
    assert scanner.return_value.test_xss.call_count == 2


def test_directory_resume_continues_after_budget_without_repeating_paths(web_response):
    from modules.web.dirbust import dirbust
    from modules.web.runtime import WebBudgetExceeded
    state, summaries = {}, []
    urls = []
    def response(url, **kwargs):
        urls.append(url)
        return web_response("Missing", status=404, url=url)
    with patch("modules.web.dirbust.get", side_effect=response):
        for _ in range(20):
            context = ScanContext("http://example.com/", MagicMock(), controls=controls("directories", request_budget=20), checkpoint=state)
            with context.activate():
                try:
                    dirbust(context.target, MagicMock(), MagicMock())
                except WebBudgetExceeded:
                    summaries.append("partial")
                    continue
            summaries.append("completed")
            break
    assert summaries[0] == "partial" and summaries[-1] == "completed"
    paths = [url for url in urls if "__autopwn_missing_" not in url]
    assert paths and len(paths) == len(set(paths))


def test_resume_api_keeps_job_results_and_rejects_duplicate_launch(dashboard):
    wu, client = dashboard
    config = wu._profile_config({"scan_web": True, "scan_ports": False, "web_options": {"max_depth": 0}}) | {"target": "http://example.com/"}
    job = wu.ScanJob("job", config["target"], config)
    job.get_or_create_host("example.com")
    job.add_web_finding("example.com", config["target"], {"id": "old", "url": config["target"], "type": "CORS"})
    job.add_web_coverage("example.com", config["target"], {"status": "partial", "issues": ["Web crawl budget reached; coverage is limited."]})
    job.mark_done("partial")
    job._stop_flag.set()
    wu._register_scan(job)
    with patch.object(wu.threading, "Thread") as thread:
        response = client.post("/api/scans/job/resume", json={"web_options": {"speed": 2, "request_delay_ms": 750}})
        assert response.status_code == 200
        assert client.post("/api/scans/job/resume", json={}).status_code == 409
    assert thread.call_count == 1
    assert job.config["web_options"]["max_depth"] == 1
    assert job.config["web_options"]["speed"] == 2
    assert job.resume_count == 1 and not job.should_stop()
    assert job.web_findings(full=True)[0]["id"] == "old"
    assert wu._get_scan("job") is job


@pytest.mark.parametrize("body", [{"web_options": {"speed": 7}}, {"web_options": {"checks": {"sqli": False}}}, {"target": "elsewhere"}, []])
def test_invalid_resume_is_atomic(dashboard, body):
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {"scan_web": True, "web_options": {}})
    job.mark_done("partial")
    wu._register_scan(job)
    with patch.object(wu.threading, "Thread") as thread:
        assert client.post("/api/scans/job/resume", json=body).status_code == 400
    thread.assert_not_called()
    assert job.status == "partial" and job.resume_count == 0


def test_resume_offline_guard_and_completed_guard(dashboard):
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {"scan_web": True})
    job.mark_done("stopped")
    wu._register_scan(job)
    wu._settings["offline_mode"] = True
    with patch.object(wu.threading, "Thread") as thread:
        assert client.post("/api/scans/job/resume", json={}).status_code == 409
        wu._settings["offline_mode"] = False
        job.mark_done("completed")
        assert client.post("/api/scans/job/resume", json={}).status_code == 409
        assert client.post("/api/scans/missing/resume", json={}).status_code == 404
    thread.assert_not_called()


def test_resume_network_reuses_nmap_and_only_retries_failed_cve_lookups(dashboard):
    wu, client = dashboard
    nm = MagicMock()
    nm.all_hosts.return_value = ["192.0.2.1", "192.0.2.2"]
    hosts = {ip: {"addresses": {}, "tcp": {80: {"state": "open", "name": "http", "product": "nginx", "version": "1"}}} for ip in nm.all_hosts()}
    nm.__getitem__.side_effect = lambda ip: hosts[ip]
    config = wu._profile_config({"skip_discovery": True}) | {"target": "192.0.2.0/24"}
    job = wu.ScanJob("job", config["target"], config)
    wu._register_scan(job)
    cve = SimpleNamespace(CVEID="CVE-2026-0001", severity="medium", description="Example", severity_score=5,
                          data_source="test", database_updated_at="")
    with patch.object(wu.shutil, "which", return_value="nmap"), patch("modules.scanner.PortScan", return_value=nm) as scan, \
         patch("modules.nist_search.searchCVE", side_effect=[RuntimeError("Unavailable"), [cve], [cve]]) as lookup, \
         patch.object(wu, "_notify"), patch.object(wu.threading, "Thread"):
        wu._run_scan(job)
        assert job.status == "partial"
        assert client.post("/api/scans/job/resume", json={}).status_code == 200
        wu._run_scan(job)
    assert job.status == "completed"
    assert scan.call_count == 1 and lookup.call_count == 3
    assert all(len(host["vulns"]) == 1 for host in job.hosts_list())


def test_pacing_uses_speed_and_minimum_delay_and_is_cancellable():
    now = [0.0]
    def sleep(seconds):
        now[0] += seconds
    with patch("modules.web.runtime.time.monotonic", side_effect=lambda: now[0]), \
         patch("modules.web.runtime.time.sleep", side_effect=sleep):
        context = ScanContext("http://example.com/", MagicMock(), controls={"speed": 4, "request_delay_ms": 200})
        context.before()
        context.before()
    assert now[0] == pytest.approx(.2)
    stop = [False]
    context = ScanContext("http://example.com/", MagicMock(), should_stop=lambda: stop[0])
    context.before()
    with patch("modules.web.runtime.time.sleep", side_effect=lambda seconds: stop.__setitem__(0, True)), pytest.raises(ScanCancelled):
        context.before()
    assert context.requests == 1
