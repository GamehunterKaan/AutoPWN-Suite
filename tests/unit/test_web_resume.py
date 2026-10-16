# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
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
from tests.unit.test_web_dashboard import dashboard as dashboard


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


@pytest.mark.parametrize("status", [401, 403, 408, 429, 500, 503])
def test_http_crawl_failure_stays_pending_and_resume_discovers_recovered_links(web_response, status):
    root, page, leaf = "http://example.com/", "http://example.com/page", "http://example.com/leaf"
    state, summaries, calls = {}, [], []
    def fetch(url, **kwargs):
        calls.append(url)
        if url == page and not summaries:
            return web_response("Unavailable", status=status, url=url, headers={"Content-Type": "application/json"})
        body = '<a href="/page">page</a>' if url == root else '<a href="/leaf">leaf</a>' if url == page else "Done"
        return web_response(body, url=url)
    with patch("modules.web.webvuln.get", side_effect=lambda url, **kw: web_response(url=url)), \
         patch("modules.web.crawler.get", side_effect=fetch):
        webvuln(root, MagicMock(), MagicMock(), controls=controls("sqli"), checkpoint=state, on_complete=summaries.append)
        assert summaries[0]["status"] == "partial"
        assert any(f"HTTP {status}" in issue for issue in summaries[0]["issues"])
        assert page not in state["crawl"] and leaf not in state["crawl"]
        webvuln(root, MagicMock(), MagicMock(), controls=controls("sqli"), checkpoint=state, on_complete=summaries.append)
    assert summaries[-1]["status"] == "completed" and not summaries[-1]["issues"]
    assert Counter(calls) == {root: 1, page: 2, leaf: 1}


@pytest.mark.parametrize("status", [404, 410])
def test_missing_crawl_pages_are_terminal_observations(web_response, status):
    root, page = "http://example.com/", "http://example.com/missing"
    state, summary = {}, {}
    def fetch(url, **kwargs):
        return web_response('<a href="/missing">missing</a>', url=url) if url == root else web_response(status=status, url=url)
    with patch("modules.web.webvuln.get", return_value=web_response(url=root)), patch("modules.web.crawler.get", side_effect=fetch):
        webvuln(root, MagicMock(), MagicMock(), controls=controls("sqli"), checkpoint=state, on_complete=summary.update)
    assert summary["status"] == "completed" and not summary["issues"]
    assert state["crawl"][page] == []


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


def test_parameter_limit_batches_continue_to_remaining_inputs(web_response):
    url = "http://example.com/?file=one&path=two&include=three"
    state, summaries = {}, []
    with patch("modules.web.webvuln.get", side_effect=lambda *a, **kw: web_response(url=url)), \
         patch("modules.web.lfi.get", side_effect=lambda requested, **kw: web_response(url=requested)) as get, \
         patch("modules.web.webvuln.crawl", return_value={url}):
        for _ in range(3):
            webvuln(url, MagicMock(), MagicMock(), controls=controls("lfi", max_parameters=1),
                    checkpoint=state, on_complete=summaries.append)
    assert [row["status"] for row in summaries] == ["partial", "partial", "completed"]
    assert get.call_count == 30  # One baseline and nine probes per input.
    assert summaries[-1]["total_requests"] == sum(row["requests"] for row in summaries)


def test_redirect_batches_only_count_relevant_inputs(web_response):
    from modules.web.probes import check_redirects
    from modules.web.runtime import run_task
    url = "http://example.com/?file=a&path=b&next=one&redirect=two"
    state, issues = {}, []
    client = MagicMock()
    client.send.side_effect = lambda probe: web_response(url=probe)
    for _ in range(2):
        context = ScanContext(url, MagicMock(), controls=controls("redirects", max_parameters=1), checkpoint=state)
        with context.activate():
            run_task("redirects", url, lambda: check_redirects(client, url, MagicMock(), max_parameters=1))
        issues.append(context.issues)
    assert issues[0] and not issues[1]
    assert client.send.call_count == 8


def test_findings_survive_request_budget_exit_and_successful_resume(web_response):
    from modules.web.findings import emit, finding
    from modules.web.runtime import ACTIVE, WebBudgetExceeded
    url = "http://example.com/?id=1"
    state, summaries, reported = {}, [], []
    def sql(url):
        result = finding("SQLI", url, "Synthetic repeatable evidence", severity="high")
        emit(MagicMock(), result)
        return [result]
    def xss(url):
        if not summaries:
            ACTIVE.get().issue("Request budget reached; coverage is limited.")
            raise WebBudgetExceeded()
        return []
    with patch("modules.web.webvuln.get", return_value=web_response(url=url)), \
         patch("modules.web.webvuln.crawl", return_value={url}), \
         patch("modules.web.webvuln.SQLIScanner") as scanner, patch("modules.web.webvuln.XSSScanner") as xss_scanner:
        scanner.return_value.test_sqli.side_effect = sql
        xss_scanner.return_value.test_xss.side_effect = xss
        first = webvuln(url, MagicMock(), MagicMock(), controls=controls("sqli", "xss"), checkpoint=state,
                       on_complete=summaries.append, on_finding=reported.append)
        second = webvuln(url, MagicMock(), MagicMock(), controls=controls("sqli", "xss"), checkpoint=state,
                        on_complete=summaries.append, on_finding=reported.append)
    assert [row["status"] for row in summaries] == ["partial", "completed"]
    assert first == second and len(second) == len(reported) == 1
    assert scanner.return_value.test_sqli.call_count == 1


def test_stopped_web_scan_resumes_without_skipping_unfinished_host(dashboard):
    wu, client = dashboard
    nm = MagicMock()
    nm.all_hosts.return_value = ["192.0.2.1"]
    nm.__getitem__.return_value = {"addresses": {}, "tcp": {80: {"state": "open", "name": "http", "product": "nginx", "version": "1"}}}
    config = wu._profile_config({"skip_discovery": True, "scan_web": True}) | {"target": "192.0.2.1"}
    job = wu.ScanJob("job", config["target"], config)
    wu._register_scan(job)
    attempts = []
    def web(endpoint, log, console, **kwargs):
        attempts.append(kwargs["checkpoint"])
        if len(attempts) == 1:
            kwargs["checkpoint"]["saved"] = True
            job.request_stop()
            kwargs["on_complete"]({"status": "stopped", "issues": [], "requests": 3})
            raise ScanCancelled("Stopped")
        assert kwargs["checkpoint"]["saved"]
        kwargs["on_complete"]({"status": "completed", "issues": [], "requests": 2})
        return []
    with patch.object(wu.shutil, "which", return_value="nmap"), patch("modules.scanner.PortScan", return_value=nm) as scan, \
         patch("modules.nist_search.searchCVE", return_value=[]) as lookup, \
         patch("modules.web.webvuln.webvuln", side_effect=web), patch.object(wu, "_notify"), patch.object(wu.threading, "Thread"):
        wu._run_scan(job)
        assert job.status == "stopped"
        assert client.post("/api/scans/job/resume", json={}).status_code == 200
        wu._run_scan(job)
    assert job.status == "completed"
    assert scan.call_count == lookup.call_count == 1
    assert len(attempts) == 2 and attempts[0] is attempts[1]
    assert job.hosts_list()[0]["scan_status"] == "completed"
    assert len(job.to_dict()["web_coverage"]) == 1


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


@pytest.mark.parametrize("failure", ["internal_details", "oversized_integer", "malformed_integer", "check_selection"])
def test_resume_validation_does_not_serialize_exceptions_or_change_job(dashboard, failure):
    from copy import deepcopy
    wu, client = dashboard
    job = wu.ScanJob("job", "example.com", {"scan_web": True, "web_options": {}})
    job.mark_done("partial")
    job.request_stop()
    wu._register_scan(job)
    before = deepcopy(job.to_dict())
    body = {"web_options": {}}
    if failure == "oversized_integer":
        import sys
        limit = sys.get_int_max_str_digits()
        if not limit:
            pytest.skip("Python integer conversion limit is disabled")
        body["web_options"]["speed"] = "9" * (limit + 1)
    elif failure == "malformed_integer":
        body["web_options"]["speed"] = "++2"
    elif failure == "check_selection":
        body["web_options"]["checks"] = {"sqli": False}
    with patch.object(wu.threading, "Thread") as thread:
        if failure == "internal_details":
            with patch.object(wu, "normalize_options", side_effect=ValueError("/private/config: secret-token-123")):
                response = client.post("/api/scans/job/resume", json=body)
        else:
            response = client.post("/api/scans/job/resume", json=body)
    assert response.status_code == 400
    expected = ("Keep the original check selection when resuming; start a new scan to change it."
                if failure == "check_selection" else "Invalid web scan configuration")
    assert response.get_json() == {"error": expected}
    assert job.to_dict() == before and job.should_stop()
    thread.assert_not_called()


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


@pytest.mark.parametrize("mixed", [False, True])
def test_resume_retries_nmap_timeouts_instead_of_caching_empty_success(dashboard, mixed):
    from modules.nmap_backend import PortScanner
    wu, client = dashboard
    def observation(timed_out):
        nm = PortScanner(nmap_path="unused")
        hosts = (f'<host timedout="{str(timed_out).lower()}"><status state="up" reason="user-set"/>'
                 '<address addr="192.0.2.1" addrtype="ipv4"/></host>')
        if mixed:
            hosts += '<host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/></host>'
        nm.load_xml('<nmaprun>' + hosts + '<runstats><finished exit="success"/>'
                    '<hosts up="2" down="0" total="2"/></runstats></nmaprun>')
        return nm
    target = "192.0.2.0/24" if mixed else "192.0.2.1"
    config = wu._profile_config({"skip_discovery": True, "scan_vulns": False}) | {"target": target}
    job = wu.ScanJob("job", target, config)
    wu._register_scan(job)
    with patch.object(wu.shutil, "which", return_value="nmap"), \
         patch("modules.scanner.PortScan", side_effect=[observation(True), observation(False)]) as scan, \
         patch.object(wu, "_notify"), patch.object(wu.threading, "Thread"):
        wu._run_scan(job)
        assert job.status == "partial" and job.to_dict()["can_resume"]
        assert "192.0.2.1" not in job._completed_hosts
        assert target not in job._network_results
        if mixed:
            assert "192.0.2.2" in job._completed_hosts
        assert client.post("/api/scans/job/resume", json={}).status_code == 200
        wu._run_scan(job)
    assert job.status == "completed" and scan.call_count == 2
    assert all(host["scan_status"] == "completed" for host in job.hosts_list())


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
