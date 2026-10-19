# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import io
import logging
import re
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest
from requests.exceptions import ConnectionError
from rich.console import Console
from rich.logging import RichHandler

from autopwn_suite.web.crawler import link_finder
from autopwn_suite.web.options import CHECKS
from autopwn_suite.web.runtime import redact_text
from autopwn_suite.web.webvuln import target_urls, web_endpoints, webvuln


@pytest.fixture(autouse=True)
def isolate_additional_checks():
    with patch("autopwn_suite.web.webvuln.additional_checks", return_value=[]):
        yield


@pytest.mark.unit
def test_no_endpoint_is_logged_and_stops_before_other_checks():
    log, console = MagicMock(), MagicMock()
    with patch("autopwn_suite.web.webvuln.get", side_effect=ConnectionError) as get, patch("autopwn_suite.web.webvuln.crawl") as crawl, patch("autopwn_suite.web.webvuln.dirbust") as dirs:
        assert webvuln("127.0.0.1", log, console) == []
    assert [call.args[0] for call in get.call_args_list] == ["http://127.0.0.1/", "https://127.0.0.1/"]
    assert all(call.kwargs["allow_redirects"] is False for call in get.call_args_list)
    crawl.assert_not_called()
    dirs.assert_not_called()
    log.logger.assert_any_call("warning", "No reachable in-scope web endpoint on 127.0.0.1.")


@pytest.mark.unit
def test_static_site_still_runs_passive_checks_and_directory_discovery(web_response):
    url = "http://example.com/"
    log, console = MagicMock(), MagicMock()
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response("<html>Home</html>", url=url)), patch("autopwn_suite.web.webvuln.crawl", return_value={url}), patch("autopwn_suite.web.webvuln.dirbust", return_value=[]) as dirs:
        findings = webvuln("example.com", log, console)
    assert dirs.call_args.args[:2] == (url, console)
    assert findings and all(item["type"] == "WEB_CONFIG" for item in findings)
    log.logger.assert_any_call("info", "Found 0 testable urls.")


@pytest.mark.unit
def test_scanners_aggregate_structured_results_and_filter_off_origin_urls(web_response):
    url, probe = "http://example.com/", "http://example.com/page?id=1"
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response(url=url)), patch("autopwn_suite.web.webvuln.inspect_response", return_value=[]), patch("autopwn_suite.web.webvuln.dirbust", return_value=[{"type": "DIR"}]), patch("autopwn_suite.web.webvuln.crawl", return_value={probe, "http://external.com/page?id=1", "http://example.com/static"}), patch("autopwn_suite.web.webvuln.LFIScanner") as lfi, patch("autopwn_suite.web.webvuln.SQLIScanner") as sql, patch("autopwn_suite.web.webvuln.XSSScanner") as xss:
        lfi.return_value.test_lfi.return_value = [{"type": "LFI"}]
        sql.return_value.test_sqli.return_value = []
        xss.return_value.test_xss.return_value = [{"type": "XSS"}]
        assert [item["type"] for item in webvuln("example.com", MagicMock(), MagicMock())] == ["LFI", "XSS", "DIR"]
    lfi.return_value.test_lfi.assert_called_once_with(probe)
    sql.return_value.test_sqli.assert_called_once_with(probe)
    xss.return_value.test_xss.assert_called_once_with(probe)


@pytest.mark.unit
@pytest.mark.parametrize("target,expected", [
    ("example.com:8080", ["http://example.com:8080/", "https://example.com:8080/"]),
    ("https://example.com/app?file=one#part", ["https://example.com/app?file=one"]),
    ("2001:db8::1", ["http://[2001:db8::1]/", "https://[2001:db8::1]/"]),
])
def test_explicit_urls_ports_and_ipv6(target, expected):
    assert target_urls(target) == expected


@pytest.mark.unit
def test_invalid_target_has_no_network_request():
    with patch("autopwn_suite.web.webvuln.get") as get:
        assert webvuln("file:///etc/passwd", MagicMock(), MagicMock()) == []
    get.assert_not_called()


@pytest.mark.unit
def test_discovered_http_and_https_ports_have_independent_checks():
    rows = [["192.0.2.1", 8080, "http-proxy", "nginx", "1"],
            ["192.0.2.1", 9443, "ssl/http", "nginx", "1"],
            ["192.0.2.1", 8080, "http-proxy", "nginx", "1"],
            ["192.0.2.2", 80, "http", "nginx", "1"],
            ["192.0.2.1", 443, "https", "unknown", "1", "udp"]]
    assert web_endpoints("192.0.2.1", rows) == ["http://192.0.2.1:8080/", "https://192.0.2.1:9443/"]
    assert web_endpoints("192.0.2.3", rows) == ["192.0.2.3"]
    assert web_endpoints("2001:db8::1", [["2001:db8::1", 443, "https", "", ""]]) == ["https://[2001:db8::1]:443/"]


@pytest.mark.unit
def test_nmap_tls_tunnel_is_used_and_port_number_does_not_override_plain_http():
    rows = [["192.0.2.1", 9443, "http", "nginx", "1"], ["192.0.2.1", 8443, "http", "nginx", "1"]]
    scan = {"scan": {"192.0.2.1": {"tcp": {9443: {"name": "http", "tunnel": "ssl"}, 8443: {"name": "http"}}}}}
    assert web_endpoints("192.0.2.1", rows, scan) == ["https://192.0.2.1:9443/", "http://192.0.2.1:8443/"]


@pytest.mark.unit
def test_injection_endpoint_control_limits_every_classic_scanner(web_response):
    from autopwn_suite.web.options import CHECKS
    controls = {"max_endpoints": 1, "checks": {name: name in ("sqli", "xss", "lfi") for name in CHECKS}}
    url = "http://example.com/"
    summary = {}
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response(url=url)), \
         patch("autopwn_suite.web.webvuln.crawl", return_value={url + "a?id=1", url + "b?id=1"}), \
         patch("autopwn_suite.web.webvuln.LFIScanner") as lfi, patch("autopwn_suite.web.webvuln.SQLIScanner") as sql, patch("autopwn_suite.web.webvuln.XSSScanner") as xss:
        for scanner, method in ((lfi, "test_lfi"), (sql, "test_sqli"), (xss, "test_xss")):
            getattr(scanner.return_value, method).return_value = []
        webvuln(url, MagicMock(), MagicMock(), controls=controls, on_complete=summary.update)
    for scanner, method in ((lfi, "test_lfi"), (sql, "test_sqli"), (xss, "test_xss")):
        getattr(scanner.return_value, method).assert_called_once_with(url + "a?id=1")
    assert summary["status"] == "partial"
    assert "Injection endpoint budget reached; coverage is limited." in summary["issues"]


@pytest.mark.unit
@pytest.mark.parametrize("landing", ["/index.php", "/en/"])
def test_directory_discovery_still_covers_the_requested_root_after_a_redirect(web_response, landing):
    requested = []

    def respond(url, **kwargs):
        requested.append(url)
        path = urlsplit(url).path
        if path == "/":
            return web_response(status=302, url=url, headers={"Location": landing})
        if path == landing:
            return web_response("<html>Home</html>", url=url)
        if path == "/.env":
            return web_response("APP_ENV=lab", url=url)
        return web_response("not found", status=404, url=url)

    with patch("autopwn_suite.web.webvuln.get", side_effect=respond), patch("autopwn_suite.web.dirbust.get", side_effect=respond), patch("autopwn_suite.web.webvuln.crawl", return_value={"http://example.test" + landing}):
        findings = webvuln("http://example.test/", MagicMock(), MagicMock(), controls={"speed": 5})
    assert {"/.env", "/.git/HEAD", "/backup.sql"} <= {urlsplit(url).path for url in requested}
    assert "http://example.test/.env" in {item["url"] for item in findings}


@pytest.mark.unit
def test_directory_discovery_stays_under_a_deliberate_sub_path(web_response):
    requested = []

    def respond(url, **kwargs):
        requested.append(url)
        return web_response("<html>App</html>" if url.endswith("/app/") else "not found", status=200 if url.endswith("/app/") else 404, url=url)

    with patch("autopwn_suite.web.webvuln.get", side_effect=respond), patch("autopwn_suite.web.dirbust.get", side_effect=respond), patch("autopwn_suite.web.webvuln.crawl", return_value={"http://example.test/app/"}):
        webvuln("http://example.test/app/", MagicMock(), MagicMock(), controls={"speed": 5})
    assert "http://example.test/app/admin" in requested
    assert all(urlsplit(url).path.startswith("/app/") for url in requested)


@pytest.mark.unit
def test_probe_log_lines_and_coverage_issues_do_not_carry_query_secrets(web_response):
    url = "http://example.com/page?id=1&session=abcdef"
    log, summary = MagicMock(), {}
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response(url=url)), patch("autopwn_suite.web.webvuln.crawl", return_value={url}), \
         patch("autopwn_suite.web.sqli.get", side_effect=ConnectionError("HTTPConnectionPool: Max retries exceeded with url: /page?id=1&session=abcdef")):
        webvuln(url, log, MagicMock(), controls={"speed": 5, "checks": {name: name == "sqli" for name in CHECKS}}, on_complete=summary.update)
    expected = "Connection error raised on: http://example.com/page?id=1&session=REDACTED, skipping"
    assert expected in summary["issues"]
    log.logger.assert_any_call("error", expected)
    assert "abcdef" not in str(log.logger.call_args_list) + str(summary["issues"])


@pytest.mark.unit
def test_crawl_failures_are_logged_with_fixed_text_not_the_exception():
    log = MagicMock()
    with patch("autopwn_suite.web.crawler.get", side_effect=ConnectionError("Max retries exceeded with url: /app?session=abcdef")):
        assert link_finder("http://example.com/app", log) == set()
    log.logger.assert_called_once_with("error", "Unable to crawl http://example.com/app; coverage is incomplete.")


@pytest.mark.unit
@pytest.mark.parametrize("message,expected", [
    ("Connection error raised on: http://127.0.0.1:8080/?id=1&token=abc, skipping", "Connection error raised on: http://127.0.0.1:8080/?id=1&token=REDACTED, skipping"),
    ("Unable to crawl https://app.test/a?api_key=XYZ.", "Unable to crawl https://app.test/a?api_key=REDACTED."),
    ("Unable to crawl http://user:pw@app.test/x: HTTP 500; coverage is incomplete.", "Unable to crawl http://app.test/x: HTTP 500; coverage is incomplete."),
    ("Two urls (http://a.test/?jwt=1) and http://b.test/?q=2", "Two urls (http://a.test/?jwt=REDACTED) and http://b.test/?q=2"),
    ("No reachable in-scope web endpoint on 127.0.0.1.", "No reachable in-scope web endpoint on 127.0.0.1."),
    ("Unable to crawl http://a.test/x\x1b[2J\x1b]0;pwned\x07y?token=1: HTTP 500", "Unable to crawl http://a.test/x[2J]0;pwnedy?token=REDACTED: HTTP 500"),
    ("one\ntwo\tthree\r\x85\x7f", "one\ntwo\tthree"),
])
def test_redact_text_hides_query_secrets_in_every_url_of_a_message(message, expected):
    assert redact_text(message) == expected


@pytest.mark.unit
def test_terminal_control_characters_in_a_crawled_url_never_reach_the_console_or_the_issues(web_response):
    page = web_response('<a href="/x\x1b[2J\x1b]0;pwned\x07y">link</a>', headers={"Content-Type": "text/html"})
    output = io.StringIO()
    sink = logging.getLogger("autopwn-test-terminal-escapes")
    sink.handlers, sink.propagate = [RichHandler(console=Console(file=output, force_terminal=True, color_system=None, width=300))], False

    class ConsoleLog:
        def logger(self, level, message):
            sink.warning(message)

    def fetch(url, **kwargs):
        return page if url == "http://example.com/" else web_response("", status=500, url=url)

    summary = {}
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response()), patch("autopwn_suite.web.crawler.get", side_effect=fetch):
        webvuln("http://example.com/", ConsoleLog(), MagicMock(), controls={"speed": 5, "checks": {name: name == "lfi" for name in CHECKS}}, on_complete=summary.update)
    expected = "Unable to crawl http://example.com/x[2J]0;pwnedy: HTTP 500; coverage is incomplete."
    assert expected in summary["issues"]
    assert expected in output.getvalue()
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", output.getvalue() + str(summary["issues"]))
