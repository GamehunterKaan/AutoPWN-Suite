from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.webvuln import target_urls, web_endpoints, webvuln


@pytest.fixture(autouse=True)
def isolate_additional_checks():
    with patch("modules.web.webvuln.additional_checks", return_value=[]):
        yield


@pytest.mark.unit
def test_no_endpoint_is_logged_and_stops_before_other_checks():
    log, console = MagicMock(), MagicMock()
    with patch("modules.web.webvuln.get", side_effect=ConnectionError) as get, patch("modules.web.webvuln.crawl") as crawl, patch("modules.web.webvuln.dirbust") as dirs:
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
    with patch("modules.web.webvuln.get", return_value=web_response("<html>Home</html>", url=url)), patch("modules.web.webvuln.crawl", return_value={url}), patch("modules.web.webvuln.dirbust", return_value=[]) as dirs:
        findings = webvuln("example.com", log, console)
    assert dirs.call_args.args[:2] == (url, console)
    assert findings and all(item["type"] == "WEB_CONFIG" for item in findings)
    log.logger.assert_any_call("info", "Found 0 testable urls.")


@pytest.mark.unit
def test_scanners_aggregate_structured_results_and_filter_off_origin_urls(web_response):
    url, probe = "http://example.com/", "http://example.com/page?id=1"
    with patch("modules.web.webvuln.get", return_value=web_response(url=url)), patch("modules.web.webvuln.inspect_response", return_value=[]), patch("modules.web.webvuln.dirbust", return_value=[{"type": "DIR"}]), patch("modules.web.webvuln.crawl", return_value={probe, "http://external.com/page?id=1", "http://example.com/static"}), patch("modules.web.webvuln.LFIScanner") as lfi, patch("modules.web.webvuln.SQLIScanner") as sql, patch("modules.web.webvuln.XSSScanner") as xss:
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
    with patch("modules.web.webvuln.get") as get:
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
    from modules.web.options import CHECKS
    controls = {"max_endpoints": 1, "checks": {name: name in ("sqli", "xss", "lfi") for name in CHECKS}}
    url = "http://example.com/"
    summary = {}
    with patch("modules.web.webvuln.get", return_value=web_response(url=url)), \
         patch("modules.web.webvuln.crawl", return_value={url + "a?id=1", url + "b?id=1"}), \
         patch("modules.web.webvuln.LFIScanner") as lfi, patch("modules.web.webvuln.SQLIScanner") as sql, patch("modules.web.webvuln.XSSScanner") as xss:
        for scanner, method in ((lfi, "test_lfi"), (sql, "test_sqli"), (xss, "test_xss")):
            getattr(scanner.return_value, method).return_value = []
        webvuln(url, MagicMock(), MagicMock(), controls=controls, on_complete=summary.update)
    for scanner, method in ((lfi, "test_lfi"), (sql, "test_sqli"), (xss, "test_xss")):
        getattr(scanner.return_value, method).assert_called_once_with(url + "a?id=1")
    assert summary["status"] == "partial"
    assert "Injection endpoint budget reached; coverage is limited." in summary["issues"]
