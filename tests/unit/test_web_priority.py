"""Critical injection work must survive large crawls and limited request budgets."""

from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

from modules.web.options import CHECKS
from modules.web.planning import prioritize_urls, skip_discovered_url
from modules.web.webvuln import webvuln


def test_file_inputs_and_diverse_endpoint_shapes_precede_query_variations():
    urls = {f"http://example.test/list?id={number}" for number in range(1000)}
    urls |= {"http://example.test/mutillidae/index.php?page=home.php", "http://example.test/another?search=one"}
    ordered = prioritize_urls(urls)
    assert ordered[0].endswith("index.php?page=home.php")
    assert {urlsplit(url).path for url in ordered[:3]} == {"/list", "/another", "/mutillidae/index.php"}
    assert set(ordered) == urls


def test_file_input_is_not_lost_behind_low_priority_parameters():
    from modules.web.runtime import ScanContext
    from modules.web.query import parameter_indexes
    params = ["sort=name", "limit=10", "offset=0", "view=list", "lang=en", "file=readme.txt"]
    context = ScanContext("http://example.test/", MagicMock(), controls={"max_parameters": 1})
    with context.activate():
        assert list(parameter_indexes(params)) == [5]
    assert any("Query parameter limit" in issue for issue in context.issues)


@pytest.mark.parametrize("url", [
    "http://example.test/set-up-database.php", "http://example.test/index.php?do=toggle-security&page=home.php",
    "http://example.test/index.php?page=reset-database.php", "http://example.test/a?drop=users",
    "http://example.test/logout", "http://example.test/image.png", "http://example.test/app.js?v=1",
    "http://example.test/documentation/installation.pdf",
])
def test_destructive_actions_and_static_assets_are_not_crawled(url):
    assert skip_discovered_url(url)


@pytest.mark.parametrize("url", [
    "http://example.test/index.php?page=home.php", "http://example.test/image.jpg?file=readme",
    "http://example.test/search?query=reset", "http://example.test/change-log.htm",
])
def test_routed_pages_and_dynamic_download_inputs_are_preserved(url):
    assert not skip_discovered_url(url)


def test_root_scan_finds_lfi_before_crawl_exhausts_request_budget(web_response):
    root = "http://example.test/"
    app = root + "mutillidae/"
    parameter_url = app + "index.php?page=home.php"
    requested = []
    found_at = []
    summary = {}

    def respond(url, **kwargs):
        requested.append(url)
        parts = urlsplit(url)
        if parts.path == "/":
            text = '<a href="/mutillidae/">Application</a>'
        elif parts.path == "/mutillidae/":
            text = '<a href="index.php?page=home.php">Page</a><a href="set-up-database.php">Setup</a>'
        elif "etc/passwd" in parse_qs(parts.query).get("page", [""])[0]:
            text = "<html><pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false</pre></html>"
        else:
            text = "<html>Normal page</html>" + ''.join(f'<a href="?page=home.php&item={number}">{number}</a>' for number in range(100))
        return web_response(text, url=url, headers={"Content-Type": "text/html"})

    controls = {"request_budget": 20, "max_pages": 100, "max_urls": 1000,
                "checks": {name: name == "lfi" for name in CHECKS}}
    with patch("modules.web.webvuln.get", side_effect=respond), \
         patch("modules.web.crawler.get", side_effect=respond), \
         patch("modules.web.lfi.get", side_effect=respond):
        findings = webvuln(root, MagicMock(), MagicMock(), controls=controls,
                           on_finding=lambda result: found_at.append(len(requested)), on_complete=summary.update)
    assert findings and findings[0]["type"] == "LFI"
    assert findings[0]["parameter"] == "page"
    assert found_at[0] < 10
    assert summary["status"] == "partial" and summary["requests"] == 20
    assert any("Request budget reached" in issue for issue in summary["issues"])
    assert parameter_url in requested
    assert not any("set-up-database" in url for url in requested)


def test_high_impact_classes_finish_before_secondary_checks(web_response):
    events = []
    url = "http://example.test/app?page=home.php"
    with patch("modules.web.webvuln.get", return_value=web_response(url=url)), \
         patch("modules.web.webvuln.crawl", return_value={url}), \
         patch("modules.web.webvuln.LFIScanner") as lfi, \
         patch("modules.web.webvuln.SQLIScanner") as sql, \
         patch("modules.web.webvuln.XSSScanner") as xss, \
         patch("modules.web.webvuln.critical_checks", side_effect=lambda *a: events.append("boolean") or []), \
         patch("modules.web.webvuln.dirbust", side_effect=lambda *a: events.append("directories") or []), \
         patch("modules.web.webvuln.additional_checks", side_effect=lambda *a, **k: events.append("advisories") or []), \
         patch("modules.web.webvuln.inspect_response", return_value=[]):
        lfi.return_value.test_lfi.side_effect = lambda *a: events.append("lfi") or []
        sql.return_value.test_sqli.side_effect = lambda *a: events.append("sqli") or []
        xss.return_value.test_xss.side_effect = lambda *a: events.append("xss") or []
        webvuln(url, MagicMock(), MagicMock())
    assert events == ["lfi", "sqli", "boolean", "xss", "directories", "advisories"]
