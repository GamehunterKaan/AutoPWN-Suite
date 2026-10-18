# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from unittest.mock import MagicMock, mock_open, patch

import pytest

from autopwn_suite.web.content import inspect_content
from autopwn_suite.web.dirbust import dirbust


@pytest.mark.unit
@pytest.mark.parametrize("path,body,kind", [
    ("/.env", "DB_HOST=localhost\nDB_PASSWORD=do-not-print-this-secret\n", "EXPOSED_FILE"),
    ("/.git/HEAD", "ref: refs/heads/main\n", "EXPOSED_FILE"),
    ("/.git/config", '[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = private-repository\n', "EXPOSED_FILE"),
    ("/config.php.bak", '<?php $password = "do-not-print-this-secret";', "EXPOSED_FILE"),
    ("/backup.sql", "-- MySQL dump\nCREATE TABLE private_records (id int);", "EXPOSED_FILE"),
    ("/web.config", '<configuration><connectionStrings>private-connection</connectionStrings></configuration>', "EXPOSED_FILE"),
    ("/backup.zip", b"PK\x03\x04private-archive", "EXPOSED_FILE"),
    ("/backup.tar.gz", b"\x1f\x8bprivate-archive", "EXPOSED_FILE"),
    ("/phpinfo.php", '<html><title>phpinfo()</title><h1>PHP Version 8</h1>private-environment</html>', "DEBUG_DISCLOSURE"),
])
def test_structured_content_is_detected_without_leaking_values(web_response, path, body, kind):
    console = MagicMock()
    results = inspect_content("http://example.com" + path, web_response(body), console)
    assert any(item["type"] == kind for item in results)
    output = str(results) + str(console.print.call_args_list)
    for private in ("do-not-print-this-secret", "private-repository", "private_records", "private-connection", "private-archive", "private-environment"):
        assert private not in output


@pytest.mark.unit
@pytest.mark.parametrize("body", ["Sign in", "<html><body>DB_HOST=a\nDB_PASSWORD=secret</body></html>", "DB_HOST=a", "This page describes .env files"])
def test_login_pages_and_unstructured_content_are_not_exposed_files(web_response, body):
    assert inspect_content("http://example.com/.env", web_response(body), MagicMock()) == []


@pytest.mark.unit
def test_directory_listing_requires_index_heading_and_real_child_links(web_response):
    body = '<html><title>Index of /backup/</title><a href="../">Parent</a><a href="?sort=one">Sort</a><a href="one.zip">One</a><a href="two.zip">Two</a></html>'
    result = inspect_content("http://example.com/backup/", web_response(body), MagicMock())
    assert [item["type"] for item in result] == ["DIR_LISTING"]
    assert inspect_content("http://example.com/backup/", web_response('<h1>Index of /backup/</h1><a href="https://external.com/one">External</a>'), MagicMock()) == []


@pytest.mark.unit
@pytest.mark.parametrize("trace", [
    'Traceback (most recent call last):\n File "/private/app.py", line 10\nValueError: private-value',
    'Fatal error: Uncaught RuntimeException in /private/app.php\nStack trace: private-value',
    'RuntimeException: private-value\n at com.example.App.run(App.java:15)',
    'Server Error in / Application.\nStack Trace: private-value',
])
def test_error_trace_requires_error_response_and_omits_trace(web_response, trace):
    console = MagicMock()
    results = inspect_content("http://example.com/failure", web_response(trace, status=500), console)
    assert len(results) == 1
    assert results[0]["type"] == "ERROR_DISCLOSURE"
    assert "private-value" not in str(results) + str(console.print.call_args_list)
    assert inspect_content("http://example.com/docs", web_response(trace, status=200), MagicMock()) == []


@pytest.mark.unit
def test_canonical_directory_redirect_is_inspected_without_external_follow(web_response):
    def respond(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        if "__autopwn_missing_" in url:
            return web_response("missing", status=404, url=url)
        if url.endswith("/backup"):
            return web_response(status=301, url=url, headers={"Location": "/backup/"})
        return web_response('<title>Index of /backup/</title><a href="a.zip">A</a><a href="b.zip">B</a>', url=url)
    with patch("autopwn_suite.web.dirbust.open", mock_open(read_data="backup")), patch("autopwn_suite.web.dirbust.get", side_effect=respond) as get:
        result = dirbust("http://example.com/", MagicMock(), MagicMock())
    assert [item["type"] for item in result] == ["DIR", "DIR_LISTING"]
    assert get.call_count == 4


@pytest.mark.unit
def test_malformed_directory_links_do_not_crash_content_checks(web_response):
    body = '<title>Index of /</title><a href="http://[broken">Bad</a><a href="one">One</a><a href="two">Two</a>'
    assert [item["type"] for item in inspect_content("http://example.com/", web_response(body), MagicMock())] == ["DIR_LISTING"]
