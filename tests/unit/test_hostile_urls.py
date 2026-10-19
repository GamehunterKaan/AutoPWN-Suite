# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""A URL that a host controls (a crawled link, a redirect) keeps its control and layout characters only as the
percent-encoding the HTTP client puts on the wire, so the recorded requests, the observations, the target and the
generated curl PoC are plain ASCII and replay sends the request that the scan sent (AUTOPWN-SA-2026-016).
Servers listen on 127.0.0.1."""

import socketserver
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest
import requests
from rich.console import Console

from autopwn_suite.text import wire_url
from autopwn_suite.web.findings import finding
from autopwn_suite.web.http import ProbeClient, scoped_get
from autopwn_suite.web.options import CHECKS
from autopwn_suite.web.poc import build_plan, curl_poc, python_poc
from autopwn_suite.web.poc_runtime import verify_plan
from autopwn_suite.web.probes import check_cors
from autopwn_suite.web.runtime import ScanContext, redact_url
from autopwn_suite.web.webvuln import webvuln
from tests.unit.test_hostile_text import FORBIDDEN, FORBIDDEN_EXCEPT_NEWLINE, FORBIDDEN_TEXT, assert_clean

# ESC sequence, BEL, a right-to-left override, a line separator, NEL and a zero-width space in a path and a query value.
HOSTILE_PATH = "/x\x1b[2J\x1b]0;pwn\x07\U0000202e\U00002028y\x85"
HOSTILE_QUERY = "?id=1&p=\U0000200b"
# What is stored for them, and the request target that the HTTP client puts on the wire (it also encodes brackets).
STORED_PATH = "/x%1B[2J%1B]0;pwn%07%E2%80%AE%E2%80%A8y%C2%85"
STORED_QUERY = "?id=1&p=%E2%80%8B"
ON_THE_WIRE = "/x%1B%5B2J%1B%5D0;pwn%07%E2%80%AE%E2%80%A8y%C2%85?id=1&p=%E2%80%8B"


@contextmanager
def recording_server(respond):
    """A 127.0.0.1 server that records the request target of every request and answers with `respond(target, headers)`
    (a status line and header lines as bytes)."""
    requests_seen = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            target = self.rfile.readline().decode("latin-1").split()[1]
            headers = {}
            while True:
                line = self.rfile.readline().decode("latin-1")
                if line in ("\r\n", "\n", ""):
                    break
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
            requests_seen.append(target)
            self.wfile.write(respond(target, headers) + b"Content-Length: 0\r\nConnection: close\r\n\r\n")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], requests_seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def reflect_origin(target, headers):
    return (b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: " + headers.get("origin", "").encode() +
            b"\r\nAccess-Control-Allow-Credentials: true\r\n")


def cors_findings(port):
    """The CORS findings on a crawled link, with the endpoint that the dashboard adds to every stored web finding."""
    url = f"http://127.0.0.1:{port}{HOSTILE_PATH}{HOSTILE_QUERY}"
    log = MagicMock()
    context = ScanContext(f"http://127.0.0.1:{port}/", log)
    with context.activate():
        results = check_cors(ProbeClient(url, log), url, Console(file=MagicMock(), width=300, color_system=None))
    return url, [{**result, "endpoint": redact_url(f"http://127.0.0.1:{port}/")} for result in results]


def test_a_finding_on_a_crawled_link_stores_the_link_as_the_wire_url_everywhere():
    with recording_server(reflect_origin) as (port, scanned):
        url, results = cors_findings(port)
    assert len(results) >= 1 and scanned
    stored = f"http://127.0.0.1:{port}{STORED_PATH}{STORED_QUERY}"
    for result in results:
        assert_clean(result, "stored result")
        assert result["url"] == stored
        assert {row["url"] for row in result["reproduction"]["requests"]} == {stored}
        assert result["observations"] and {row["request"]["url"] for row in result["observations"]} == {stored}
        assert result["reproduction"]["target"] == f"http://127.0.0.1:{port}/"
    # No character that a terminal or a shell reader would act on in the generated PoCs, and plain ASCII in the curl one.
    for result in results:
        assert curl_poc(result).isascii()
        for text in (curl_poc(result), python_poc(result)):
            assert not FORBIDDEN_EXCEPT_NEWLINE.search(text)
        assert f"--url 'http://127.0.0.1:{port}{STORED_PATH}{STORED_QUERY}'" in curl_poc(result)
    # The requests of the scan all had the same target on the wire.
    assert set(scanned) == {ON_THE_WIRE}


def test_replay_sends_the_request_that_the_scan_sent():
    with recording_server(reflect_origin) as (port, requests_seen):
        _, results = cors_findings(port)
        scanned = list(requests_seen)
        requests_seen.clear()
        plan = build_plan(results[0])
        assert verify_plan(plan)["status"] == "reproduced"
        assert requests_seen and set(requests_seen) == set(scanned) == {ON_THE_WIRE}
        assert all(not FORBIDDEN.search(row["url"]) for row in plan["requests"])


def test_a_finding_without_its_own_reproduction_replays_the_url_that_was_probed():
    url = f"http://127.0.0.1:9{HOSTILE_PATH}{HOSTILE_QUERY}"
    context = ScanContext("http://127.0.0.1:9/", MagicMock())
    with context.activate():
        result = finding("HEADERS", url, "evidence")
    stored = f"http://127.0.0.1:9{STORED_PATH}{STORED_QUERY}"
    assert result["url"] == stored
    assert result["reproduction"]["requests"][0]["url"] == stored
    assert_clean(result)


def test_a_redirect_to_a_hostile_path_is_recorded_as_the_wire_url():
    def respond(target, headers):
        if target.startswith("/start"):
            return b"HTTP/1.1 301 Moved Permanently\r\nLocation: /landing\x1b[2J\x07x?id=1\r\n"
        return b"HTTP/1.1 200 OK\r\n"

    with recording_server(respond) as (port, requests_seen):
        origin = f"http://127.0.0.1:{port}"
        context = ScanContext(origin + "/", MagicMock())
        with context.activate():
            scoped_get(requests.get, origin + "/start")
            result = finding("HEADERS", origin + "/start", "evidence", reproduction={"strategy": "response", "requests": [{"url": origin + "/start"}]})
    assert requests_seen == ["/start", "/landing%1B%5B2J%07x?id=1"]
    assert_clean(result, "redirect")
    assert result["reproduction"]["requests"][0]["url"] == origin + "/landing%1B[2J%07x?id=1"
    assert [row["request"]["url"] for row in result["observations"]] == [origin + "/start", origin + "/landing%1B[2J%07x?id=1"]
    assert [row["response"]["headers"].get("Location") for row in result["observations"]] == ["/landing%1B[2J%07x?id=1", None]


def test_the_scan_target_that_a_redirect_chose_is_recorded_as_the_wire_url(web_response):
    summary = {}
    page = web_response("", url="http://example.com/a\x1b[2J\U0000202e\U00002028")
    with patch("autopwn_suite.web.webvuln.get", return_value=page), patch("autopwn_suite.web.crawler.get", return_value=page):
        webvuln("http://example.com/", MagicMock(), MagicMock(), on_complete=summary.update,
                controls={"speed": 5, "checks": {name: False for name in CHECKS}})
    assert summary["target"] == "http://example.com/a%1B[2J%E2%80%AE%E2%80%A8"


@pytest.mark.parametrize("url, expected", [
    ("http://a.test/x\x1b\x07\x00\x7f\x85y", "http://a.test/x%1B%07%00%7F%C2%85y"),
    ("http://a.test/\U0000202e\U00002028\U00002029\U0000200b\U0000feff\U000e0041", "http://a.test/%E2%80%AE%E2%80%A8%E2%80%A9%E2%80%8B%EF%BB%BF%F3%A0%81%81"),
    ("http://a.test/a\r\nb\tc", "http://a.test/a%0D%0Ab%09c"),
    ("http://a.test/x?token=s3cret\x1b&a=b\U00002028c", "http://a.test/x?token=REDACTED&a=b%E2%80%A8c"),
    ("http://a.test/café ok", "http://a.test/café ok"),
])
def test_redact_url_encodes_the_characters_a_terminal_acts_on(url, expected):
    assert redact_url(url) == expected
    assert not FORBIDDEN.search(redact_url(url))


def test_every_encoded_character_is_encoded_as_the_http_client_sends_it():
    """No character can be encoded differently from the wire: the stored URL would then name another request."""
    for char in FORBIDDEN_TEXT:
        url = f"http://a.test/p{char}q?x=1"
        if 0xD800 <= ord(char) <= 0xDFFF:
            # No client can send a lone surrogate; the stored URL is still plain text.
            assert wire_url(url).isascii() and not FORBIDDEN.search(wire_url(url))
            continue
        assert wire_url(url) == requests.Request("GET", url).prepare().url == f"http://a.test/p{quote(char, safe='')}q?x=1", hex(ord(char))
    assert wire_url("http://a.test/caf\u00e9 \u65e5\u672c") == "http://a.test/caf\u00e9 \u65e5\u672c" and wire_url(None) is None
