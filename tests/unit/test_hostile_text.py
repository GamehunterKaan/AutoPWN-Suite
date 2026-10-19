# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Text that a host or a data provider controls reaches the console, stored results and saved reports as one
line, without control, bidirectional or zero-width characters (AUTOPWN-SA-2026-016): the cleaning function, the
log and the web scan. Servers listen on 127.0.0.1 and everything else is built in memory."""

import http.client
import io
import logging
import re
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from unittest.mock import MagicMock, mock_open, patch
from urllib.parse import urlsplit

import pytest
import requests
import urllib3
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

from autopwn_suite.logger import Logger, banner, console_safe
from autopwn_suite.web.dirbust import dirbust
from autopwn_suite.web.findings import emit, finding, printable
from autopwn_suite.web.options import CHECKS
from autopwn_suite.web.runtime import ScanContext, redact_text
from autopwn_suite.web.webvuln import webvuln

# What must never reach the output, written out by name and separately from the implementation. Only the line feed
# may stay in multi-line text.
CONTROLS = "".join(chr(code) for code in (*range(0x00, 0x20), *range(0x7F, 0xA0)))  # C0 (ESC, CR, tab, LF), DEL, C1 (NEL)
SEPARATORS = "\U00002028\U00002029"
BIDI = ("\U0000061c\U0000200e\U0000200f\U0000202a\U0000202b\U0000202c\U0000202d\U0000202e"
        "\U00002066\U00002067\U00002068\U00002069")
ZERO_WIDTH = "\U0000180e\U0000200b\U0000200c\U0000200d\U00002060\U0000feff"
# Word joiner to the deprecated format characters (U+2060 to U+206F), interlinear annotation and the tag characters.
OTHER_FORMAT = "".join(map(chr, (*range(0x2060, 0x2070), *range(0xFFF9, 0xFFFC), *range(0xE0000, 0xE0080))))
SURROGATES = "".join(map(chr, range(0xD800, 0xE000)))  # no UTF-8 stream can write one
FORBIDDEN_TEXT = CONTROLS + SEPARATORS + BIDI + ZERO_WIDTH + OTHER_FORMAT + SURROGATES
FORBIDDEN = re.compile("[" + re.escape(FORBIDDEN_TEXT) + "]")
FORBIDDEN_EXCEPT_NEWLINE = re.compile("[" + re.escape(FORBIDDEN_TEXT.replace("\n", "")) + "]")

# Every class at once: ESC sequence, BEL, NEL, line and paragraph separator, right-to-left override, zero-width space.
HOSTILE = "a\x1b[2J\x1b]0;pwned\x07b\x85c\U00002028d\U00002029e\U0000202ef\U0000200bg"
HOSTILE_CLEAN = "a[2J]0;pwnedbc d efg"
HOSTILE_WIRE = "a%1B[2J%1B]0;pwned%07b%C2%85c%E2%80%A8d%E2%80%A9e%E2%80%AEf%E2%80%8Bg"


def strings(value):
    """Every string inside a nested structure, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from strings(item)


def assert_clean(value, what=""):
    for text in strings(value):
        assert not FORBIDDEN.search(text), (what, text)


# ── printable and console_safe ───────────────────────────────────────────────

def expected_character(char, multiline):
    if char == "\n":
        return "\n" if multiline else " "
    if char in "\t\U00002028\U00002029":
        return " "
    return "" if char in FORBIDDEN_TEXT else char


@pytest.mark.parametrize("multiline", [False, True])
def test_every_code_point_is_kept_removed_or_turned_into_a_space(multiline):
    everything = "".join(map(chr, range(0x110000)))
    expected = "".join(expected_character(char, multiline) for char in everything)
    assert printable(everything, multiline=multiline) == expected
    cleaned = printable(everything, multiline=multiline)
    assert printable(cleaned, multiline=multiline) == cleaned
    assert not (FORBIDDEN_EXCEPT_NEWLINE if multiline else FORBIDDEN).search(cleaned)
    # No character is left that any line-splitting routine would treat as a line boundary.
    assert len(cleaned.splitlines()) <= (cleaned.count("\n") + 1 if multiline else 1)


@pytest.mark.parametrize("text, single_line, multi_line", [
    ("a\nb", "a b", "a\nb"),
    ("a\tb", "a b", "a b"),
    ("a\r\n b", "a  b", "a\n b"),
    ("a\U00002028b\U00002029c", "a b c", "a b c"),
    ("one\rtwo\x0bthree\x0cfour\x85five", "onetwothreefourfive", "onetwothreefourfive"),
    ("\x1b[2J\x1b]0;t\x07\x08\x00\x1f\x7f", "[2J]0;t", "[2J]0;t"),
    ("csi\x9b2J\x9d0;t\x9c", "csi2J0;t", "csi2J0;t"),
    ("a\U0000202eb\U0000202ac\U00002066d\U00002069e\U0000200ef\U0000200fg\U0000061ch", "abcdefgh", "abcdefgh"),
    ("a\U0000200bb\U0000200cc\U0000200dd\U00002060e\U0000feffg\U0000180eh", "abcdegh", "abcdegh"),
    ("tag\U000e0041\U000e007f", "tag", "tag"),
    ("Türkçe 日本語 😀 العربية", "Türkçe 日本語 😀 العربية", "Türkçe 日本語 😀 العربية"),
])
def test_printable_character_classes(text, single_line, multi_line):
    assert printable(text) == single_line
    assert printable(text, multiline=True) == multi_line


def test_printable_leaves_values_that_are_not_text_alone():
    assert printable(None) is None and printable(7) == 7 and printable(b"x\x1b") == b"x\x1b"


def test_console_safe_removes_the_characters_before_it_escapes_markup():
    # Escaping first would leave "[\x00/red]" as markup once the NUL is gone, and Rich would raise MarkupError.
    assert Text.from_markup(console_safe("[\x00/red]x\U0000202e"), emoji=False).plain == "[/red]x"
    assert Text.from_markup(console_safe(HOSTILE), emoji=False).plain == HOSTILE_CLEAN
    assert console_safe(None) == "None"


def test_log_lines_keep_their_own_newlines_but_nothing_that_drives_a_terminal():
    logger = Logger(MagicMock())
    logger.log = MagicMock()
    logger.logger("warning", "You need to be root.\nChanged scan mode.")
    logger.log.warning.assert_called_with("[*] You need to be root.\nChanged scan mode.")
    logger.logger("error", HOSTILE)
    logger.log.error.assert_called_with("[-] " + HOSTILE_CLEAN)
    logger.logger("info", ValueError("bad\x1b[2J"))
    logger.log.info.assert_called_with("[+] bad[2J")


def test_banners_are_one_clean_line():
    console = MagicMock()
    with patch("autopwn_suite.logger.get_terminal_width", return_value=40):
        banner("Testing http://a.test/" + HOSTILE + "\nFORGED", "green", console)
    assert console.print.call_args_list[1].args[0] == Text("Testing http://a.test/" + HOSTILE_CLEAN + " FORGED")


# ── web scan: findings, log lines, coverage notes and captured headers ───────

@contextmanager
def raw_server(respond):
    """A 127.0.0.1 server that writes the bytes `respond(path)` returns, so a header can be malformed on purpose."""
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            path = self.rfile.readline().decode("latin-1").split()[1]
            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                pass
            self.wfile.write(respond(path))

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


# The case that AUTOPWN-SA-2026-016 reproduced: the continuation line of a folded Location header used to start a
# console line of its own.
FOLDED_RESPONSE = (b"HTTP/1.1 301 Moved Permanently\r\nLocation: /admin/\r\n"
                   b" [+] DIR (observation, info): http://127.0.0.1/admin - FORGED line\r\n"
                   b"Content-Length: 0\r\nConnection: close\r\n\r\n")
MISSING_RESPONSE = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def serve_the_fold(path):
    return MISSING_RESPONSE if "__autopwn_missing_" in path else FOLDED_RESPONSE


def assert_the_fold_stays_on_one_console_line(found, output):
    assert len(found) == 1 and "\n" not in found[0]["evidence"] and "FORGED line" in found[0]["evidence"]
    lines = output.getvalue().splitlines()
    assert len(lines) == 1 and lines[0].startswith("[+] DIR (observation, info): http://127.0.0.1:")
    assert lines[0].endswith("FORGED line")


def test_a_header_with_an_obsolete_line_fold_cannot_forge_a_result_line():
    """Through the HTTP client that the scanner uses. Only a client that does not deliver the continuation line at all
    skips the test (it cannot send the fold); the variant below parses the bytes itself and always runs."""
    output = io.StringIO()
    console = Console(file=output, width=1000, color_system=None)
    with raw_server(serve_the_fold) as port, patch("autopwn_suite.web.dirbust.open", mock_open(read_data="admin")):
        if "FORGED line" not in requests.get(f"http://127.0.0.1:{port}/admin", allow_redirects=False, timeout=5).headers.get("Location", ""):
            pytest.skip(f"requests {requests.__version__} with urllib3 {urllib3.__version__} drops the continuation line of an obsolete line fold")
        found = dirbust(f"http://127.0.0.1:{port}", console, MagicMock())
    assert_the_fold_stays_on_one_console_line(found, output)


def test_a_folded_header_read_from_the_raw_bytes_cannot_forge_a_result_line(web_response):
    """The same response, read from a plain socket and parsed with the standard library, so no HTTP client can
    decide to drop the fold: this variant never skips."""
    def read_through_a_socket(url, **kwargs):
        parts = urlsplit(url)
        with socket.create_connection((parts.hostname, parts.port), timeout=5) as connection:
            connection.sendall(f"GET {parts.path}?{parts.query} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n".encode())
            raw = b""
            while chunk := connection.recv(4096):
                raw += chunk
        head, _, body = raw.partition(b"\r\n\r\n")
        status_line, _, header_lines = head.partition(b"\r\n")
        headers = http.client.parse_headers(io.BytesIO(header_lines + b"\r\n\r\n"))
        status = int(status_line.split()[1])
        assert status != 301 or "FORGED line" in headers["Location"]  # the standard parser keeps the fold
        return web_response(body, status=status, url=url, headers=dict(headers.items()))

    output = io.StringIO()
    console = Console(file=output, width=1000, color_system=None)
    with raw_server(serve_the_fold) as port, patch("autopwn_suite.web.dirbust.open", mock_open(read_data="admin")), \
         patch("autopwn_suite.web.dirbust.get", side_effect=read_through_a_socket):
        found = dirbust(f"http://127.0.0.1:{port}", console, MagicMock())
    assert_the_fold_stays_on_one_console_line(found, output)


def test_findings_are_one_line_without_control_or_layout_characters():
    result = finding("X", "http://example.com/a" + HOSTILE, "one\ntwo\tthree\r\x07\x7f\x85" + HOSTILE, parameter="q" + HOSTILE)
    # A URL keeps the characters as the percent-encoding that the HTTP client sends; see test_hostile_urls.py.
    assert result["url"] == "http://example.com/a" + HOSTILE_WIRE
    assert result["parameter"] == "q" + HOSTILE_CLEAN
    assert result["evidence"] == "one two three" + HOSTILE_CLEAN
    assert finding("X", "http://example.com/", "plain", parameter=None)["parameter"] is None


def test_a_finding_prints_as_one_line_even_when_the_result_was_not_built_by_finding():
    output = io.StringIO()
    console = Console(file=output, width=1000, color_system=None)
    for result in (finding("CORS", "http://example.com/?a=1" + HOSTILE, "first\nsecond\U00002028third"),
                   {"type": "DIR", "confidence": "observation", "severity": "info", "url": "http://example.com/x\ny",
                    "evidence": "one\n[+] FORGED\x1b[2J\U0000202e"}):
        emit(console, result)
    lines = output.getvalue().splitlines()
    assert len(lines) == 2 and all(line.startswith("[+] ") for line in lines)
    assert not FORBIDDEN.search(output.getvalue().replace("\n", ""))


def test_crawled_link_text_never_reaches_the_log_or_the_coverage_notes_with_layout_characters(web_response):
    link = "/x\U00002028\U0000202ey\U0000200bz\U00002029end"
    page = web_response(f'<a href="{link}">link</a>', headers={"Content-Type": "text/html"})
    output = io.StringIO()
    sink = logging.getLogger("autopwn-test-hostile-text")
    sink.handlers, sink.propagate = [RichHandler(console=Console(file=output, width=300, color_system=None))], False

    class ConsoleLog:
        def logger(self, level, message):
            sink.warning(message)

    def fetch(url, **kwargs):
        return page if url == "http://example.com/" else web_response("", status=500, url=url)

    summary = {}
    with patch("autopwn_suite.web.webvuln.get", return_value=web_response()), patch("autopwn_suite.web.crawler.get", side_effect=fetch):
        webvuln("http://example.com/", ConsoleLog(), MagicMock(), controls={"speed": 5, "checks": {name: name == "lfi" for name in CHECKS}},
                on_complete=summary.update)
    expected = "Unable to crawl http://example.com/x yz end: HTTP 500; coverage is incomplete."
    assert summary["issues"] == [expected]
    assert expected in output.getvalue()
    assert not FORBIDDEN_EXCEPT_NEWLINE.search(output.getvalue())


def test_a_coverage_issue_and_its_log_line_are_one_clean_line():
    log = MagicMock()
    context = ScanContext("http://example.com/", log)
    context.issue("Unable to crawl http://a.test/x?token=1\U00002028\U0000202e\nFORGED: HTTP 500")
    # The line separator belongs to the value of the URL, which is redacted whole; only the line feed is left as a space.
    expected = "Unable to crawl http://a.test/x?token=REDACTED FORGED: HTTP 500"
    assert context.issues == [expected]
    log.logger.assert_called_once_with("warning", expected)
    assert redact_text("one\ntwo\tthree\r\x85\x7f\U00002028four") == "one two three four"


def test_response_headers_kept_with_a_finding_are_cleaned(web_response):
    context = ScanContext("http://example.test/", MagicMock())
    response = web_response("", headers={"Server": "nginx\x85\U0000202e\x1b[2J", "Location": "/a\U00002028b",
                                         "Content-Type": "text/html\x0b"})
    response.autopwn_truncated = False
    captured = context.capture(response, "GET", "http://example.test/", {}, time.monotonic())
    assert captured["response"]["headers"] == {"Server": "nginx[2J", "Location": "/a%E2%80%A8b", "Content-Type": "text/html"}


def test_a_certificate_name_that_the_target_chose_is_cleaned():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from autopwn_suite.web.tls import inspect_certificate
    now, key = datetime.now(timezone.utc), ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ex\x1b[2J\x07\U0000202e\U00002028ample\x85")])
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
           .not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=30))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("other.example")]), critical=False)
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    context = ScanContext("https://example.com/", MagicMock())
    with context.activate():
        results = inspect_certificate("https://example.com/", der)
    assert results and results[0]["reproduction"]["certificate"]["subject"] == "CN=ex[2J ample"
    assert_clean(results, "certificate result")
