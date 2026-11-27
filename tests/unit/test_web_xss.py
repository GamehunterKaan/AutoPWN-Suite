# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import html
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from requests.exceptions import ConnectionError

from autopwn_suite.web.xss import XSSScanner, reflection_context


@pytest.mark.unit
@pytest.mark.parametrize("context", ["<body>{}</body>", '<input value="{}">'])
def test_active_reflection_is_candidate(web_response, context):
    scanner = XSSScanner(MagicMock(), MagicMock())

    def respond(url, **kwargs):
        value = parse_qs(urlsplit(url).query)["q"][0]
        return web_response(context.format(value), url=url, headers={"Content-Type": "text/html"})

    with patch("autopwn_suite.web.xss.get", side_effect=respond):
        found = scanner.test_xss("http://example.com/search?q=hello")
    assert len(found) == 1
    assert found[0]["confidence"] == "candidate"
    assert "browser execution not verified" in found[0]["evidence"]


@pytest.mark.unit
@pytest.mark.parametrize("context,mime", [
    ("{}", "application/json"), ("{}", "text/plain"),
    ("<!-- {} -->", "text/html"), ("<textarea>{}</textarea>", "text/html"),
    ("<template>{}</template>", "text/html"), ("<title>{}</title>", "text/html"),
    ('<script type="application/json">{}</script>', "text/html"),
])
def test_raw_reflection_in_inactive_context_is_not_xss(web_response, context, mime):
    scanner = XSSScanner(MagicMock(), MagicMock())
    scanner.xss_test = ["<script>alert('PAYLOAD')</script>"]

    def respond(url, **kwargs):
        value = parse_qs(urlsplit(url).query)["q"][0]
        return web_response(context.format(value), url=url, headers={"Content-Type": mime})

    with patch("autopwn_suite.web.xss.get", side_effect=respond):
        assert scanner.test_xss("http://example.com/search?q=hello") == []
    scanner.console.print.assert_not_called()


@pytest.mark.unit
def test_html_escaped_reflection_is_not_xss(web_response):
    scanner = XSSScanner(MagicMock(), MagicMock())
    with patch("autopwn_suite.web.xss.get", side_effect=lambda url, **kwargs: web_response(html.escape(parse_qs(urlsplit(url).query)["q"][0]))):
        assert scanner.test_xss("http://example.com/search?q=hello") == []


@pytest.mark.unit
def test_second_payload_and_query_context_are_preserved(web_response):
    scanner = XSSScanner(MagicMock(), MagicMock())
    scanner.xss_test = ["<script>PAYLOAD</script>", "<img onerror='PAYLOAD'>"]

    def respond(url, **kwargs):
        params = parse_qs(urlsplit(url).query)
        assert params["token"] == ["a&b"] or params["q"] == ["original"]
        value = params["q"][0]
        return web_response(value if value.startswith("<img") else "safe", url=url)

    with patch("autopwn_suite.web.xss.get", side_effect=respond) as get:
        found = scanner.test_xss("http://example.com/search?q=original&token=a%26b#fragment")
    assert len(found) == 1
    assert "HTML event handler" in found[0]["evidence"]
    assert all(not urlsplit(call.args[0]).fragment for call in get.call_args_list)


@pytest.mark.unit
def test_connection_error_and_no_query():
    scanner = XSSScanner(MagicMock(), MagicMock())
    with patch("autopwn_suite.web.xss.get", side_effect=ConnectionError) as get:
        assert scanner.test_xss("http://example.com/page") == []
        get.assert_not_called()
        assert scanner.test_xss("http://example.com/page?q=test") == []
    scanner.log.logger.assert_called_once()


MARKER = "AbCdEfGhIjKlMnOp"
ESCAPED_STATE = '<script>var state={{"q":"{}"}};</script>'


def json_copy(payload):
    """The payload as a JSON string in a script: markup escaped, the marker still in the script text."""
    return payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\'").replace('"', '\\"')


@pytest.mark.unit
@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("raw", ['<input name="q" value="{}">', "<!-- {} -->", "<textarea>{}</textarea>"])
def test_inert_reflection_beside_an_escaped_script_copy_is_not_xss(web_response, raw, index):
    # Issue #125: the raw payload is inert, and the only script holding the marker has an escaped copy of it.
    payload = XSSScanner(MagicMock(), MagicMock()).xss_test[index].replace("PAYLOAD", MARKER)
    page = "<html><body>" + raw.format(payload) + ESCAPED_STATE.format(json_copy(payload)) + "</body></html>"
    assert reflection_context(web_response(page, headers={"Content-Type": "text/html"}), payload, MARKER) is None


@pytest.mark.unit
@pytest.mark.parametrize("index,page,context", [
    (0, "<html><body>{}</body></html>", "script element"),
    (1, "<html><body>{}</body></html>", "HTML event handler"),
    (2, '<html><body><input value="{}"></body></html>', "HTML event handler"),
    (3, "<html><body><textarea>{}</textarea></body></html>", "script element"),
])
def test_each_payload_is_found_in_the_context_it_creates(web_response, index, page, context):
    payload = XSSScanner(MagicMock(), MagicMock()).xss_test[index].replace("PAYLOAD", MARKER)
    # An escaped copy in an earlier script does not hide the script or handler the payload created.
    body = ESCAPED_STATE.format(json_copy(payload)) + page.format(payload)
    assert reflection_context(web_response(body, headers={"Content-Type": "text/html"}), payload, MARKER) == context


@pytest.mark.unit
@pytest.mark.parametrize("index", [0, 1, 2, 3])
@pytest.mark.parametrize("script", ['<script>var q="{}";</script>', "<script>var state={{\"q\":'{}'}};</script>"])
def test_payload_reflected_raw_inside_an_existing_script_is_found(web_response, index, script):
    # The payload creates no element of its own here, but its raw markup breaks out of the script around it.
    payload = XSSScanner(MagicMock(), MagicMock()).xss_test[index].replace("PAYLOAD", MARKER)
    page = "<html><body>" + script.format(payload) + "</body></html>"
    assert reflection_context(web_response(page, headers={"Content-Type": "text/html"}), payload, MARKER) == "script element"
