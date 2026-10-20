# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import re
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

from autopwn_suite.web.boolean_sqli import BooleanSQLIScanner
from autopwn_suite.web.http import ProbeClient


@pytest.mark.unit
def test_two_distinct_boolean_pairs_preserve_other_query_inputs(web_response):
    client = ProbeClient("http://example.com/", MagicMock())
    comparisons = []
    def respond(method, url, **kwargs):
        params = parse_qs(urlsplit(url).query)
        assert params["token"] == ["a&b"] or params["id"] == ["1"]
        value = params["id"][0]
        comparison = re.search(r" AND (\d+)=(\d+)", value)
        if comparison:
            comparisons.append(comparison.groups())
        content = "<html><h1>Record exists</h1><p>Useful result with substantial content</p></html>"
        if comparison and comparison[1] != comparison[2]:
            content = "<html><h1>No matching records</h1></html>"
        return web_response(content, headers={"Content-Type": "text/html"})
    with patch("autopwn_suite.web.http.request", side_effect=respond):
        result = BooleanSQLIScanner(client, MagicMock()).test("http://example.com/item?id=1&token=a%26b")
    assert len(result) == 1 and result[0]["type"] == "SQLI_BOOLEAN"
    assert result[0]["parameter"] == "id"
    assert len({left for left, right in comparisons if left == right}) == 2


@pytest.mark.unit
@pytest.mark.parametrize("behavior", ["unchanged", "reflection", "validation_error", "varying_status", "unstable"])
def test_generic_differences_are_not_boolean_sqli(web_response, behavior):
    client = ProbeClient("http://example.com/", MagicMock())
    calls = []
    def respond(method, url, **kwargs):
        calls.append(url)
        value = parse_qs(urlsplit(url).query)["id"][0]
        content, status = "<html>Normal page</html>", 200
        if behavior == "reflection":
            content = f"<html>You searched for {value}</html>"
        if behavior == "validation_error" and "AND" in value:
            content = "sqlite3.OperationalError"
        if behavior == "varying_status" and "AND" in value:
            status = 403
        if behavior == "unstable" and len(calls) == 2:
            content = "Entirely different second page"
        return web_response(content, status=status)
    with patch("autopwn_suite.web.http.request", side_effect=respond):
        assert BooleanSQLIScanner(client, MagicMock()).test("http://example.com/item?id=1") == []


@pytest.mark.unit
def test_query_parameter_and_request_limits_are_reported(web_response):
    log = MagicMock()
    client = ProbeClient("http://example.com/", log, max_requests=2)
    with patch("autopwn_suite.web.http.request", return_value=web_response("stable baseline")) as request:
        assert BooleanSQLIScanner(client, MagicMock(), max_parameters=1).test("http://example.com/item?a=1&b=2") == []
    assert request.call_count == 2
    assert any("coverage is limited" in call.args[1] for call in log.logger.call_args_list)
