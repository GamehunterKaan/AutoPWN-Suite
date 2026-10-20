# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from requests.exceptions import ConnectionError

from autopwn_suite.web.sqli import SQLIScanner


@pytest.mark.unit
@pytest.mark.parametrize("error", [
    "You have an error in your SQL syntax", "ORA-01756: quoted string not properly terminated",
    "psycopg2.errors.SyntaxError", "sqlite3.OperationalError: near x: syntax error",
    "Unclosed quotation mark after the character string",
])
def test_repeatable_new_database_error_is_candidate(web_response, error):
    scanner = SQLIScanner(MagicMock(), MagicMock())
    url = "http://example.com/item?id=1&category=news&token=a%26b#details"

    def respond(probe, **kwargs):
        params = parse_qs(urlsplit(probe).query)
        assert params["token"] == ["a&b"] or params["id"] == ["1"]
        assert not urlsplit(probe).fragment
        assert kwargs["allow_redirects"] is False
        return web_response(error if params["id"] == ["'1"] else "Normal page", url=probe)

    with patch("autopwn_suite.web.sqli.get", side_effect=respond) as get:
        found = scanner.test_sqli(url)
        assert len(found) == 1
        assert found[0]["parameter"] == "id"
        assert found[0]["confidence"] == "candidate"
        assert "Repeatable" in found[0]["evidence"]
        count = get.call_count
        assert scanner.test_sqli(url) == []
        assert get.call_count == count


@pytest.mark.unit
@pytest.mark.parametrize("text", ["You have an error in your SQL syntax", "Microsoft SQL Server documentation", "Hello"])
def test_existing_errors_and_product_names_are_not_sqli(web_response, text):
    scanner = SQLIScanner(MagicMock(), MagicMock())
    with patch("autopwn_suite.web.sqli.get", return_value=web_response(text)):
        assert scanner.test_sqli("http://example.com/item?id=1") == []
    scanner.console.print.assert_not_called()


@pytest.mark.unit
def test_transient_error_is_not_reported(web_response):
    scanner = SQLIScanner(MagicMock(), MagicMock())
    responses = [web_response("normal"), web_response("You have an error in your SQL syntax"),
                 web_response("normal"), web_response("normal"), web_response("normal")]
    with patch("autopwn_suite.web.sqli.get", side_effect=responses):
        assert scanner.test_sqli("http://example.com/item?id=1") == []


@pytest.mark.unit
def test_timeout_skips_unverified_endpoint():
    scanner = SQLIScanner(MagicMock(), MagicMock())
    with patch("autopwn_suite.web.sqli.get", side_effect=ConnectionError):
        assert scanner.test_sqli("http://example.com/item?id=1") == []
    scanner.log.logger.assert_called_once()


@pytest.mark.unit
def test_repeated_names_are_tested_separately(web_response):
    scanner = SQLIScanner(MagicMock(), MagicMock())
    with patch("autopwn_suite.web.sqli.get", return_value=web_response("normal")) as get:
        scanner.test_sqli("http://example.com/item?id=1&id=2")
    probes = [parse_qs(urlsplit(call.args[0]).query)["id"] for call in get.call_args_list]
    assert ["'1", "2"] in probes
    assert ["1", "'1"] in probes
