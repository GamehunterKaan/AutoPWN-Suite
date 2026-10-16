# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from unittest.mock import MagicMock, mock_open, patch
from urllib.parse import urlsplit

import pytest
from requests.exceptions import ConnectionError

from modules.web.dirbust import dirbust


@pytest.mark.unit
@pytest.mark.parametrize("status", [200, 301, 401, 403])
def test_distinct_endpoint_is_observation(web_response, status):
    log, console = MagicMock(), MagicMock()

    def respond(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == 10
        if "__autopwn_missing_" in url:
            return web_response("not found", status=404, url=url)
        return web_response("admin panel", status=status, url=url, headers={"Location": "/admin/"} if status == 301 else {})

    with patch("modules.web.dirbust.open", mock_open(read_data="admin\nadmin\n#comment\n\n")), patch("modules.web.dirbust.get", side_effect=respond) as get:
        found = dirbust("http://example.com/app?view=one", console, log)
    assert len(found) == 1
    assert found[0]["url"] == "http://example.com/app/admin"
    assert found[0]["confidence"] == "observation"
    assert get.call_count == 3
    console.print.assert_called_once()


@pytest.mark.unit
@pytest.mark.parametrize("status", [200, 401, 403])
def test_soft_not_found_and_blanket_denials_are_suppressed(web_response, status):
    log, console = MagicMock(), MagicMock()

    def respond(url, **kwargs):
        return web_response(f"<h1>Nothing at {urlsplit(url).path}</h1>", status=status, url=url)

    with patch("modules.web.dirbust.open", mock_open(read_data="admin\napi")), patch("modules.web.dirbust.get", side_effect=respond):
        assert dirbust("http://example.com", console, log) == []
    console.print.assert_not_called()


@pytest.mark.unit
def test_blanket_login_redirect_is_suppressed_and_never_followed(web_response):
    with patch("modules.web.dirbust.open", mock_open(read_data="admin")), patch("modules.web.dirbust.get", side_effect=lambda url, **kwargs: web_response(status=302, url=url, headers={"Location": "/login?next=" + urlsplit(url).path})) as get:
        assert dirbust("http://example.com", MagicMock(), MagicMock()) == []
    assert all(call.kwargs["allow_redirects"] is False for call in get.call_args_list)


@pytest.mark.unit
@pytest.mark.parametrize("status", [404, 500, 503])
def test_errors_do_not_indicate_directory_exists(web_response, status):
    with patch("modules.web.dirbust.open", mock_open(read_data="admin")), patch("modules.web.dirbust.get", return_value=web_response("error", status=status)):
        assert dirbust("http://example.com", MagicMock(), MagicMock()) == []


@pytest.mark.unit
def test_missing_wordlist_and_baseline_failure():
    log, console = MagicMock(), MagicMock()
    with patch("modules.web.dirbust.open", side_effect=FileNotFoundError), patch("modules.web.dirbust.get") as get:
        assert dirbust("http://example.com", console, log) == []
        get.assert_not_called()
    with patch("modules.web.dirbust.open", mock_open(read_data="admin")), patch("modules.web.dirbust.get", side_effect=ConnectionError) as get:
        assert dirbust("http://example.com", console, log) == []
        get.assert_called_once()
    console.print.assert_not_called()
