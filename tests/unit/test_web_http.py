# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from unittest.mock import Mock

import pytest
from requests.exceptions import RequestException, TooManyRedirects

from modules.web.http import same_origin, scoped_get


@pytest.mark.unit
@pytest.mark.parametrize("destination", ["https://external.com/x", "//external.com/x", "http://example.com:8080/x", "http://user:pass@example.com/x", "file:///etc/passwd", "https://example.com/x", "http://[broken", "http://example.com:0/", "http://@example.com/"])
def test_redirect_is_validated_before_any_out_of_scope_request(web_response, destination):
    get = Mock(return_value=web_response(status=302, headers={"Location": destination}))
    with pytest.raises(RequestException):
        scoped_get(get, "http://example.com/")
    get.assert_called_once()


@pytest.mark.unit
def test_same_origin_redirect_and_initial_https_upgrade(web_response):
    get = Mock(side_effect=[web_response(status=301, headers={"Location": "https://example.com/app/"}),
                           web_response(status=302, headers={"Location": "page"}), web_response("ok", url="https://example.com/app/page")])
    assert scoped_get(get, "http://example.com/", allow_upgrade=True).text == "ok"
    assert [call.args[0] for call in get.call_args_list] == ["http://example.com/", "https://example.com/app/", "https://example.com/app/page"]


@pytest.mark.unit
def test_redirect_loop_and_limit(web_response):
    get = Mock(return_value=web_response(status=302, headers={"Location": "/"}))
    with pytest.raises(TooManyRedirects):
        scoped_get(get, "http://example.com/")
    get.assert_called_once()
    get = Mock(side_effect=[web_response(status=302, headers={"Location": f"/{i}"}) for i in range(5)])
    with pytest.raises(TooManyRedirects):
        scoped_get(get, "http://example.com/")
    assert get.call_count == 4


@pytest.mark.unit
def test_effective_ports_and_host_case_define_origin():
    assert same_origin("https://EXAMPLE.com/", "https://example.com:443/path")
    assert not same_origin("http://example.com/", "https://example.com/")
    assert not same_origin("http://example.com/", "http://example.com.evil/x")


@pytest.mark.unit
def test_bounded_response_closes_connection_and_retains_only_prefix(web_response):
    from modules.web.http import bounded_request
    response = web_response("abcd" * 5000)
    get = Mock(return_value=response)
    result = bounded_request(get, "http://example.com/file", max_bytes=10000)
    assert result.content == b"abcd" * 2500
    assert result.autopwn_truncated
    assert get.call_args.kwargs["stream"] is True
    response.raw.release_conn.assert_called()


@pytest.mark.unit
def test_bounded_reader_releases_connection_on_stream_error(web_response):
    from modules.web.http import bounded_request
    response = web_response()
    response.iter_content = Mock(side_effect=RequestException("broken stream"))
    with pytest.raises(RequestException):
        bounded_request(Mock(return_value=response), "http://example.com/")
    response.raw.release_conn.assert_called()
