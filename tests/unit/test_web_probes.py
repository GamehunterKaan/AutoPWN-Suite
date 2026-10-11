from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

from modules.web.http import ProbeClient, ProbeLimitReached
from modules.web.probes import check_cors, check_host_headers, check_methods, check_redirects


@pytest.mark.unit
def test_cors_arbitrary_and_null_origins_need_credential_permission(web_response):
    client = ProbeClient("http://example.com/", MagicMock())
    def respond(method, url, **kwargs):
        return web_response("public response", headers={"Access-Control-Allow-Origin": kwargs["headers"]["Origin"], "Access-Control-Allow-Credentials": "true"})
    with patch("modules.web.http.request", side_effect=respond):
        results = check_cors(client, "http://example.com/", MagicMock())
    assert len(results) == 2
    assert all(item["type"] == "CORS" and "not verified" in item["evidence"] for item in results)


@pytest.mark.unit
@pytest.mark.parametrize("origin,credentials,status,expected", [
    ("*", "", 200, []), ("*", "true", 200, ["CORS_CONFIG"]),
    ("https://allowed.example", "true", 200, []), ("reflect", "True", 200, []),
    ("reflect", "false", 200, []), ("reflect", "true", 403, []),
])
def test_public_cors_and_browser_rejected_cases_are_not_vulnerabilities(web_response, origin, credentials, status, expected):
    def respond(method, url, **kwargs):
        return web_response(status=status, headers={"Access-Control-Allow-Origin": kwargs["headers"]["Origin"] if origin == "reflect" else origin,
                                                    "Access-Control-Allow-Credentials": credentials})
    with patch("modules.web.http.request", side_effect=respond):
        result = check_cors(ProbeClient("http://example.com/", MagicMock()), "http://example.com/", MagicMock())
    assert [item["type"] for item in result] == expected


@pytest.mark.unit
def test_open_redirect_uses_two_external_markers_and_never_visits_them(web_response):
    client = ProbeClient("http://example.com/", MagicMock())
    def respond(method, url, **kwargs):
        assert urlsplit(url).hostname == "example.com"
        assert kwargs["allow_redirects"] is False
        params = parse_qs(urlsplit(url).query)
        assert params["token"] == ["a&b"]
        return web_response(status=302, headers={"Location": params["next"][0]})
    with patch("modules.web.http.request", side_effect=respond) as request:
        result = check_redirects(client, "http://example.com/go?next=/home&token=a%26b", MagicMock())
    assert len(result) == 1 and result[0]["type"] == "OPEN_REDIRECT"
    assert request.call_count == 2
    assert request.call_args_list[0].args[1] != request.call_args_list[1].args[1]


@pytest.mark.unit
def test_body_reflection_and_static_location_are_not_open_redirects(web_response):
    client = ProbeClient("http://example.com/", MagicMock())
    with patch("modules.web.http.request", side_effect=lambda method, url, **kwargs: web_response(url, status=302, headers={"Location": "https://fixed.example/"})):
        assert check_redirects(client, "http://example.com/go?next=/home", MagicMock()) == []


@pytest.mark.unit
def test_host_header_requires_generated_uri_not_plain_text_reflection(web_response):
    for html, expected in ((True, 2), (False, 0)):
        def respond(method, url, **kwargs):
            assert urlsplit(url).hostname == "example.com"
            assert "__autopwn_probe=" in url
            host = kwargs["headers"].get("Host", kwargs["headers"].get("X-Forwarded-Host"))
            return web_response(f'<a href="https://{host}/reset">Reset</a>' if html else f"Invalid host: {host}")
        with patch("modules.web.http.request", side_effect=respond):
            results = check_host_headers(ProbeClient("http://example.com/", MagicMock()), "http://example.com/", MagicMock())
        assert len(results) == expected


@pytest.mark.unit
def test_http_methods_only_advertise_writes_and_verify_trace_echo(web_response):
    client = ProbeClient("http://example.com/", MagicMock(), {"Cookie": "secret", "Authorization": "secret"})
    def respond(method, url, **kwargs):
        assert "Cookie" not in kwargs["headers"] and "Authorization" not in kwargs["headers"]
        if method == "OPTIONS":
            return web_response(headers={"Allow": "GET, OPTIONS, PUT, DELETE, TRACE"})
        assert method == "TRACE"
        return web_response("TRACE / HTTP/1.1\r\nX-Autopwn-Trace: " + kwargs["headers"]["X-Autopwn-Trace"] + "\r\n")
    with patch("modules.web.http.request", side_effect=respond) as request:
        result = check_methods(client, "http://example.com/", MagicMock())
    assert [item["type"] for item in result] == ["HTTP_METHODS", "TRACE_ENABLED"]
    assert {call.args[0] for call in request.call_args_list} == {"OPTIONS", "TRACE"}


@pytest.mark.unit
def test_html_trace_reflection_does_not_prove_trace_enabled(web_response):
    with patch("modules.web.http.request", return_value=web_response("<p>TRACE is disabled</p>")):
        assert check_methods(ProbeClient("http://example.com/", MagicMock()), "http://example.com/", MagicMock()) == []


@pytest.mark.unit
def test_budget_and_origin_validation_prevent_requests(web_response):
    from requests.exceptions import RequestException
    client = ProbeClient("http://example.com/", MagicMock(), max_requests=1)
    with patch("modules.web.http.request", return_value=web_response()) as request:
        with pytest.raises(RequestException):
            client.send("http://external.com/")
        with pytest.raises(RequestException):
            client.send("http://example.com/", method="DELETE")
        client.send("http://example.com/")
        for _ in range(2):
            with pytest.raises(ProbeLimitReached):
                client.send("http://example.com/")
    request.assert_called_once()
    client.log.logger.assert_called_once()
    assert client.requests == 1


@pytest.mark.unit
def test_confirmed_cors_is_preserved_when_later_probes_hit_budget(web_response):
    client = ProbeClient("http://example.com/", MagicMock(), max_requests=2)
    def respond(method, url, **kwargs):
        return web_response(headers={"Access-Control-Allow-Origin": kwargs["headers"]["Origin"], "Access-Control-Allow-Credentials": "true"})
    with patch("modules.web.http.request", side_effect=respond):
        results = check_cors(client, "http://example.com/", MagicMock())
    assert len(results) == 1 and results[0]["type"] == "CORS"
    assert client.exhausted


@pytest.mark.unit
def test_probe_auth_disables_ambient_netrc_and_strips_supplied_secrets():
    from requests import Request, Session
    from modules.web.http import AnonymousAuth
    with Session() as session, patch("requests.sessions.get_netrc_auth", return_value=("user", "secret")) as netrc:
        prepared = session.prepare_request(Request("TRACE", "http://example.com/", auth=AnonymousAuth(), headers={
            "Authorization": "secret", "Cookie": "secret", "Proxy-Authorization": "secret"}))
    netrc.assert_not_called()
    assert not ({"Authorization", "Cookie", "Proxy-Authorization"} & set(prepared.headers))
