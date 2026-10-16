# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from unittest.mock import MagicMock

import pytest

from modules.web.passive import inspect_response


@pytest.mark.unit
def test_secure_html_headers_and_cookies_have_no_advisories(web_response):
    url = "https://example.com/"
    response = web_response("<html>Home</html>", url=url, headers={
        "Content-Type": "text/html", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }, cookies=["session=secret; Secure; HttpOnly; SameSite=Lax", "other=private; Secure; HttpOnly; SameSite=Strict"])
    assert inspect_response(url, response, MagicMock()) == []


@pytest.mark.unit
def test_cookie_advisories_never_include_values(web_response):
    url = "https://example.com/"
    response = web_response("<html>Home</html>", cookies=["session=super-secret; SameSite=None", "token=another-secret; Secure; HttpOnly; SameSite=Lax"])
    console = MagicMock()
    results = inspect_response(url, response, console)
    assert any("SameSite=None without Secure" in item["evidence"] for item in results)
    assert all(item["confidence"] == "advisory" for item in results)
    assert "super-secret" not in str(results) + str(console.print.call_args_list)
    assert "another-secret" not in str(results) + str(console.print.call_args_list)
    assert not any("Cookie token" in item["evidence"] for item in results)


@pytest.mark.unit
@pytest.mark.parametrize("mime,text", [("application/json", '{"ok":true}'), ("text/plain", "text")])
def test_non_html_does_not_get_html_specific_advisories(web_response, mime, text):
    result = inspect_response("http://example.com/", web_response(text, headers={"Content-Type": mime, "X-Content-Type-Options": "nosniff"}), MagicMock())
    assert result == []


@pytest.mark.unit
@pytest.mark.parametrize("url", ["http://example.com/", "https://127.0.0.1/", "https://[::1]/"])
def test_hsts_only_applies_to_https_hostnames(web_response, url):
    results = inspect_response(url, web_response("<html></html>"), MagicMock())
    assert not any("HSTS" in item["evidence"] for item in results)


@pytest.mark.unit
@pytest.mark.parametrize("hsts", ["", "max-age=0", "max-age=abc", "max-age=000"])
def test_missing_or_disabled_hsts_is_advisory(web_response, hsts):
    results = inspect_response("https://example.com/", web_response(headers={"Strict-Transport-Security": hsts}), MagicMock())
    assert any("HSTS" in item["evidence"] for item in results)


@pytest.mark.unit
def test_report_only_csp_and_deprecated_xfo_are_not_enforced_protection(web_response):
    results = inspect_response("http://example.com/", web_response("<html></html>", headers={"Content-Security-Policy-Report-Only": "frame-ancestors 'none'", "X-Frame-Options": "ALLOW-FROM https://example.com"}), MagicMock())
    assert any("No enforced" in item["evidence"] for item in results)
    assert any("No restrictive" in item["evidence"] for item in results)


@pytest.mark.unit
def test_enforced_wildcard_frame_policy_overrides_xfo(web_response):
    results = inspect_response("http://example.com/", web_response("<html></html>", headers={
        "Content-Security-Policy": "frame-ancestors *", "X-Frame-Options": "DENY"}), MagicMock())
    assert any("No restrictive" in item["evidence"] for item in results)
