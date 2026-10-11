from urllib.parse import parse_qs, urlsplit

import pytest

from modules.web.query import probe_url


@pytest.mark.unit
def test_probe_retains_context_and_escapes_payload_delimiters():
    url = probe_url("https://example.com/search", ["category=news", "q=old", "token=a%26b"], 1, "<img src='#'>&value")
    parsed = urlsplit(url)
    assert parsed.fragment == ""
    assert parse_qs(parsed.query) == {"category": ["news"], "q": ["<img src='#'>&value"], "token": ["a&b"]}
