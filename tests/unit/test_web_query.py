from urllib.parse import parse_qs, urlsplit

import pytest

from modules.web.query import parameter_indexes, probe_url, query_parts


@pytest.mark.unit
def test_probe_retains_context_and_escapes_payload_delimiters():
    url = probe_url("https://example.com/search", ["category=news", "q=old", "token=a%26b"], 1, "<img src='#'>&value")
    parsed = urlsplit(url)
    assert parsed.fragment == ""
    assert parse_qs(parsed.query) == {"category": ["news"], "q": ["<img src='#'>&value"], "token": ["a&b"]}


@pytest.mark.unit
def test_fragments_and_duplicate_blank_inputs():
    base, params = query_parts("https://example.com/search?q=&q=second&&token=a%26b#details")
    assert base == "https://example.com/search"
    assert params == ["q=", "q=second", "", "token=a%26b"]
    assert list(parameter_indexes(params)) == [0, 1, 3]
    assert parse_qs(urlsplit(probe_url(base, params, 1, "'\"<>")).query, keep_blank_values=True) == {
        "q": ["", "'\"<>"], "token": ["a&b"]}
