# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""A target controls the response body, so no check may take longer than a moment to read one.

Python's `re` holds the GIL while it matches, so a body that makes a pattern backtrack stalls the scan,
its Stop button and every other dashboard thread until the match ends (minutes for the bodies below
with the unbounded patterns they replaced).
"""
import random
import time
from difflib import SequenceMatcher
from unittest.mock import MagicMock

import pytest

from autopwn_suite.web import poc_runtime
from autopwn_suite.web import similarity as similarity_module
from autopwn_suite.web.boolean_sqli import _similar
from autopwn_suite.web.content import inspect_content
from autopwn_suite.web.dirbust import _catch_all
from autopwn_suite.web.similarity import similarity
from autopwn_suite.web.sqli import SQLIScanner
from autopwn_suite.web.xss import reflection_context

LIMIT_SECONDS = 2.0

SQL_BODIES = [
    "microsoft odbc " * 12_000, "microsoft jet " * 12_000, "microsoft access " * 12_000, "warning " * 20_000,
    "postgresql " * 15_000, "pg_query() " * 15_000, "sqlite " * 20_000, "syntax error " * 12_000, "a" * 1_000_000,
]
FILE_BODIES = {
    "/.env": ["\n" * 100_000, " \n" * 50_000, "A" * 100_000, "export " * 14_000],
    "/dump.sql": ["-- MySQL" * 12_000, "-- PostgreSQL" * 8_000],
}
ERROR_BODIES = ["a" * 100_000, "Exception:" * 10_000, "AException:" + "a" * 100_000, "Uncaught " + "a" * 100_000, "Traceback (most recent call last):\n" * 3_000]


def seconds(call, *args):
    started = time.perf_counter()
    call(*args)
    return time.perf_counter() - started


@pytest.mark.unit
@pytest.mark.parametrize("body", SQL_BODIES, ids=lambda body: body[:14])
def test_sql_error_patterns_stay_fast_on_hostile_bodies(body):
    assert seconds(SQLIScanner(MagicMock(), MagicMock())._errors, body) < LIMIT_SECONDS
    assert seconds(poc_runtime._sql_errors, body) < LIMIT_SECONDS


@pytest.mark.unit
@pytest.mark.parametrize("path,body", [(path, body) for path, bodies in FILE_BODIES.items() for body in bodies], ids=lambda value: str(value)[:14])
def test_exposed_file_checks_stay_fast_on_hostile_bodies(web_response, path, body):
    response = web_response(body, url="http://example.com" + path, headers={"Content-Type": "text/plain"})
    assert seconds(inspect_content, "http://example.com" + path, response, MagicMock()) < LIMIT_SECONDS


@pytest.mark.unit
@pytest.mark.parametrize("body", ERROR_BODIES, ids=lambda body: body[:14])
def test_error_page_signatures_stay_fast_on_hostile_bodies(web_response, body):
    response = web_response(body, status=500, headers={"Content-Type": "text/plain"})
    assert seconds(inspect_content, "http://example.com/", response, MagicMock()) < LIMIT_SECONDS


@pytest.mark.unit
def test_environment_file_keys_are_still_found_on_ordinary_lines(web_response):
    body = "# comment\r\nexport APP_NAME=demo\r\n  DB_PASSWORD = secret\r\nTOKEN=abc\r\n"
    results = inspect_content("http://example.com/.env", web_response(body, headers={"Content-Type": "text/plain"}), MagicMock())
    assert [item["type"] for item in results] == ["EXPOSED_FILE"]


# The reflected marker sits after the nesting, so the whole tree has to be read to find it.
DEEP_PAGES = {"nested": "<html><body>" + "<b>" * 16_000 + "MARK", "unmatched end tags": "<b>" * 16_000 + "</i>" * 16_000 + "MARK"}


@pytest.mark.unit
@pytest.mark.parametrize("page", DEEP_PAGES.values(), ids=DEEP_PAGES.keys())
def test_deeply_nested_html_stays_fast_for_reflection_analysis(web_response, page):
    response = web_response(page, headers={"Content-Type": "text/html"})
    assert seconds(reflection_context, response, "MARK", "MARK") < LIMIT_SECONDS
    assert seconds(poc_runtime._Document("MARK").feed, page) < LIMIT_SECONDS


@pytest.mark.unit
def test_nested_headings_stay_fast_and_ordinary_listing_headings_are_still_read(web_response):
    nested = web_response("<html><body>" + "<h1>" * 16_000, headers={"Content-Type": "text/html"})
    assert seconds(inspect_content, "http://example.com/", nested, MagicMock()) < LIMIT_SECONDS
    listing = '<html><title>Welcome</title><h1>Files</h1><h1>Index of /files/</h1><a href="one">One</a><a href="two">Two</a></html>'
    result = inspect_content("http://example.com/files/", web_response(listing, headers={"Content-Type": "text/html"}), MagicMock())
    assert [item["type"] for item in result] == ["DIR_LISTING"]


INACTIVE_CASES = [
    ('<template><div><img onerror="MARK"></div></template>', None),
    ("<noscript><p><script>MARK</script></p></noscript>", None),
    ('<template><p></p></template><img onerror="MARK">', "HTML event handler"),
    ('<textarea onclick="MARK"></textarea>', "HTML event handler"),
    ("<div><script>MARK</script></div>", "script element"),
    ('<template><b></i></b><img onerror="MARK">', None),
    ('<template></template></template><img onerror="MARK">', "HTML event handler"),
]


@pytest.mark.unit
@pytest.mark.parametrize("page,context", INACTIVE_CASES)
def test_inactive_elements_are_skipped_in_the_scanner_and_in_the_downloaded_poc(web_response, page, context):
    assert reflection_context(web_response(page, headers={"Content-Type": "text/html"}), "MARK", "MARK") == context
    document = poc_runtime._Document("MARK")
    document.feed(page)
    assert document.active is (context is not None)


def unicode_noise(seed, size):
    """100 different characters at about 1% each: difflib finds nothing to ignore, and compares them all."""
    generator = random.Random(seed)
    alphabet = [chr(0x4E00 + index) for index in range(100)]
    return "".join(generator.choice(alphabet) for _ in range(size))


@pytest.mark.unit
@pytest.mark.parametrize("compare", [similarity, _similar, poc_runtime._similarity], ids=["similarity", "boolean_sqli", "poc_runtime"])
def test_similarity_stays_fast_on_hostile_bodies_and_stays_meaningful(compare):
    one, other = unicode_noise(1, 100_000), unicode_noise(2, 100_000)
    assert seconds(compare, one, other) < LIMIT_SECONDS
    assert compare(one, one) == 1.0
    assert compare(one, other) < .5


def periodic_pair(size, period=101):
    """Every character occurs about size / period times in the other body, so difflib finds thousands of small
    blocks and searches the whole range again for each one: minutes for 20,000 characters."""
    return ("".join(chr(0x4E00 + index * 7 % period) for index in range(size)),
            "".join(chr(0x4E00 + index * 11 % period) for index in range(size)))


def varied_text(seed, size):
    """Like prose or code: common letters, and a dozen characters of under 1% each, which difflib cannot ignore."""
    return "".join(random.Random(seed).choices("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKL", weights=[3.4] * 27 + [.7] * 12, k=size))


def listing(count, changed=()):
    return "<html><body><ul>" + "".join(f"<li class='item'>Item {number} costs {number * 3} dollars{'!' if number in changed else ''}</li>"
                                         for number in range(count)) + "</ul></body></html>"


COMPARISONS = [(similarity, similarity_module), (poc_runtime._similarity, poc_runtime)]


@pytest.mark.unit
@pytest.mark.parametrize("size", [20_000, 100_000])
@pytest.mark.parametrize("compare", [similarity, _similar, poc_runtime._similarity], ids=["similarity", "boolean_sqli", "poc_runtime"])
def test_similarity_stays_fast_on_periodic_bodies(compare, size):
    one, other = periodic_pair(size)
    started = time.perf_counter()
    ratio = compare(one, other)
    assert time.perf_counter() - started < LIMIT_SECONDS
    assert ratio < .5


@pytest.mark.unit
@pytest.mark.parametrize("compare,module", COMPARISONS, ids=["similarity", "poc_runtime"])
def test_the_search_for_common_blocks_stops_at_its_deadline_and_counts_what_it_found(compare, module, monkeypatch):
    left, right = "1111x22y333", "1111z22w333"
    assert compare(left, right) == SequenceMatcher(None, left, right).ratio() == 18 / 22
    clock, search = [0.0], SequenceMatcher.find_longest_match

    def slow_search(matcher, *bounds):
        clock[0] += .3
        return search(matcher, *bounds)

    monkeypatch.setattr(module, "monotonic", lambda: clock[0])
    monkeypatch.setattr(SequenceMatcher, "find_longest_match", slow_search)
    # The deadline (half a second) allows two searches, which find "1111" and "333", but not the third for "22".
    assert compare(left, right) == 14 / 22


@pytest.mark.unit
@pytest.mark.parametrize("compare,module", COMPARISONS, ids=["similarity", "poc_runtime"])
def test_markup_and_twenty_thousand_characters_of_varied_text_are_compared_in_full(compare, module, monkeypatch):
    monkeypatch.setattr(module, "monotonic", lambda: 0.0)  # no deadline: the result is what difflib itself computes
    page = listing(2000)  # about 100,000 characters, nearly all of them repeated markup
    pairs = [(page, listing(2000, {7, 1500})), (page, page[:50_000]), (varied_text(1, 20_000), varied_text(1, 14_000) + varied_text(2, 6_000))]
    for left, right in pairs:
        assert compare(left, right) == SequenceMatcher(None, left, right).ratio()


@pytest.mark.unit
@pytest.mark.parametrize("compare", [similarity, poc_runtime._similarity], ids=["similarity", "poc_runtime"])
def test_large_pages_of_varied_text_are_compared_on_their_first_characters(compare):
    # difflib needs seconds for 100,000 characters like these, so one comparison reads about the first 30,000 of
    # them: a change in that part is seen, a change after it is not (docs/ASSURANCE_CASE.md says so).
    page = varied_text(1, 100_000)
    assert compare(page, varied_text(2, 30_000) + page[30_000:]) < .5
    assert compare(page, page[:70_000] + varied_text(2, 30_000)) > .98


@pytest.mark.unit
def test_directory_catch_all_check_uses_the_bounded_comparison(web_response, monkeypatch):
    url = "http://example.com/admin/"
    response = web_response("<html>Not found</html>", url=url)
    seen = []

    def spy(left, right):
        seen.append((left, right))
        return similarity(left, right)

    monkeypatch.setattr("autopwn_suite.web.dirbust.similarity", spy)
    assert _catch_all(response, url, [("http://example.com/missing", web_response("<html>Not found</html>"))])
    assert seen == [("<html>Not found</html>", "<html>Not found</html>")]
    other = web_response(unicode_noise(1, 20_000))
    assert not _catch_all(web_response(unicode_noise(2, 20_000), url=url), url, [("http://example.com/missing", other)])
    assert len(seen) == 2


@pytest.mark.unit
@pytest.mark.parametrize("compare", [similarity, poc_runtime._similarity], ids=["similarity", "poc_runtime"])
def test_ordinary_pages_are_compared_exactly_as_difflib_does(compare):
    page = "<html><head><title>Store</title></head><body>" + "".join(f"<li class='item'>Item {number} costs {number * 3} dollars</li>" for number in range(400))
    changed = page.replace("Item 7 ", "Item seven ").replace("</body>", "<p>You have an error</p></body>")
    for left, right in ((page, page), (page, changed), (page, page[:5000]), (page[:3000], "<html>Not found</html>"), ("", page), (page, "")):
        assert compare(left, right) == SequenceMatcher(None, left, right).ratio()
