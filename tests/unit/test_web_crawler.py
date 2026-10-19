# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the crawler module.
"""
import time
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from autopwn_suite.web import crawler
from autopwn_suite.web.crawler import MAX_LINK_CHARACTERS, MAX_URL_LENGTH, crawl, link_finder
from autopwn_suite.web.options import LIMITS
from autopwn_suite.web.planning import prioritize_urls
from autopwn_suite.web.runtime import ScanContext


@pytest.mark.unit
class TestCrawler:
    """Tests for the web crawler functions."""

    @pytest.fixture
    def mock_log(self):
        """Fixture for a mocked logger."""
        return MagicMock()

    @pytest.mark.parametrize(
        "html_content, expected_urls",
        [
            ('<a href="/page1">Page 1</a>', {"http://example.com/page1"}),
            ('<a href="page2">Page 2</a>', {"http://example.com/page2"}),
            ('<a href="./page3">Page 3</a>', {"http://example.com/page3"}),
            ('<a href="http://example.com/page4">Page 4</a>', {"http://example.com/page4"}),
            # Ignored cases
            ('<a href="http://external.com/page5">Page 5</a>', set()),
            ('<a href="#">Anchor</a>', set()),
            ('<a href="">Empty</a>', set()),
            # Combination
            ('<a href="/page1">1</a> <a href="page2">2</a> <a href="http://external.com">3</a>', {"http://example.com/page1", "http://example.com/page2"}),
        ]
    )
    @patch("autopwn_suite.web.crawler.random_user_agent")
    @patch("autopwn_suite.web.crawler.get")
    def test_link_finder_parses_links(self, mock_get, mock_ua, mock_log, html_content, expected_urls):
        """Verify link_finder correctly parses various link formats."""
        mock_ua.return_value = iter(["Test-UA"])
        mock_response = MagicMock()
        mock_response.text = html_content
        mock_get.return_value = mock_response

        target_url = "http://example.com"
        urls = link_finder(target_url, mock_log)

        assert urls == expected_urls

    @patch("autopwn_suite.web.crawler.link_finder")
    @patch("autopwn_suite.web.crawler.get")
    @patch("autopwn_suite.web.crawler.random_user_agent")
    def test_crawl_success_path_no_deep_crawl(self, mock_ua, mock_get, mock_link_finder, mock_log):
        """Verify crawl function returns links without deep crawling if enough are found."""
        mock_ua.return_value = iter(["Test-UA"])
        # Simulate a large number of found URLs to prevent deep crawl
        initial_urls = {f"http://example.com/page{i}" for i in range(30)}
        mock_link_finder.return_value = initial_urls

        found_urls = crawl("http://example.com", mock_log, max_pages=1)

        # link_finder should only be called once
        mock_link_finder.assert_called_once()
        assert found_urls == initial_urls | {"http://example.com/"}
        mock_log.logger.assert_any_call("warning", "Web crawl budget reached; coverage is limited.")

    @patch("autopwn_suite.web.crawler.link_finder")
    @patch("autopwn_suite.web.crawler.get")
    @patch("autopwn_suite.web.crawler.random_user_agent")
    def test_crawl_deep_crawl_logic(self, mock_ua, mock_get, mock_link_finder, mock_log):
        """Verify crawl function performs a deep crawl if few links are found."""
        mock_ua.return_value = iter(["Test-UA", "Test-UA-2"])

        # First call finds one link, second call finds another
        mock_link_finder.side_effect = [
            {"http://example.com/page1"},
            {"http://example.com/page2"},
            set(),
        ]

        found_urls = crawl("http://example.com", mock_log)

        assert mock_link_finder.call_count == 3
        assert found_urls == {"http://example.com/", "http://example.com/page1", "http://example.com/page2"}

    @patch("autopwn_suite.web.crawler.random_user_agent")
    @patch("autopwn_suite.web.crawler.get", side_effect=ConnectionError)
    def test_crawl_initial_connection_error(self, mock_get, mock_ua, mock_log):
        """Verify crawl handles a connection error on the initial request."""
        mock_ua.return_value = iter(["Test-UA"])

        found_urls = crawl("http://example.com", mock_log)

        # Keep the supplied seed; a failed fetch must still be visible in logs.
        assert found_urls == {"http://example.com/"}
        assert mock_log.logger.call_args.args[0] == "error"

    @patch("autopwn_suite.web.crawler.get")
    def test_nested_page_resolves_root_parent_query_and_fragments(self, mock_get, mock_log):
        page = "https://example.com/app/page?view=one"
        mock_get.return_value = MagicMock(url=page, text='''
          <a href="/root">root</a><a href="../other">parent</a>
          <a href="?view=two#details">query</a><a href="//other.com/x">external</a>
          <a href="javascript:alert(1)">script</a><a href="mailto:a@example.com">mail</a>''')
        assert link_finder(page, mock_log) == {
            "https://example.com/root", "https://example.com/other", "https://example.com/app/page?view=two"
        }
        assert mock_get.call_args.args[0] == page
        assert mock_get.call_args.kwargs["timeout"] == 10

    @patch("autopwn_suite.web.crawler.get", side_effect=ConnectionError("Actual requests error"))
    def test_link_failure_is_logged_and_skipped(self, mock_get, mock_log):
        assert link_finder("https://example.com/app/page", mock_log) == set()
        mock_log.logger.assert_called()

    @patch("autopwn_suite.web.crawler.link_finder", return_value=set())
    @patch("autopwn_suite.web.crawler.get")
    def test_root_query_value_is_not_changed(self, mock_get, mock_links, mock_log):
        crawl("https://example.com?view=one", mock_log)
        assert mock_links.call_args.args[0] == "https://example.com/?view=one"


@pytest.mark.unit
def test_get_forms_include_blank_repeated_and_selected_inputs(web_response):
    page = "https://example.com/app/page"
    response = web_response('''<base href="/search/">
      <form action="find?discard=one"><input name="q"><input name="tag" value="a">
      <input name="tag" value="b"><input name="disabled" disabled>
      <select name="category"><option value="old">Old</option><option value="news" selected>News</option></select>
      <input type="checkbox" name="all" checked><input type="checkbox" name="ignored">
      <textarea name="note">hello</textarea><input type="submit" name="submit"></form>''', url=page)
    with patch("autopwn_suite.web.crawler.get", return_value=response):
        urls = link_finder(page, MagicMock())
    from urllib.parse import parse_qs, urlsplit
    assert len(urls) == 1
    url = next(iter(urls))
    assert urlsplit(url).path == "/search/find"
    assert parse_qs(urlsplit(url).query, keep_blank_values=True) == {
        "q": [""], "tag": ["a", "b"], "category": ["news"], "all": ["on"], "note": ["hello"]}


@pytest.mark.unit
def test_post_password_upload_and_off_origin_forms_are_skipped(web_response):
    response = web_response('''
      <form method="post"><input name="q"></form>
      <form><input type="PASSWORD" name="password"></form>
      <form><input type="file" name="upload"></form>
      <form action="https://external.com/"><input name="q"></form>''')
    with patch("autopwn_suite.web.crawler.get", return_value=response):
        assert link_finder("http://example.com/", MagicMock()) == set()


@pytest.mark.unit
def test_external_redirect_is_not_fetched(web_response):
    response = web_response(status=302, headers={"Location": "https://external.com/"})
    with patch("autopwn_suite.web.crawler.get", return_value=response) as get:
        assert link_finder("http://example.com/", MagicMock()) == set()
    get.assert_called_once()


@pytest.mark.unit
def test_crawl_limits_and_seed_query(web_response):
    links = {f"http://example.com/page?id={i}" for i in range(200)}
    with patch("autopwn_suite.web.crawler.link_finder", return_value=links) as finder:
        urls = crawl("http://example.com/?seed=yes", MagicMock(), max_pages=3, max_urls=5)
    assert len(urls) == 5
    assert "http://example.com/?seed=yes" in urls
    assert finder.call_count <= 3


@pytest.mark.unit
def test_links_beyond_depth_limit_are_not_probed():
    graph = {"http://example.com/": {"http://example.com/one"},
             "http://example.com/one": {"http://example.com/two"},
             "http://example.com/two": {"http://example.com/three"}}
    log = MagicMock()
    with patch("autopwn_suite.web.crawler.link_finder", side_effect=lambda url, log: graph[url]) as finder:
        assert crawl("http://example.com/", log, max_depth=2) == {
            "http://example.com/", "http://example.com/one", "http://example.com/two"}
    assert all(call.args[0] != "http://example.com/three" for call in finder.call_args_list)
    log.logger.assert_any_call("warning", "Web crawl budget reached; coverage is limited.")


@pytest.mark.unit
def test_non_html_and_http_errors_are_not_crawled(web_response):
    for response in (web_response('<a href="/injected">', headers={"Content-Type": "application/json"}),
                     web_response('<a href="/error">', status=500)):
        with patch("autopwn_suite.web.crawler.get", return_value=response):
            assert link_finder("http://example.com/", MagicMock()) == set()


@pytest.mark.unit
def test_malformed_base_links_and_actions_are_skipped(web_response):
    response = web_response('<base href="http://[broken"><a href="http://[broken">Bad</a><a href="/good">Good</a><form action="http://[broken"><input name="q"></form>')
    with patch("autopwn_suite.web.crawler.get", return_value=response):
        assert link_finder("http://example.com/", MagicMock()) == {"http://example.com/good"}


@pytest.mark.unit
def test_checkpoint_keeps_a_bounded_list_of_links_per_page_and_a_raised_limit_resumes_from_it():
    root = "http://example.com/"
    links = {f"{root}p{i}?id={i}" for i in range(12_000)}
    ordered = prioritize_urls(links)
    state = {}
    with patch("autopwn_suite.web.crawler.link_finder", return_value=set(links)) as finder:
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            assert len(crawl(root, MagicMock(), max_pages=1, max_urls=5)) == 5
        # One more than the largest URL budget, not the 12,000 links the hostile page offered.
        assert state["crawl"][root] == ordered[:LIMITS["max_urls"][2] + 1]
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            found = crawl(root, MagicMock(), max_pages=1, max_urls=LIMITS["max_urls"][2])
    assert found == {root, *ordered[:LIMITS["max_urls"][2] - 1]}
    assert [call.args[0] for call in finder.call_args_list].count(root) == 1


@pytest.mark.unit
def test_links_the_crawl_never_follows_do_not_use_up_the_stored_list():
    root = "http://example.com/"
    pages = [root + "one", root + "two"]
    state = {}
    with patch("autopwn_suite.web.crawler.link_finder", return_value={f"{root}a{i:05}.css" for i in range(10_500)} | set(pages)):
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            assert crawl(root, MagicMock(), max_pages=1, max_urls=5) == {root, *pages}
    assert state["crawl"][root] == pages


@pytest.mark.unit
def test_a_budget_limited_crawl_picks_the_same_urls_as_before_the_list_was_bounded_and_so_does_its_resume():
    root = "http://example.com/"
    # Prioritized as a whole, the links come in the order delete (never followed), m, zeta, zulu: the crawl takes m.
    # Dropping the link it never follows before prioritizing would put zeta first.
    links = {f"{root}p?page=delete", f"{root}p?page=zeta", f"{root}p?page=zulu", f"{root}q?page=m"}
    state = {}
    with patch("autopwn_suite.web.crawler.link_finder", return_value=set(links)):
        for _ in range(2):  # the second crawl reads the stored list of the root page
            with ScanContext(root, MagicMock(), checkpoint=state).activate():
                assert crawl(root, MagicMock(), max_pages=1, max_urls=2) == {root, f"{root}q?page=m"}


@pytest.mark.unit
def test_links_to_other_origins_do_not_use_up_the_stored_list():
    root = "http://example.com/"
    # They sort before the one link the crawl can follow, and a page can offer more of them than the list holds.
    links = {f"http://a{i:05}.test/" for i in range(LIMITS["max_urls"][2] + 500)} | {root + "one"}
    state = {}
    with patch("autopwn_suite.web.crawler.link_finder", return_value=links):
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            assert crawl(root, MagicMock(), max_pages=1, max_urls=5) == {root, root + "one"}
    assert state["crawl"][root] == [root + "one"]


def _reported(log, text):
    return any(text in call.args[1] for call in log.logger.call_args_list)


@pytest.mark.unit
def test_a_link_longer_than_a_server_accepts_is_not_followed_and_is_reported(web_response):
    log = MagicMock()
    page = f'<a href="/{"a" * MAX_URL_LENGTH}">long</a><a href="/ok">ok</a><form><input name="q" value="{"b" * MAX_URL_LENGTH}"></form>'
    with patch("autopwn_suite.web.crawler.get", return_value=web_response(page)):
        assert link_finder("http://example.com/", log) == {"http://example.com/ok"}
    assert _reported(log, "were not followed")


@pytest.mark.unit
def test_a_page_whose_base_url_is_too_long_offers_no_links(web_response):
    # Every relative link would be 20,000 characters long: 2,000 of them left 40 MB in the checkpoint of one page.
    page = f'<base href="/{"a" * 20_000}/">' + "".join(f'<a href="p{number}">x</a>' for number in range(2_000))
    log = MagicMock()
    with patch("autopwn_suite.web.crawler.get", return_value=web_response(page)):
        assert link_finder("http://example.com/", log) == set()
    assert _reported(log, "base URL is longer")


@pytest.mark.unit
def test_the_links_of_one_page_are_cut_to_a_total_size_and_stay_fast(web_response):
    page = f'<base href="/{"a" * 7_000}/">' + "".join(f'<a href="p{number}">x</a>' for number in range(60_000))
    log = MagicMock()
    with patch("autopwn_suite.web.crawler.get", return_value=web_response(page)):
        started = time.perf_counter()
        urls = link_finder("http://example.com/", log)
        elapsed = time.perf_counter() - started
    assert 0 < sum(map(len, urls)) <= MAX_LINK_CHARACTERS
    assert elapsed < 2.0 and _reported(log, "were not followed")


@pytest.mark.unit
def test_a_crawl_stores_links_for_resuming_only_up_to_a_total_size(monkeypatch):
    monkeypatch.setattr(crawler, "MAX_LINK_CHARACTERS", 1_500)
    root = "http://example.com/"
    first = {f"{root}a{number:03}" for number in range(40)}  # 40 links of 23 characters
    second = {f"{root}b{number:03}" for number in range(40)}
    pages = {root: first, min(first): second}
    state = {}
    with patch("autopwn_suite.web.crawler.link_finder", side_effect=lambda url, log: set(pages.get(url, ()))):
        with ScanContext(root, MagicMock(), checkpoint=state).activate():
            found = crawl(root, MagicMock(), max_pages=2, max_urls=100)
    assert found >= first | second  # the crawl uses the links of every page it reads
    assert set(state["crawl"]) == {root}  # the second page's links would take the store past its size
