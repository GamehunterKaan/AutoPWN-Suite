"""
Unit tests for the crawler module.
"""
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.crawler import crawl, link_finder


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
    @patch("modules.web.crawler.random_user_agent")
    @patch("modules.web.crawler.get")
    def test_link_finder_parses_links(self, mock_get, mock_ua, mock_log, html_content, expected_urls):
        """Verify link_finder correctly parses various link formats."""
        mock_ua.return_value = iter(["Test-UA"])
        mock_response = MagicMock()
        mock_response.text = html_content
        mock_get.return_value = mock_response

        target_url = "http://example.com"
        urls = link_finder(target_url, mock_log)

        assert urls == expected_urls

    @patch("modules.web.crawler.link_finder")
    @patch("modules.web.crawler.get")
    @patch("modules.web.crawler.random_user_agent")
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

    @patch("modules.web.crawler.link_finder")
    @patch("modules.web.crawler.get")
    @patch("modules.web.crawler.random_user_agent")
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

    @patch("modules.web.crawler.random_user_agent")
    @patch("modules.web.crawler.get", side_effect=ConnectionError)
    def test_crawl_initial_connection_error(self, mock_get, mock_ua, mock_log):
        """Verify crawl handles a connection error on the initial request."""
        mock_ua.return_value = iter(["Test-UA"])

        found_urls = crawl("http://example.com", mock_log)

        # Keep the supplied seed; a failed fetch must still be visible in logs.
        assert found_urls == {"http://example.com/"}
        assert mock_log.logger.call_args.args[0] == "error"

    @patch("modules.web.crawler.get")
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

    @patch("modules.web.crawler.get", side_effect=ConnectionError("Actual requests error"))
    def test_link_failure_is_logged_and_skipped(self, mock_get, mock_log):
        assert link_finder("https://example.com/app/page", mock_log) == set()
        mock_log.logger.assert_called()

    @patch("modules.web.crawler.link_finder", return_value=set())
    @patch("modules.web.crawler.get")
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
    with patch("modules.web.crawler.get", return_value=response):
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
    with patch("modules.web.crawler.get", return_value=response):
        assert link_finder("http://example.com/", MagicMock()) == set()


@pytest.mark.unit
def test_external_redirect_is_not_fetched(web_response):
    response = web_response(status=302, headers={"Location": "https://external.com/"})
    with patch("modules.web.crawler.get", return_value=response) as get:
        assert link_finder("http://example.com/", MagicMock()) == set()
    get.assert_called_once()


@pytest.mark.unit
def test_crawl_limits_and_seed_query(web_response):
    links = {f"http://example.com/page?id={i}" for i in range(200)}
    with patch("modules.web.crawler.link_finder", return_value=links) as finder:
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
    with patch("modules.web.crawler.link_finder", side_effect=lambda url, log: graph[url]) as finder:
        assert crawl("http://example.com/", log, max_depth=2) == {
            "http://example.com/", "http://example.com/one", "http://example.com/two"}
    assert all(call.args[0] != "http://example.com/three" for call in finder.call_args_list)
    log.logger.assert_any_call("warning", "Web crawl budget reached; coverage is limited.")


@pytest.mark.unit
def test_non_html_and_http_errors_are_not_crawled(web_response):
    for response in (web_response('<a href="/injected">', headers={"Content-Type": "application/json"}),
                     web_response('<a href="/error">', status=500)):
        with patch("modules.web.crawler.get", return_value=response):
            assert link_finder("http://example.com/", MagicMock()) == set()


@pytest.mark.unit
def test_malformed_base_links_and_actions_are_skipped(web_response):
    response = web_response('<base href="http://[broken"><a href="http://[broken">Bad</a><a href="/good">Good</a><form action="http://[broken"><input name="q"></form>')
    with patch("modules.web.crawler.get", return_value=response):
        assert link_finder("http://example.com/", MagicMock()) == {"http://example.com/good"}
