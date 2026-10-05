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

        found_urls = crawl("http://example.com", mock_log)

        # link_finder should only be called once
        mock_link_finder.assert_called_once()
        assert found_urls == initial_urls

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
        ]

        found_urls = crawl("http://example.com", mock_log)

        assert mock_link_finder.call_count == 2
        assert found_urls == {"http://example.com/page1", "http://example.com/page2"}

    @patch("modules.web.crawler.ConnectionError", new=ConnectionError)
    @patch("modules.web.crawler.random_user_agent")
    @patch("modules.web.crawler.get", side_effect=ConnectionError)
    def test_crawl_initial_connection_error(self, mock_get, mock_ua, mock_log):
        """Verify crawl handles a connection error on the initial request."""
        mock_ua.return_value = iter(["Test-UA"])

        found_urls = crawl("http://example.com", mock_log)

        # Assert that it returns an empty set and logs the error
        assert found_urls == set()
        mock_log.logger.assert_called_with("error", "Connection error raised.")

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
        assert mock_get.call_args.args[0] == "https://example.com/?view=one"
