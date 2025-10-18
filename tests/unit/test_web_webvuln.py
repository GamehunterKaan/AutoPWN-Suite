"""
Unit tests for the webvuln module.
"""
from unittest.mock import MagicMock, patch, call
from requests.exceptions import ConnectionError

import pytest

from modules.web.webvuln import webvuln


@pytest.mark.unit
class TestWebVuln:
    """Tests for the main webvuln orchestration function."""

    @pytest.fixture
    def mock_log_console(self):
        """Fixture for a mocked logger and console."""
        return MagicMock(), MagicMock()

    @patch("modules.web.webvuln.random_user_agent")
    @patch("modules.web.webvuln.get", side_effect=ConnectionError)
    def test_webvuln_no_web_server(self, mock_get, mock_ua, mock_log_console):
        """Verify webvuln exits if get_url can't find a server."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA"])

        webvuln("127.0.0.1", mock_log, mock_console)

        # Verify it tried to connect to both http and https
        mock_get.assert_has_calls([call("http://127.0.0.1/", headers={'User-Agent': 'Test-UA'}, timeout=10, verify=False), call("https://127.0.0.1/", headers={'User-Agent': 'Test-UA'}, timeout=10, verify=False)])
        # Ensure no other actions were taken
        mock_log.logger.assert_not_called()

    @patch("modules.web.webvuln.get")
    @patch("modules.web.webvuln.crawl", return_value={"http://example.com/index.html"})
    def test_webvuln_no_testable_urls(self, mock_crawl, mock_get, mock_log_console):
        """Verify webvuln logs and exits if no testable URLs are found."""
        mock_log, mock_console = mock_log_console
        webvuln("example.com", mock_log, mock_console)

        mock_crawl.assert_called_once_with("http://example.com/", mock_log)
        mock_log.logger.assert_called_with("info", "Found 0 testable urls.")

    @patch("modules.web.webvuln.dirbust")
    @patch("modules.web.webvuln.XSSScanner")
    @patch("modules.web.webvuln.SQLIScanner")
    @patch("modules.web.webvuln.LFIScanner")
    @patch("modules.web.webvuln.crawl")
    @patch("modules.web.webvuln.get")
    def test_webvuln_success_path(
        self,
        mock_get,
        mock_crawl,
        mock_lfi_scanner,
        mock_sqli_scanner,
        mock_xss_scanner,
        mock_dirbust,
        mock_log_console,
    ):
        """Verify that all scanners are called for a testable URL."""
        mock_log, mock_console = mock_log_console
        target_url = "http://example.com/"
        testable_url = "http://example.com/page?id=1"

        mock_crawl.return_value = {testable_url}

        # Mock the instances of the scanner classes
        mock_lfi_instance = mock_lfi_scanner.return_value
        mock_sqli_instance = mock_sqli_scanner.return_value
        mock_xss_instance = mock_xss_scanner.return_value

        webvuln("example.com", mock_log, mock_console)

        # Verify orchestration functions are called
        mock_dirbust.assert_called_once_with(target_url, mock_console, mock_log)

        # Verify individual scanners are called with the testable URL
        mock_lfi_instance.test_lfi.assert_called_once_with(testable_url)
        mock_sqli_instance.test_sqli.assert_called_once_with(testable_url)
        mock_xss_instance.test_xss.assert_called_once_with(testable_url)