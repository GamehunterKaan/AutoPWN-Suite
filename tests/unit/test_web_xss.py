"""
Unit tests for the xss module.
"""
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.xss import XSSScanner


@pytest.mark.unit
class TestXSSScanner:
    """Tests for the XSSScanner class."""

    @pytest.fixture
    def mock_log_console(self):
        """Fixture for a mocked logger and console."""
        return MagicMock(), MagicMock()

    @patch("modules.web.xss.get")
    @patch("modules.web.xss.choices")
    def test_xss_vulnerability_found(self, mock_choices, mock_get, mock_log_console):
        """Verify that an XSS vulnerability is detected and printed."""
        mock_log, mock_console = mock_log_console

        # Make the random payload predictable for the test
        fixed_payload_text = "fixedpayload"
        mock_choices.return_value = list(fixed_payload_text)

        mock_response = MagicMock()
        # Simulate a response that reflects the payload
        mock_response.text = f"<html><body>Search results for {fixed_payload_text}</body></html>"
        mock_get.return_value = mock_response

        xss_tester = XSSScanner(mock_log, mock_console)
        test_url = "http://example.com/search?q=test"
        xss_tester.test_xss(test_url)

        # Verify that a vulnerability was printed to the console
        mock_console.print.assert_called()
        assert "[white]XSS :[/white]" in mock_console.print.call_args[0][0]
        assert fixed_payload_text in mock_console.print.call_args[0][0]

    @patch("modules.web.xss.get")
    def test_xss_no_vulnerability(self, mock_get, mock_log_console):
        """Verify that no vulnerability is reported for a clean response."""
        mock_log, mock_console = mock_log_console
        mock_response = MagicMock()
        # Simulate a normal response that does not reflect the payload
        mock_response.text = "<html><body>Search results</body></html>"
        mock_get.return_value = mock_response

        xss_tester = XSSScanner(mock_log, mock_console)
        test_url = "http://example.com/search?q=test"
        xss_tester.test_xss(test_url)

        # Verify that nothing was printed to the console
        mock_console.print.assert_not_called()

    @patch("modules.web.xss.ConnectionError", new=ConnectionError)
    @patch("modules.web.xss.get", side_effect=ConnectionError)
    def test_xss_connection_error(self, mock_get, mock_log_console):
        """Verify that a connection error is handled gracefully."""
        mock_log, mock_console = mock_log_console

        xss_tester = XSSScanner(mock_log, mock_console)
        test_url = "http://example.com/search?q=test"
        xss_tester.test_xss(test_url)

        # Verify that the error was logged
        mock_log.logger.assert_called()
        assert "Connection error raised on" in mock_log.logger.call_args[0][1]