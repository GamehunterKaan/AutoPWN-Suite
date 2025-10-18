"""
Unit tests for the sqli module.
"""
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.sqli import SQLIScanner


@pytest.mark.unit
class TestSQLIScanner:
    """Tests for the SQLIScanner class."""

    @pytest.fixture
    def mock_log_console(self):
        """Fixture for a mocked logger and console."""
        return MagicMock(), MagicMock()

    @patch("modules.web.sqli.get")
    def test_sqli_vulnerability_found(self, mock_get, mock_log_console):
        """Verify that a SQLi vulnerability is detected and printed."""
        mock_log, mock_console = mock_log_console
        mock_response = MagicMock()
        # Simulate a response containing a SQL error message
        mock_response.text = "Error: You have an error in your SQL syntax"
        mock_get.return_value = mock_response

        sqli_tester = SQLIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?id=1&user=test"
        sqli_tester.test_sqli(test_url)

        # Verify that a vulnerability was printed to the console
        mock_console.print.assert_called()
        assert "[white]SQLI :[/white] http://example.com/page?id='1" in mock_console.print.call_args[0][0]

    @patch("modules.web.sqli.get")
    def test_sqli_no_vulnerability(self, mock_get, mock_log_console):
        """Verify that no vulnerability is reported for a clean response."""
        mock_log, mock_console = mock_log_console
        mock_response = MagicMock()
        # Simulate a normal response
        mock_response.text = "<html><body>Hello, world!</body></html>"
        mock_get.return_value = mock_response

        sqli_tester = SQLIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?id=1"
        sqli_tester.test_sqli(test_url)

        # Verify that nothing was printed to the console
        mock_console.print.assert_not_called()

    # Patch the ConnectionError within the module where it's being caught.
    @patch("modules.web.sqli.ConnectionError", new=ConnectionError)
    @patch("modules.web.sqli.get", side_effect=ConnectionError)
    def test_sqli_connection_error(self, mock_get, mock_log_console):
        """Verify that a connection error is handled gracefully."""
        mock_log, mock_console = mock_log_console

        sqli_tester = SQLIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?id=1"

        sqli_tester.test_sqli(test_url)

        # Verify that the error was logged
        mock_log.logger.assert_called_once()
        assert "Connection error raised on" in mock_log.logger.call_args[0][1]