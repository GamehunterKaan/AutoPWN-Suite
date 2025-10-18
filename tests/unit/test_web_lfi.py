"""
Unit tests for the lfi module.
"""
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.lfi import LFIScanner


@pytest.mark.unit
class TestLFIScanner:
    """Tests for the LFIScanner class."""

    @pytest.fixture
    def mock_log_console(self):
        """Fixture for a mocked logger and console."""
        return MagicMock(), MagicMock()

    @patch("modules.web.lfi.get")
    def test_lfi_vulnerability_found(self, mock_get, mock_log_console):
        """Verify that an LFI vulnerability is detected and printed."""
        mock_log, mock_console = mock_log_console
        mock_response = MagicMock()
        # Simulate a response containing the content of /etc/passwd
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_get.return_value = mock_response

        lfi_tester = LFIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?file=test.txt"
        lfi_tester.test_lfi(test_url)

        # Verify that a vulnerability was printed to the console
        mock_console.print.assert_called()
        assert "[white]LFI :[/white]" in mock_console.print.call_args[0][0]

    @patch("modules.web.lfi.get")
    def test_lfi_no_vulnerability(self, mock_get, mock_log_console):
        """Verify that no vulnerability is reported for a clean response."""
        mock_log, mock_console = mock_log_console
        mock_response = MagicMock()
        # Simulate a normal response
        mock_response.text = "<html><body>Hello, world!</body></html>"
        mock_get.return_value = mock_response

        lfi_tester = LFIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?file=test.txt"
        lfi_tester.test_lfi(test_url)

        # Verify that nothing was printed to the console
        mock_console.print.assert_not_called()

    # Patch the ConnectionError within the module where it's being caught.
    @patch("modules.web.lfi.ConnectionError", new=ConnectionError)
    @patch("modules.web.lfi.get", side_effect=ConnectionError)
    def test_lfi_connection_error(self, mock_get, mock_log_console):
        """Verify that a connection error is handled gracefully."""
        mock_log, mock_console = mock_log_console

        lfi_tester = LFIScanner(mock_log, mock_console)
        test_url = "http://example.com/page?file=test.txt"
        lfi_tester.test_lfi(test_url)

        # Verify that the error was logged
        mock_log.logger.assert_called()
        assert "Connection error raised on" in mock_log.logger.call_args[0][1]