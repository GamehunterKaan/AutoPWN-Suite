"""
Unit tests for the dirbust module.
"""
from unittest.mock import MagicMock, mock_open, patch

import pytest
from requests.exceptions import ConnectionError

from modules.web.dirbust import dirbust


@pytest.mark.unit
class TestDirbust:
    """Tests for the dirbust function."""

    @pytest.fixture
    def mock_log_console(self):
        """Fixture for a mocked logger and console."""
        return MagicMock(), MagicMock()

    @patch("modules.web.dirbust.random_user_agent")
    @patch("modules.web.dirbust.get")
    @patch("modules.web.dirbust.open", new_callable=mock_open, read_data="admin\napi")
    def test_dir_found_200(self, mock_file, mock_get, mock_ua, mock_log_console):
        """Verify a found directory (200 OK) is printed."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA", "Test-UA-2"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_get.return_value = mock_response

        dirbust("http://example.com", mock_console, mock_log)

        # It should be called for 'admin' and 'api'
        assert mock_console.print.call_count == 2
        mock_console.print.assert_any_call("[red][[/red][green]+[/green][red]][/red] [white]DIR :[/white] http://example.com/admin")

    @patch("modules.web.dirbust.random_user_agent")
    @patch("modules.web.dirbust.get")
    @patch("modules.web.dirbust.open", new_callable=mock_open, read_data="test")
    def test_dir_not_found_404(self, mock_file, mock_get, mock_ua, mock_log_console):
        """Verify a 404 response is correctly ignored."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA"])

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        dirbust("http://example.com", mock_console, mock_log)

        mock_console.print.assert_not_called()

    @patch("modules.web.dirbust.random_user_agent")
    @patch("modules.web.dirbust.get")
    @patch("modules.web.dirbust.open", new_callable=mock_open, read_data="admin")
    def test_dir_redirect(self, mock_file, mock_get, mock_ua, mock_log_console):
        """Verify a redirect is correctly identified and printed."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA"])

        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.is_redirect = True
        mock_response.url = "http://example.com/admin/"
        mock_get.return_value = mock_response

        dirbust("http://example.com", mock_console, mock_log)

        mock_console.print.assert_called_once_with(
            "[red][[/red][green]+[/green][red]][/red] [white]DIR :[/white] http://example.com/admin -> http://example.com/admin/"
        )

    @patch("modules.web.dirbust.open", side_effect=FileNotFoundError)
    def test_wordlist_not_found(self, mock_file, mock_log_console):
        """Verify that a missing wordlist is handled gracefully."""
        mock_log, mock_console = mock_log_console
        dirbust("http://example.com", mock_console, mock_log)
        mock_log.logger.assert_called_with("error", "Web discovery database not found.")

    @patch("modules.web.dirbust.random_user_agent")
    @patch("modules.web.dirbust.get", side_effect=ConnectionError("Test connection error"))
    @patch("modules.web.dirbust.open", new_callable=mock_open, read_data="admin")
    def test_connection_error(self, mock_file, mock_get, mock_ua, mock_log_console):
        """Verify that a connection error is handled gracefully."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA"])

        dirbust("http://example.com", mock_console, mock_log)

        # Check that logger was called with an error and a ConnectionError instance
        mock_log.logger.assert_called_once()
        call_args, _ = mock_log.logger.call_args
        assert call_args[0] == "error"
        assert isinstance(call_args[1], ConnectionError)
        assert str(call_args[1]) == "Test connection error"

    @patch("modules.web.dirbust.random_user_agent")
    @patch("modules.web.dirbust.get", side_effect=Exception("Generic test error"))
    @patch("modules.web.dirbust.open", new_callable=mock_open, read_data="admin")
    def test_dirbust_generic_exception(self, mock_file, mock_get, mock_ua, mock_log_console):
        """Verify that a generic exception is handled gracefully."""
        mock_log, mock_console = mock_log_console
        mock_ua.return_value = iter(["Test-UA"])

        dirbust("http://example.com", mock_console, mock_log)

        # Check that the logger was called with an error and the Exception instance
        mock_log.logger.assert_called_once()
        call_args, _ = mock_log.logger.call_args
        assert call_args[0] == "error"
        assert isinstance(call_args[1], Exception)
        assert str(call_args[1]) == "Generic test error"