"""
Unit tests for the logger module.
"""
from unittest.mock import MagicMock, patch, call

import pytest
from rich.text import Text

from modules.logger import Logger, banner


@pytest.mark.unit
class TestLogger:
    """Tests for the Logger class."""

    @pytest.fixture
    def mock_console(self):
        """Fixture for a mocked Rich Console."""
        return MagicMock()

    @patch("modules.logger.logging")
    def test_logger_init(self, mock_logging, mock_console):
        """Verify that the logger is initialized correctly."""
        Logger(mock_console)
        mock_logging.basicConfig.assert_called_once()
        assert mock_logging.getLogger.called

    def test_log_levels(self, mock_console):
        """Test logging messages for all levels."""
        logger_instance = Logger(mock_console)
        logger_instance.log = MagicMock()

        # Test info
        logger_instance.logger("info", "info message")
        logger_instance.log.info.assert_called_with("[+] info message")

        # Test error
        logger_instance.logger("error", "error message")
        logger_instance.log.error.assert_called_with("[-] error message")

        # Test warning
        logger_instance.logger("warning", "warning message")
        logger_instance.log.warning.assert_called_with("[*] warning message")

        # Test success (which maps to info)
        logger_instance.logger("success", "success message")
        logger_instance.log.info.assert_called_with("[+] success message")


@pytest.mark.unit
@patch("modules.logger.get_terminal_width", return_value=80)
def test_banner(mock_width):
    """Test that the banner function prints correctly."""
    mock_console = MagicMock()
    msg = "Test Banner"
    color = "green"

    banner(msg, color, mock_console)

    expected_calls = [
        call("─" * 80, style=color),
        call(Text(msg), justify="center", style=color),
        call("─" * 80, style=color),
    ]
    mock_console.print.assert_has_calls(expected_calls)