"""
Unit tests for the daemon_installer.py module.
"""
from unittest.mock import MagicMock, patch, call, mock_open
from configparser import ConfigParser
import io

import pytest

from modules.daemon.daemon_installer import (
    _get_menu_choice,
    _get_validated_int,
    _get_validated_email,
    _get_non_empty_input,
    InstallDaemon,
)


@pytest.fixture
def mock_console():
    """Fixture for a mocked Rich Console."""
    return MagicMock()


@pytest.mark.unit
class TestDaemonInstallerHelpers:
    """Tests for the helper functions in the daemon installer."""

    @pytest.mark.parametrize("user_input, expected", [
        ("1", "1"),
        ("2", "2"),
        ("", "1"), # Default
    ])
    @patch("builtins.input")
    def test_get_menu_choice(self, mock_input, mock_console, user_input, expected):
        """Verify menu choice selection, including defaults."""
        mock_input.return_value = user_input
        options = {"1": "Option 1", "2": "Option 2"}
        result = _get_menu_choice(mock_console, "Prompt", options, default="1")
        assert result == expected

    @patch("builtins.input", side_effect=["abc", "123"])
    def test_get_validated_int_retry(self, mock_input, mock_console):
        """Verify it re-prompts after invalid integer input."""
        result = _get_validated_int(mock_console, "Prompt")
        assert result == 123
        assert mock_input.call_count == 2
        mock_console.print.assert_called_with("[red]Invalid input. Please enter a whole number.[/red]")

    @patch("builtins.input", side_effect=["invalid-email", "valid@example.com"])
    def test_get_validated_email_retry(self, mock_input, mock_console):
        """Verify it re-prompts after invalid email input."""
        result = _get_validated_email(mock_console, "Prompt")
        assert result == "valid@example.com"
        assert mock_input.call_count == 2
        mock_console.print.assert_called_with("[red]Invalid email format. Please enter a valid email address.[/red]")

    @patch("builtins.input", side_effect=["", "  ", "some value"])
    def test_get_non_empty_input_retry(self, mock_input, mock_console):
        """Verify it re-prompts after empty input."""
        result = _get_non_empty_input(mock_console, "Prompt")
        assert result == "some value"
        assert mock_input.call_count == 3
        mock_console.print.assert_has_calls([
            call("[red]This field cannot be empty.[/red]"),
            call("[red]This field cannot be empty.[/red]")
        ])


@pytest.mark.unit
class TestInstallDaemon:
    """Tests for the main InstallDaemon function."""

    @patch("modules.daemon.daemon_installer.ConfigParser") # This should be patched as a class
    @patch("builtins.open", new_callable=mock_open) # Use mock_open for builtins.open
    @patch("builtins.input")
    def test_install_daemon_flow(self, mock_input, mock_open, mock_config_parser, mock_console):
        """Verify the full daemon installation flow and config file creation."""
        # Mock a sequence of user inputs for all prompts
        mock_input.side_effect = [
            "60",  # scan_interval
            "1",  # report_choice (Email)
            "user@example.com",  # report_email
            "password123",  # report_email_password
            "to@example.com",  # report_email_to
            "",  # report_email_from (empty)
            "smtp.example.com",  # report_email_server
            "587",  # report_email_server_port
            "192.168.1.0/24",  # target
            "",  # host_file
            "test-api-key",  # api_key
            "-sC",  # nmap_flags
            "4",  # speed
            "y",  # skip_discovery
            "2",  # scan_type_choice (Ping)
            "300",  # host_timeout
            "2",  # scan_method_choice (Evade)
            "my_outputs",  # output_folder
            "txt",  # output_type
        ]

        mock_config_instance = MagicMock()
        mock_config_parser.return_value = mock_config_instance

        InstallDaemon(mock_console)

        # Verify the AUTOPWN section
        autopwn_config = mock_config_instance.__setitem__.call_args_list[0][0][1]
        assert autopwn_config['target'] == "192.168.1.0/24"
        assert autopwn_config['speed'] == 4
        assert autopwn_config['skip_discovery'] == "True"
        assert autopwn_config['scan_type'] == "ping"
        assert autopwn_config['mode'] == "evade"
        assert autopwn_config['output_folder'] == "my_outputs"

        # Verify the REPORT section
        report_config = mock_config_instance.__setitem__.call_args_list[1][0][1]
        assert report_config['method'] == "email"

        # Verify the config was written
        mock_config_instance.write.assert_called_once()

    @patch("autopwn.InstallDaemon")
    @patch("autopwn.cli")
    @patch("autopwn.print_banner")
    @patch("autopwn.CheckConnection")
    @patch("autopwn.InitArgsConf")
    def test_main_daemon_install_flow(self, mock_init_conf, mock_check_connection, mock_print_banner, mock_cli, mock_install_daemon):
        """Verify that the --daemon-install flag correctly triggers the installer and exits."""
        # This test is for the entrypoint in autopwn.py
        from autopwn import main

        mock_args = MagicMock()
        mock_args.version = False
        mock_args.daemon_install = True # This is the key for this test
        mock_args.no_color = True
        mock_cli.return_value = mock_args

        with pytest.raises(SystemExit):
            main()

        mock_install_daemon.assert_called_once()
        mock_print_banner.assert_not_called()
        mock_check_connection.assert_not_called()
        mock_init_conf.assert_not_called()