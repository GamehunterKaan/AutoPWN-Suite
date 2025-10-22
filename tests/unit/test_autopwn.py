"""
Unit tests for the main autopwn.py script.
"""
from unittest.mock import MagicMock, patch

import pytest

from autopwn import main, StartScanning


@pytest.mark.unit
class TestMainExecution:
    """Tests for the main function in autopwn.py."""

    @patch("autopwn.cli")
    def test_main_version_flag(self, mock_cli, capsys):
        """Verify that the -v flag prints the version and exits."""
        # Mock the CLI arguments to simulate '-v'
        mock_args = MagicMock()
        mock_args.version = True
        mock_args.no_color = True  # To simplify console mocking
        mock_cli.return_value = mock_args

        with pytest.raises(SystemExit):
            main()

        captured = capsys.readouterr()
        assert "AutoPWN Suite v" in captured.out

    @patch("autopwn.SaveOutput")
    @patch("autopwn.InitializeReport")
    @patch("autopwn.StartScanning")
    @patch("autopwn.ParamPrint")
    @patch("autopwn.InitReport")
    @patch("autopwn.InitArgsAPI")
    @patch("autopwn.InitArgsMode")
    @patch("autopwn.InitArgsScanType")
    @patch("autopwn.InitArgsTarget")
    @patch("autopwn.InitAutomation")
    @patch("autopwn.InitArgsConf")
    @patch("autopwn.CheckConnection")
    @patch("autopwn.print_banner")
    @patch("autopwn.cli")
    def test_main_basic_scan_flow(self, mock_cli, mock_banner, mock_check_connection, mock_init_conf, mock_init_auto, mock_init_target, mock_init_scantype, mock_init_mode, mock_init_api, mock_init_report, *other_mocks):
        """Verify the main orchestration flow of the application."""
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.config = None  # No config file
        mock_args.daemon_install = False
        mock_args.daemon_uninstall = False
        mock_args.create_config = False
        mock_args.no_color = True
        mock_args.report = None # Explicitly set no report
        mock_args.scan_interval = None # Prevent TypeError on comparison
        mock_cli.return_value = mock_args

        # Configure the mock for InitReport to return a tuple
        mock_init_report.return_value = (None, None)

        main()

        all_mocks = [
            mock_banner, mock_check_connection, mock_init_conf, mock_init_auto,
            mock_init_target, mock_init_scantype, mock_init_mode, mock_init_api,
            mock_init_report
        ] + list(other_mocks)

        # Verify that all the main setup and execution functions are called
        # Note: InitArgsConf is not called in this path because args.config is None
        for func in all_mocks:
            if func is mock_init_conf:
                func.assert_not_called()
                continue
            func.assert_called_once()

    @patch("autopwn.SaveOutput")
    @patch("autopwn.InitializeReport")
    @patch("autopwn.StartScanning")
    @patch("autopwn.ParamPrint")
    @patch("autopwn.InitReport")
    @patch("autopwn.InitArgsAPI")
    @patch("autopwn.InitArgsMode")
    @patch("autopwn.InitArgsScanType")
    @patch("autopwn.InitArgsTarget")
    @patch("autopwn.InitAutomation")
    @patch("autopwn.InitArgsConf")
    @patch("autopwn.CheckConnection")
    @patch("autopwn.print_banner")
    @patch("autopwn.cli")
    def test_main_with_config_file(self, mock_cli, mock_banner, mock_check_connection, mock_init_conf, mock_init_auto, mock_init_target, mock_init_scantype, mock_init_mode, mock_init_api, mock_init_report, *other_mocks):
        """Verify that InitArgsConf is called when a config file is provided."""
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.config = "test.ini"
        mock_args.daemon_install = False
        mock_args.daemon_uninstall = False
        mock_args.create_config = False
        mock_args.no_color = True
        mock_args.report = None
        mock_args.scan_interval = None # Prevent TypeError on comparison
        mock_cli.return_value = mock_args

        # Configure the mock for InitReport to return a tuple
        mock_init_report.return_value = (None, None)

        main()

        # Specifically check that InitArgsConf was called because a config was provided
        mock_init_conf.assert_called_once()

    @patch("autopwn.InstallDaemon")
    @patch("autopwn.cli")
    @patch("autopwn.print_banner") # Patch functions that should NOT be called
    @patch("autopwn.CheckConnection")
    @patch("autopwn.InitArgsConf")
    def test_main_daemon_install_flow(self, mock_init_conf, mock_check_connection, mock_print_banner, mock_cli, mock_install_daemon):
        """Verify that the --daemon-install flag correctly triggers the installer and exits."""
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.daemon_install = True # This is the key for this test
        mock_args.no_color = True
        mock_cli.return_value = mock_args

        with pytest.raises(SystemExit):
            main()

        # Verify that InstallDaemon was called exactly once
        mock_install_daemon.assert_called_once()

        # Verify that other parts of the main flow were NOT called
        # because daemon_install should short-circuit the execution.
        mock_print_banner.assert_not_called()
        mock_check_connection.assert_not_called()
        mock_init_conf.assert_not_called()
        # We don't need to assert on all other InitArgs* functions
        # as they are downstream from print_banner and CheckConnection.
        # If those aren't called, neither should the others.

        # Verify that cli was called to get the arguments
        mock_cli.assert_called_once()


@pytest.mark.unit
@patch("autopwn.check_nmap")
class TestStartScanning:
    """Tests for the StartScanning function."""
    
    @patch("builtins.input")
    @patch("autopwn.NoiseScan")
    def test_start_scanning_noise_mode(self, mock_noise_scan, mock_input, mock_check_nmap):
        """Verify that only NoiseScan is called in Noise mode."""
        args = MagicMock(yes_please=False)
        # NoiseScan is designed to exit the program. We simulate this behavior.
        mock_noise_scan.side_effect = SystemExit

        from modules.utils import ScanMode, ScanType
        from autopwn import InitAutomation
        InitAutomation(args) # Set up the global state
        with pytest.raises(SystemExit):
            StartScanning(args, "target", ScanType.Ping, ScanMode.Noise, "apiKey", MagicMock(), MagicMock(), MagicMock())
        mock_noise_scan.assert_called_once()

    @patch("autopwn.webvuln")
    @patch("autopwn.GetExploitsFromArray")
    @patch("autopwn.SearchSploits")
    @patch("autopwn.AnalyseScanResults")
    @patch("autopwn.PortScan")
    @patch("autopwn.WebScan", return_value=True)
    @patch("autopwn.UserConfirmation", return_value=(True, True, True))
    @patch("autopwn.GetHostsToScan", return_value=["192.168.1.1"])
    @patch("autopwn.DiscoverHosts")
    def test_full_scan_flow(self, mock_discover, mock_get_hosts, mock_user_confirm, mock_web_scan, mock_port_scan, mock_analyse, mock_search_vulns, mock_get_exploits, mock_webvuln, mock_check_nmap):
        """Verify all scanning functions are called when user confirms all."""
        args = MagicMock(skip_discovery=False, yes_please=False)
        from autopwn import InitAutomation
        InitAutomation(args)
        from modules.utils import ScanMode
        
        # Mock return values to allow the chain to complete
        mock_port_scan.return_value = "port_scan_results"
        mock_analyse.return_value = ["port_array"]
        mock_search_vulns.return_value = ["vulns_array"]

        StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_discover.assert_called_once()
        mock_port_scan.assert_called_once()
        mock_search_vulns.assert_called_once()
        mock_get_exploits.assert_called_once()
        mock_webvuln.assert_called_once()

    @patch("autopwn.webvuln")
    @patch("autopwn.GetExploitsFromArray")
    @patch("autopwn.SearchSploits")
    @patch("autopwn.AnalyseScanResults")
    @patch("autopwn.PortScan")
    @patch("autopwn.WebScan", return_value=False)
    @patch("autopwn.UserConfirmation", return_value=(True, False, False)) # User says NO to vuln scan
    @patch("autopwn.GetHostsToScan", return_value=["192.168.1.1"])
    @patch("autopwn.DiscoverHosts")
    def test_partial_scan_flow(self, mock_discover, mock_get_hosts, mock_user_confirm, mock_web_scan, mock_port_scan, mock_analyse, mock_search_vulns, mock_get_exploits, mock_webvuln, mock_check_nmap):
        """Verify vuln scan and exploit download are skipped if user says no."""
        args = MagicMock(skip_discovery=False, yes_please=False)
        from modules.utils import ScanMode
        from autopwn import InitAutomation
        InitAutomation(args)
        StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_port_scan.assert_called_once()
        mock_search_vulns.assert_not_called()
        mock_get_exploits.assert_not_called()

    @patch("builtins.input")
    @patch("autopwn.DiscoverHosts")
    def test_skip_discovery(self, mock_discover, mock_input, mock_check_nmap):
        """Verify DiscoverHosts is not called when skip_discovery is True."""
        args = MagicMock(skip_discovery=True, yes_please=False)
        from modules.utils import ScanMode
        from autopwn import InitAutomation
        InitAutomation(args)
        # Mock UserConfirmation and WebScan to prevent the scan from proceeding into slow network calls
        with patch("autopwn.UserConfirmation", return_value=(False, False, False)), \
             patch("autopwn.WebScan", return_value=False):
            StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_discover.assert_not_called()