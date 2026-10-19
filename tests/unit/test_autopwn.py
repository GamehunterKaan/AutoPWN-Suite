# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the main autopwn.py script.
"""
from unittest.mock import DEFAULT, MagicMock, patch

import pytest

from autopwn_suite.cli import StartScanning, main
from autopwn_suite.utils import GetHostsToScan, NoHostsFound


@pytest.mark.unit
class TestMainExecution:
    """Tests for the main function in autopwn.py."""

    @patch("autopwn_suite.cli.cli")
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

    @patch("autopwn_suite.cli.SaveOutput")
    @patch("autopwn_suite.cli.InitializeReport")
    @patch("autopwn_suite.cli.StartScanning")
    @patch("autopwn_suite.cli.ParamPrint")
    @patch("autopwn_suite.cli.InitReport")
    @patch("autopwn_suite.cli.InitArgsAPI")
    @patch("autopwn_suite.cli.InitArgsMode")
    @patch("autopwn_suite.cli.InitArgsScanType")
    @patch("autopwn_suite.cli.InitArgsTarget")
    @patch("autopwn_suite.cli.InitAutomation")
    @patch("autopwn_suite.cli.InitArgsConf")
    @patch("autopwn_suite.cli.CheckConnection")
    @patch("autopwn_suite.cli.print_banner")
    @patch("autopwn_suite.cli.cli")
    def test_main_basic_scan_flow(self, mock_cli, mock_banner, mock_check_connection, mock_init_conf, mock_init_auto, mock_init_target, mock_init_scantype, mock_init_mode, mock_init_api, mock_init_report, *other_mocks):
        """Verify the main orchestration flow of the application."""
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.config = None  # No config file
        mock_args.daemon_install = False
        mock_args.daemon_uninstall = False
        mock_args.create_config = False
        mock_args.no_color = True
        mock_args.web = False
        mock_args.report = None # Explicitly set no report
        mock_args.vulnerability_source = "auto"
        mock_args.vuln_db = None
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
            if func is mock_check_connection:
                func.assert_not_called()
                continue
            if func is mock_init_conf:
                func.assert_not_called()
                continue
            func.assert_called_once()

    @patch("autopwn_suite.cli.SaveOutput")
    @patch("autopwn_suite.cli.InitializeReport")
    @patch("autopwn_suite.cli.StartScanning")
    @patch("autopwn_suite.cli.ParamPrint")
    @patch("autopwn_suite.cli.InitReport")
    @patch("autopwn_suite.cli.InitArgsAPI")
    @patch("autopwn_suite.cli.InitArgsMode")
    @patch("autopwn_suite.cli.InitArgsScanType")
    @patch("autopwn_suite.cli.InitArgsTarget")
    @patch("autopwn_suite.cli.InitAutomation")
    @patch("autopwn_suite.cli.InitArgsConf")
    @patch("autopwn_suite.cli.CheckConnection")
    @patch("autopwn_suite.cli.print_banner")
    @patch("autopwn_suite.cli.cli")
    def test_main_with_config_file(self, mock_cli, mock_banner, mock_check_connection, mock_init_conf, mock_init_auto, mock_init_target, mock_init_scantype, mock_init_mode, mock_init_api, mock_init_report, *other_mocks):
        """Verify that InitArgsConf is called when a config file is provided."""
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.config = "test.ini"
        mock_args.daemon_install = False
        mock_args.daemon_uninstall = False
        mock_args.create_config = False
        mock_args.no_color = True
        mock_args.web = False
        mock_args.report = None
        mock_args.vulnerability_source = "auto"
        mock_args.vuln_db = None
        mock_args.scan_interval = None # Prevent TypeError on comparison
        mock_cli.return_value = mock_args

        # Configure the mock for InitReport to return a tuple
        mock_init_report.return_value = (None, None)

        main()

        # Specifically check that InitArgsConf was called because a config was provided
        mock_init_conf.assert_called_once()

    @patch("autopwn_suite.cli.InstallDaemon")
    @patch("autopwn_suite.cli.cli")
    @patch("autopwn_suite.cli.print_banner") # Patch functions that should NOT be called
    @patch("autopwn_suite.cli.CheckConnection")
    @patch("autopwn_suite.cli.InitArgsConf")
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
class TestEmptyDiscovery:
    """With a scan interval (the daemon) an empty discovery is a finished round: the process waits for the
    next one instead of exiting, because systemd restarts an exited service after 5 seconds."""

    @staticmethod
    def run_main(scan_interval):
        args = MagicMock(
            version=False, config=None, daemon_install=False, daemon_uninstall=False, create_config=False,
            no_color=True, web=False, web_reset_account=False, offline=False, update_vuln_db=False,
            vuln_db_status=False, vulnerability_source="auto", vuln_db=None, scan_interval=scan_interval)
        with patch("autopwn_suite.cli.cli", return_value=args), patch.multiple(
                "autopwn_suite.cli", print_banner=DEFAULT, InitAutomation=DEFAULT, InitArgsTarget=DEFAULT,
                InitArgsScanType=DEFAULT, InitArgsMode=DEFAULT, InitArgsAPI=DEFAULT, InitReport=DEFAULT,
                ParamPrint=DEFAULT, StartScanning=DEFAULT, InitializeReport=DEFAULT, SaveOutput=DEFAULT,
                sleep=DEFAULT) as mocks:
            mocks["InitReport"].return_value = (None, None)
            mocks["StartScanning"].side_effect = NoHostsFound("No hosts found! Oct 19 2026 12:00:00 - Scan completed.")
            main()
        return mocks

    def test_a_daemon_waits_for_its_next_round(self):
        mocks = self.run_main(3600)

        mocks["sleep"].assert_called_once_with(3600)
        # Nothing was scanned: no empty report is sent and no empty output file is written.
        mocks["InitializeReport"].assert_not_called()
        mocks["SaveOutput"].assert_not_called()

    @pytest.mark.parametrize("scan_interval", [None, 0])
    def test_a_single_run_still_ends_with_the_message_and_a_failure_status(self, scan_interval):
        with pytest.raises(SystemExit) as stopped:
            self.run_main(scan_interval)

        assert isinstance(stopped.value, NoHostsFound)
        assert "No hosts found!" in str(stopped.value) and stopped.value.code

    def test_discovery_without_hosts_raises_the_dedicated_exit(self):
        with pytest.raises(NoHostsFound, match="No hosts found!"):
            GetHostsToScan([], MagicMock())


@pytest.mark.unit
@patch("autopwn_suite.cli.check_nmap")
class TestStartScanning:
    """Tests for the StartScanning function."""

    @patch("builtins.input")
    @patch("autopwn_suite.cli.NoiseScan")
    def test_start_scanning_noise_mode(self, mock_noise_scan, mock_input, mock_check_nmap):
        """Verify that only NoiseScan is called in Noise mode."""
        args = MagicMock(yes_please=False)
        # NoiseScan is designed to exit the program. We simulate this behavior.
        mock_noise_scan.side_effect = SystemExit

        from autopwn_suite.cli import InitAutomation
        from autopwn_suite.utils import ScanMode, ScanType
        InitAutomation(args) # Set up the global state
        with pytest.raises(SystemExit):
            StartScanning(args, "target", ScanType.Ping, ScanMode.Noise, "apiKey", MagicMock(), MagicMock(), MagicMock())
        mock_noise_scan.assert_called_once()

    @patch("autopwn_suite.cli.webvuln")
    @patch("autopwn_suite.cli.GetExploitsFromArray")
    @patch("autopwn_suite.cli.SearchSploits")
    @patch("autopwn_suite.cli.AnalyseScanResults")
    @patch("autopwn_suite.cli.PortScan")
    @patch("autopwn_suite.cli.WebScan", return_value=True)
    @patch("autopwn_suite.cli.UserConfirmation", return_value=(True, True, True))
    @patch("autopwn_suite.cli.GetHostsToScan", return_value=["192.168.1.1"])
    @patch("autopwn_suite.cli.DiscoverHosts")
    def test_full_scan_flow(self, mock_discover, mock_get_hosts, mock_user_confirm, mock_web_scan, mock_port_scan, mock_analyse, mock_search_vulns, mock_get_exploits, mock_webvuln, mock_check_nmap):
        """Verify all scanning functions are called when user confirms all."""
        args = MagicMock(skip_discovery=False, yes_please=False)
        from autopwn_suite.cli import InitAutomation
        InitAutomation(args)
        from autopwn_suite.utils import ScanMode

        # Mock return values to allow the chain to complete
        mock_port_scan.return_value = MagicMock()
        mock_analyse.return_value = [["192.168.1.1", 80, "http", "Apache", "2.4"]]
        mock_search_vulns.return_value = ["vulns_array"]

        StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_discover.assert_called_once()
        mock_port_scan.assert_called_once()
        mock_search_vulns.assert_called_once()
        mock_get_exploits.assert_called_once()
        mock_webvuln.assert_called_once()

    @patch("autopwn_suite.cli.webvuln")
    @patch("autopwn_suite.cli.GetExploitsFromArray")
    @patch("autopwn_suite.cli.SearchSploits", return_value=[])
    @patch("autopwn_suite.cli.AnalyseScanResults", return_value=[["192.168.1.1", 443, "https", "nginx", "1"]])
    @patch("autopwn_suite.cli.PortScan")
    @patch("autopwn_suite.cli.WebScan", return_value=True)
    @patch("autopwn_suite.cli.UserConfirmation", return_value=(True, False, False))
    @patch("autopwn_suite.cli.GetHostsToScan", return_value=["192.168.1.1"])
    @patch("autopwn_suite.cli.DiscoverHosts")
    def test_insecure_tls_flag_reaches_web_checks_only_when_requested(
            self, mock_discover, mock_get_hosts, mock_user_confirm, mock_web_scan, mock_port_scan, mock_analyse,
            mock_search_vulns, mock_get_exploits, mock_webvuln, mock_check_nmap):
        from autopwn_suite.cli import InitAutomation
        from autopwn_suite.utils import ScanMode
        for insecure, controls in ((True, {"verify_tls": False}), (False, None)):
            args = MagicMock(skip_discovery=False, yes_please=False, insecure_tls=insecure)
            InitAutomation(args)
            mock_webvuln.reset_mock()
            StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())
            assert mock_webvuln.call_args.kwargs.get("controls") == controls

    @patch("autopwn_suite.cli.webvuln")
    @patch("autopwn_suite.cli.GetExploitsFromArray")
    @patch("autopwn_suite.cli.SearchSploits")
    @patch("autopwn_suite.cli.AnalyseScanResults")
    @patch("autopwn_suite.cli.PortScan")
    @patch("autopwn_suite.cli.WebScan", return_value=False)
    @patch("autopwn_suite.cli.UserConfirmation", return_value=(True, False, False)) # User says NO to vuln scan
    @patch("autopwn_suite.cli.GetHostsToScan", return_value=["192.168.1.1"])
    @patch("autopwn_suite.cli.DiscoverHosts")
    def test_partial_scan_flow(self, mock_discover, mock_get_hosts, mock_user_confirm, mock_web_scan, mock_port_scan, mock_analyse, mock_search_vulns, mock_get_exploits, mock_webvuln, mock_check_nmap):
        """Verify vuln scan and exploit download are skipped if user says no."""
        args = MagicMock(skip_discovery=False, yes_please=False)
        from autopwn_suite.cli import InitAutomation
        from autopwn_suite.utils import ScanMode
        InitAutomation(args)
        StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_port_scan.assert_called_once()
        mock_search_vulns.assert_not_called()
        mock_get_exploits.assert_not_called()

    @patch("builtins.input")
    @patch("autopwn_suite.cli.DiscoverHosts")
    def test_skip_discovery(self, mock_discover, mock_input, mock_check_nmap):
        """Verify DiscoverHosts is not called when skip_discovery is True."""
        args = MagicMock(skip_discovery=True, yes_please=False)
        from autopwn_suite.cli import InitAutomation
        from autopwn_suite.utils import ScanMode
        InitAutomation(args)
        # Mock UserConfirmation and WebScan to prevent the scan from proceeding into slow network calls
        with patch("autopwn_suite.cli.UserConfirmation", return_value=(False, False, False)), \
             patch("autopwn_suite.cli.WebScan", return_value=False):
            StartScanning(args, "target", "scantype", ScanMode.Normal, "apiKey", MagicMock(), MagicMock(), MagicMock())

        mock_discover.assert_not_called()
