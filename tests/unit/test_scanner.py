"""
Unit tests for the scanner module.
"""
from unittest.mock import MagicMock, patch, call

import pytest

from modules.scanner import (
    AnalyseScanResults,
    DiscoverHosts,
    NoiseScan,
    InitPortInfo,
    InitHostInfo,
    PortScan,
    TargetInfo,
    TestArp,
    TestPing,
)
from modules.utils import ScanMode, ScanType


@pytest.fixture
def mock_port_scanner():
    """Fixture for a mocked nmap.PortScanner."""
    with patch("modules.scanner.PortScanner") as mock_scanner_class:
        mock_instance = MagicMock()
        mock_scanner_class.return_value = mock_instance
        yield mock_instance


@pytest.mark.unit
class TestDiscoveryFunctions:
    """Tests for host discovery functions like TestPing and TestArp."""

    def test_test_ping_normal_mode(self, mock_port_scanner):
        """Verify TestPing calls nmap with correct arguments in normal mode."""
        target = "192.168.1.1"
        mock_port_scanner.all_hosts.return_value = [target]

        hosts = TestPing(target)

        mock_port_scanner.scan.assert_called_once_with(hosts=target, arguments="-sn")
        assert hosts == [target]

    @patch("modules.scanner.is_root", return_value=True)
    def test_test_arp_evade_mode(self, mock_is_root, mock_port_scanner):
        """Verify TestArp calls nmap with correct arguments in evade mode."""
        target = "192.168.1.0/24"
        TestArp(target, mode=ScanMode.Evade)

        mock_port_scanner.scan.assert_called_once_with(
            hosts=target, arguments="-sn -PR -T 2 -f -g 53 --data-length 10"
        )

    @patch("modules.scanner.TestArp")
    @patch("modules.scanner.TestPing")
    def test_discover_hosts_uses_arp(self, mock_test_ping, mock_test_arp):
        """Verify DiscoverHosts calls TestArp when specified."""
        target = "192.168.1.0/24"
        mock_console = MagicMock()
        DiscoverHosts(target, mock_console, scantype=ScanType.ARP)

        mock_test_arp.assert_called_once()
        mock_test_ping.assert_not_called()


@pytest.mark.unit
class TestPortScan:
    """Tests for the PortScan function."""

    @patch("modules.scanner.is_root", return_value=True)
    def test_port_scan_as_root(self, mock_is_root, mock_port_scanner):
        """Verify PortScan uses sudo arguments when run as root."""
        target = "127.0.0.1"
        mock_log = MagicMock()

        PortScan(target, mock_log, scanspeed=4, customflags="-A")

        # Note: The arguments are joined with spaces, so we check for substrings.
        kwargs = mock_port_scanner.scan.call_args.kwargs
        assert "-sS" in kwargs["arguments"]
        assert "-O" in kwargs["arguments"]
        assert "-T 4" in kwargs["arguments"]
        assert "-A" in kwargs["arguments"]

    @patch("modules.scanner.is_root", return_value=False)
    def test_port_scan_as_non_root(self, mock_is_root, mock_port_scanner):
        """Verify PortScan does not use sudo arguments when not root."""
        target = "127.0.0.1"
        mock_log = MagicMock()

        PortScan(target, mock_log)

        kwargs = mock_port_scanner.scan.call_args.kwargs
        assert "-sS" not in kwargs["arguments"]
        assert "-O" not in kwargs["arguments"]


@pytest.mark.unit
class TestResultParsing:
    """Tests for functions that parse nmap results."""

    def test_init_host_info_full_data(self, mock_nmap_result):
        """Verify InitHostInfo parses a complete nmap result."""
        target_key = mock_nmap_result["scan"]["192.168.1.1"]
        # Add some OS data to the mock
        target_key["vendor"] = ["TestVendor"]
        target_key["osmatch"] = [
            {
                "name": "Linux 5.4",
                "accuracy": "100",
                "osclass": [{"type": "general purpose"}],
            }
        ]

        info = InitHostInfo(target_key)

        assert isinstance(info, TargetInfo)
        assert info.vendor == "TestVendor"
        assert info.os == "Linux 5.4"

    def test_init_host_info_missing_data(self):
        """Verify InitHostInfo handles missing keys gracefully."""
        info = InitHostInfo({})  # Empty dictionary
        assert info.mac == "Unknown"
        assert info.vendor == "Unknown"
        assert info.os == "Unknown"

    def test_init_port_info_full_data(self):
        """Verify InitPortInfo parses a complete port data dictionary."""
        port_data = {
            "state": "open",
            "name": "http",
            "product": "Apache httpd",
            "version": "2.4.41",
        }
        state, service, product, version = InitPortInfo(port_data)
        assert state == "open"
        assert service == "http"
        assert product == "Apache httpd"
        assert version == "2.4.41"

    def test_init_port_info_partial_data(self):
        """Verify InitPortInfo handles empty strings and falls back to 'Unknown'."""
        port_data = {"state": "open", "name": "http", "product": "", "version": ""}
        state, service, product, version = InitPortInfo(port_data)
        assert state == "open"
        assert service == "http"
        assert product == "Unknown"
        assert version == "Unknown"

    def test_analyse_scan_results_host_offline(self, mock_rich_console):
        """Verify it handles an offline host (KeyError) gracefully."""
        mock_log = MagicMock()
        mock_scanner_obj = MagicMock()
        mock_scanner_obj.__getitem__.side_effect = KeyError

        host_array = AnalyseScanResults(mock_scanner_obj, mock_log, mock_rich_console, "192.168.1.99")

        assert host_array == []
        mock_log.logger.assert_called_with("warning", "Target 192.168.1.99 seems to be offline.")

    def test_analyse_scan_results_no_open_ports(self, mock_nmap_result, mock_rich_console):
        """Verify it handles a host with no open TCP ports."""
        mock_log = MagicMock()
        target_ip = "192.168.1.1"

        mock_host_result = MagicMock()
        mock_host_result.all_tcp.return_value = []  # No open ports
        mock_scanner_obj = MagicMock()
        mock_scanner_obj.__getitem__.return_value = mock_host_result

        host_array = AnalyseScanResults(mock_scanner_obj, mock_log, mock_rich_console, target_ip)

        assert host_array == []
        mock_log.logger.assert_called_with("warning", f"Target {target_ip} seems to have no open ports.")
        # Ensure no table was printed
        mock_rich_console.print.assert_not_called()

    @patch("modules.scanner.is_root", return_value=True)
    def test_analyse_scan_results_localhost_detection(self, mock_is_root, mock_nmap_result, mock_rich_console):
        """Verify it logs a message when scanning the local host."""
        mock_log = MagicMock()
        target_ip = "127.0.0.1"
        host_data = {"status": {"reason": "localhost-response"}, "tcp": {}}

        # Create a mock for the host-specific result object
        mock_host_result = MagicMock()
        mock_host_result.all_tcp.return_value = []  # Simulate no open ports
        mock_host_result.__getitem__.side_effect = host_data.__getitem__

        mock_scanner_obj = MagicMock()
        mock_scanner_obj.__getitem__.return_value = mock_host_result

        AnalyseScanResults(mock_scanner_obj, mock_log, mock_rich_console, target_ip)

        mock_log.logger.assert_any_call("info", f"Target {target_ip} seems to be us.")

    @patch("modules.scanner.Table")
    def test_analyse_scan_results_table_content(self, mock_table_class, mock_nmap_result, mock_rich_console):
        """Verify the content of the results table is correct."""
        mock_log = MagicMock()
        target_ip = "192.168.1.1"
        mock_table_instance = MagicMock()
        mock_table_class.return_value = mock_table_instance

        # Create a mock for the result of nm[target]
        mock_host_result = MagicMock()
        mock_host_result.__getitem__.side_effect = mock_nmap_result["scan"][target_ip].__getitem__
        mock_host_result.all_tcp.return_value = list(mock_nmap_result["scan"][target_ip]["tcp"].keys())

        mock_scanner_obj = MagicMock()
        mock_scanner_obj.__getitem__.return_value = mock_host_result

        AnalyseScanResults(mock_scanner_obj, mock_log, mock_rich_console, target_ip)

        # Verify columns were added
        expected_calls = [call("Port", style="cyan"), call("State", style="white"), call("Service", style="blue"), call("Product", style="red"), call("Version", style="purple")]
        mock_table_instance.add_column.assert_has_calls(expected_calls)

        # Verify the row was added with the correct data
        mock_table_instance.add_row.assert_called_once_with("80", "open", "http", "Apache httpd", "2.4.41")

        # Verify the table was printed
        mock_rich_console.print.assert_called_with(mock_table_instance, justify="center")

    def test_analyse_scan_results_no_target_provided(self, mock_nmap_result, mock_rich_console):
        """Verify it correctly determines the target if none is provided."""
        mock_log = MagicMock()
        target_ip = "192.168.1.1"

        # Create a mock for the result of nm[target]
        mock_host_result = MagicMock()
        mock_host_result.__getitem__.side_effect = mock_nmap_result["scan"][target_ip].__getitem__
        mock_host_result.all_tcp.return_value = list(mock_nmap_result["scan"][target_ip]["tcp"].keys())

        # Create a mock that behaves like a PortScanner object
        mock_scanner_obj = MagicMock()
        mock_scanner_obj.all_hosts.return_value = [target_ip] # This is the key part for this test
        mock_scanner_obj.__getitem__.return_value = mock_host_result

        # Call with target=None
        host_array = AnalyseScanResults(mock_scanner_obj, mock_log, mock_rich_console, target=None)

        assert len(host_array) == 1
        assert host_array[0][0] == target_ip # Verify it used the correct target

    def test_analyse_scan_results(self, mock_nmap_result, mock_rich_console):
        """Verify AnalyseScanResults prints a table and returns open ports."""
        mock_log = MagicMock()
        target_ip = "192.168.1.1"

        # Create a mock for the result of nm[target]
        mock_host_result = MagicMock()
        # Configure it to behave like a dictionary
        mock_host_result.__getitem__.side_effect = mock_nmap_result["scan"][target_ip].__getitem__
        # Configure the all_tcp() method
        mock_host_result.all_tcp.return_value = list(mock_nmap_result["scan"][target_ip]["tcp"].keys())

        # Create a mock that behaves like a PortScanner object
        mock_scanner_obj = MagicMock()
        mock_scanner_obj.__getitem__.return_value = mock_host_result

        host_array = AnalyseScanResults(
            mock_scanner_obj, mock_log, mock_rich_console, target_ip
        )

        # Verify a table was printed
        mock_rich_console.print.assert_called()
        # Verify the open port was returned
        assert len(host_array) == 1
        assert host_array[0] == [target_ip, 80, "http", "Apache httpd", "2.4.41"]


@pytest.mark.unit
class TestNoiseScan:
    """Tests for the NoiseScan function."""

    @patch("modules.scanner.sleep")
    @patch("modules.scanner.Process")
    @patch("modules.scanner.TestPing", return_value=["192.168.1.1", "192.168.1.2"])
    def test_noise_scan_creates_processes(self, mock_test_ping, mock_process, mock_sleep):
        """Verify that NoiseScan creates a process for each discovered host."""
        mock_log = MagicMock()
        mock_console = MagicMock()

        # By providing a noisetimeout, we avoid the `while True` loop.
        # We can then mock sleep to raise an exception after the for loop has completed.
        mock_sleep.side_effect = [None, SystemExit] # Allow first sleep, exit on second.

        with pytest.raises(SystemExit):
            # Provide a timeout to bypass the problematic `while True` loop
            NoiseScan("192.168.1.0/24", mock_log, mock_console, scantype=ScanType.Ping, noisetimeout=1)

        # Should be called for each of the two hosts
        assert mock_process.call_count == 2
        mock_process.return_value.start.assert_called()

    @patch("modules.scanner.sleep")
    @patch("modules.scanner.Process")
    @patch("modules.scanner.TestPing", return_value=["192.168.1.1"])
    def test_noise_scan_with_timeout(self, mock_test_ping, mock_process, mock_sleep):
        """Verify that sleep is called with the correct timeout."""
        mock_log = MagicMock()
        mock_console = MagicMock()
        # Mock sleep to raise an exception to exit the function after it's called.
        mock_sleep.side_effect = SystemExit

        with pytest.raises(SystemExit):
            NoiseScan("192.168.1.0/24", mock_log, mock_console, scantype=ScanType.Ping, noisetimeout=10)

        mock_sleep.assert_called_once_with(10)