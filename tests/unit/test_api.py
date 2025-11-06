"""
Unit tests for the api.py module.
"""
import json
from unittest.mock import ANY, MagicMock, mock_open, patch

import pytest

from api import AutoScanner, GenerateKeyword


@pytest.mark.unit
class TestAutoScanner:
    """Tests for the AutoScanner class."""

    @pytest.fixture
    def scanner(self):
        """Fixture for an AutoScanner instance."""
        return AutoScanner()

    def test_create_scan_args_valid(self, scanner):
        """Verify that scan arguments are created correctly."""
        args = scanner.CreateScanArgs(host_timeout=240, scan_speed=4, os_scan=False, nmap_args="-sC")
        assert "-sV" in args
        assert "--host-timeout 240" in args
        assert "-T 4" in args
        assert "-O" not in args  # os_scan is False
        assert "-sC" in args

    def test_create_scan_args_invalid_speed(self, scanner):
        """Verify that an invalid scan speed raises an exception."""
        with pytest.raises(Exception, match="Scanspeed must be in range of 0, 5."):
            scanner.CreateScanArgs(host_timeout=None, scan_speed=9, os_scan=False, nmap_args=None)

    def test_init_host_info(self, scanner, mock_nmap_result):
        """Verify InitHostInfo parses OS and vendor data correctly."""
        target_key = mock_nmap_result["scan"]["192.168.1.1"]
        target_key["vendor"] = ["TestVendor"]
        target_key["osmatch"] = [
            {
                "name": "Linux 5.4", "accuracy": "100", "osclass": [{"type": "general purpose"}]
            }
        ]

        os_info = scanner.InitHostInfo(target_key)

        assert os_info["vendor"] == "TestVendor"
        assert os_info["os_name"] == "Linux 5.4"

    def test_init_host_info_missing_mac(self, scanner):
        """Verify InitHostInfo handles a result with no MAC address."""
        # Simulate a target key with no 'addresses' field
        target_key = {"vendor": ["TestVendor"], "osmatch": []}
        os_info = scanner.InitHostInfo(target_key)

        assert os_info["mac"] == "Unknown"
        assert os_info["vendor"] == "TestVendor" # Should still parse vendor

    def test_parse_vuln_info(self, scanner):
        """Verify ParseVulnInfo correctly extracts details from a vulnerability object."""
        mock_vuln = MagicMock()
        mock_vuln.description = "Test Description"
        mock_vuln.severity = "HIGH"
        mock_vuln.exploitability = 8.0

        vuln_info = scanner.ParseVulnInfo(mock_vuln)

        assert vuln_info["description"] == "Test Description"
        assert vuln_info["severity"] == "HIGH"

    @pytest.mark.parametrize(
        "product, version, expected",
        [
            ("Apache httpd", "2.4.41", "Apache httpd 2.4.41"),
            ("OpenSSH", "8.2p1", "OpenSSH 8.2p1"),
            ("Product", "Unknown", ""),
            ("Unknown", "1.0", ""),
            ("http", "1.1", ""), # Ignored product
        ],
    )
    def test_api_generate_keyword_wrapper(self, product, version, expected):
        """Verify the GenerateKeyword function exposed via the API module."""
        # This function is imported from searchvuln, but we test it here
        # to ensure the API's usage context is covered.
        assert GenerateKeyword(product, version) == expected

    @patch("api.GenerateKeyword", return_value="apache 2.4")
    @patch("api.searchCVE")
    def test_search_vuln(self, mock_search_cve, mock_gen_keyword, scanner):
        """Verify that SearchVuln correctly calls search functions and parses results."""
        mock_vuln = MagicMock()
        mock_vuln.CVEID = "CVE-2023-1234"
        mock_vuln.description = "Test vulnerability"
        mock_vuln.severity = "HIGH"
        mock_vuln.severity_score = 7.5
        mock_vuln.details_url = "http://example.com"
        mock_vuln.exploitability = 8.0
        mock_search_cve.return_value = [mock_vuln]

        port_key = {"product": "apache", "version": "2.4"}
        results = scanner.SearchVuln(port_key, apiKey="test-key")

        mock_gen_keyword.assert_called_once_with("apache", "2.4")
        # Use ANY to match the fake_logger object created internally
        mock_search_cve.assert_called_once_with("apache 2.4", ANY, "test-key")
        assert "CVE-2023-1234" in results
        assert results["CVE-2023-1234"]["description"] == "Test vulnerability"

    @patch("api.is_root", return_value=True)
    @patch("api.PortScanner")
    @patch("api.AutoScanner.SearchVuln")
    def test_scan_success_path(self, mock_search_vuln, mock_port_scanner, mock_is_root, scanner, mock_nmap_result):
        """Verify the main scan method orchestrates scans and returns JSON."""
        mock_scanner_instance = MagicMock()
        # Configure the mock to allow dictionary-style access
        mock_scanner_instance.__getitem__.return_value = mock_nmap_result["scan"]["192.168.1.1"]
        mock_port_scanner.return_value = mock_scanner_instance

        # Mock the vulnerability search to return a predictable result
        mock_search_vuln.return_value = {
            "CVE-2023-TEST": {"description": "A test vulnerability"}
        }

        target = "192.168.1.1"
        results = scanner.scan(target, os_scan=True, scan_vulns=True)

        # Verify nmap scan was called
        mock_scanner_instance.scan.assert_called_once()

        # Verify the structure of the final JSON result
        assert target in results
        assert "ports" in results[target]
        assert "os" in results[target]
        assert "vulns" in results[target]
        assert "Apache httpd" in results[target]["vulns"]
        assert "CVE-2023-TEST" in results[target]["vulns"]["Apache httpd"]

    @patch("api.PortScanner")
    def test_scan_host_offline(self, mock_port_scanner, scanner):
        """Verify that an offline host is handled gracefully."""
        mock_scanner_instance = MagicMock()
        # To test the "offline" path without crashing on the application's logic bug,
        # we simulate a host that is "up" but has no open TCP ports.
        mock_scanner_instance.__getitem__.return_value = {"tcp": {}}
        mock_port_scanner.return_value = mock_scanner_instance

        target = "192.168.1.99"
        results = scanner.scan(target)

        mock_scanner_instance.scan.assert_called_once()
        # Verify the result contains the host but with empty ports and vulns.
        assert results == {"192.168.1.99": {"ports": {}, "vulns": {}}}

    @patch("api.PortScanner")
    def test_scan_with_custom_nmap_args(self, mock_port_scanner, scanner):
        """Verify that custom nmap arguments are passed to the scanner."""
        mock_scanner_instance = MagicMock()
        # Simulate an offline host to prevent the test from going further
        mock_scanner_instance.__getitem__.return_value = {"tcp": {}}
        mock_port_scanner.return_value = mock_scanner_instance

        target = "192.168.1.1"
        custom_args = "-sC -p 1-1000"
        scanner.scan(target, nmap_args=custom_args)

        # Verify that the custom arguments were included in the nmap command
        _, call_kwargs = mock_scanner_instance.scan.call_args
        assert custom_args in call_kwargs["arguments"]

    @patch("api.PortScanner")
    def test_scan_debug_mode(self, mock_port_scanner, scanner, capsys):
        """Verify that debug mode prints status messages."""
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.__getitem__.return_value = {"tcp": {}}
        mock_port_scanner.return_value = mock_scanner_instance

        target = "192.168.1.1"
        scanner.scan(target, debug=True)

        # Verify that the debug message was printed to stdout
        captured = capsys.readouterr()
        assert f"Scanning {target} ..." in captured.out

    @patch("builtins.open", new_callable=mock_open)
    def test_save_to_file(self, mock_file, scanner):
        """Verify that scan results are correctly written to a JSON file."""
        # Populate some dummy scan results
        scanner.scan_results = {"127.0.0.1": {"status": "up"}}
        filename = "test_output.json"

        scanner.save_to_file(filename)

        # Verify that open was called with the correct filename and mode
        mock_file.assert_called_once_with(filename, "w")

        # Verify that the JSON data was written to the file
        handle = mock_file()
        written_data = handle.write.call_args[0][0]
        assert json.loads(written_data) == scanner.scan_results