"""
Unit tests for the searchvuln module.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.searchvuln import (
    GenerateKeyword,
    SearchKeyword,
    GenerateKeywords,
    SearchSploits,
    VulnerableSoftware,
)


@pytest.mark.unit
class TestGenerateKeyword:
    """Tests for the GenerateKeyword function."""

    @pytest.mark.parametrize(
        "product, version, expected",
        [
            ("Apache httpd", "2.4.41", "Apache httpd 2.4.41"),
            ("OpenSSH", "8.2p1", "OpenSSH 8.2p1"),
            ("vsftpd", "3.0.3", "vsftpd 3.0.3"),
            ("Product", "Unknown", "Product"),
            ("Unknown", "1.0", ""),
        ],
    )
    def test_generate_keyword_valid(self, product, version, expected):
        """Verify keyword generation for valid inputs."""
        assert GenerateKeyword(product, version) == expected

    def test_generate_keyword_ignored_product(self):
        """Verify that ignored products (like 'ssh') return an empty string."""
        assert GenerateKeyword("ssh", "1.0") == ""
        assert GenerateKeyword("http", "1.1") == ""


@pytest.mark.unit
class TestSearchSploitsFunctions:
    """Tests for the main vulnerability searching logic."""

    def test_generate_keywords_from_host_array(self):
        """Verify that a list of unique keywords is generated from a host array."""
        host_array = [
            ["192.168.1.1", 80, "http", "Apache httpd", "2.4.41"],
            ["192.168.1.1", 22, "ssh", "OpenSSH", "8.2p1"],
            ["192.168.1.1", 443, "https", "Apache httpd", "2.4.41"],  # Duplicate
            ["192.168.1.1", 21, "ftp", "vsftpd", "3.0.3"],
            ["192.168.1.1", 25, "smtp", "Unknown", "1.0"],  # Should be ignored
        ]
        expected_keywords = ["Apache httpd 2.4.41", "OpenSSH 8.2p1", "vsftpd 3.0.3"]

        keywords = GenerateKeywords(host_array)

        assert sorted(keywords) == sorted(expected_keywords)

    @patch("modules.searchvuln.CheckConnection", return_value=False)
    def test_searchsploits_no_connection(self, mock_check_connection):
        """Verify SearchSploits exits if there is no internet connection."""
        # Provide a non-empty HostArray to prevent an IndexError before the check.
        host_array = [["192.168.1.1"]]
        result = SearchSploits(host_array, MagicMock(), MagicMock(), MagicMock())
        assert result == []
        mock_check_connection.assert_called_once()

    @patch("modules.searchvuln.CheckConnection", return_value=True)
    @patch("modules.searchvuln.GenerateKeywords", return_value=[])
    def test_searchsploits_no_keywords(self, mock_gen_keywords, mock_check_connection):
        """Verify SearchSploits logs a warning if no keywords are generated."""
        mock_log = MagicMock()
        host_array = [["192.168.1.1", 80, "http", "nginx", "1.18.0"]]

        result = SearchSploits(host_array, mock_log, MagicMock(), MagicMock())

        assert result == []
        mock_log.logger.assert_called_with("warning", "Insufficient information for 192.168.1.1")

    @patch("modules.searchvuln.CheckConnection", return_value=True)
    @patch("modules.searchvuln.SearchKeyword")
    def test_searchsploits_success_path(self, mock_search_keyword, mock_check_connection):
        """Verify the success path of searching for and printing vulnerabilities."""
        mock_console = MagicMock()
        mock_console2 = MagicMock()
        mock_log = MagicMock()
        host_array = [["192.168.1.1", 21, "ftp", "vsftpd", "2.3.4"]]

        # Mock the return from the NIST search
        mock_vuln = MagicMock()
        mock_vuln.CVEID = "CVE-2011-2523"
        mock_vuln.description = "vsftpd 2.3.4 contains a backdoor."
        mock_vuln.severity = "CRITICAL"
        mock_vuln.severity_score = 10.0
        mock_search_keyword.return_value = [mock_vuln]

        result = SearchSploits(host_array, mock_log, mock_console, mock_console2)

        # Verify the banner and results were printed
        mock_console.print.assert_called()
        # Verify a VulnerableSoftware object was created and returned
        assert len(result) == 1
        assert isinstance(result[0], VulnerableSoftware)
        assert result[0].title == "vsftpd 2.3.4"
        assert "CVE-2011-2523" in result[0].CVEs


@pytest.mark.unit
class TestSearchKeyword:
    """Tests for the SearchKeyword function."""

    @patch("modules.searchvuln.searchCVE")
    def test_search_keyword_success(self, mock_search_cve):
        """Verify it returns the result from searchCVE on success."""
        mock_log = MagicMock()
        mock_vulnerability = MagicMock()
        mock_search_cve.return_value = [mock_vulnerability]

        result = SearchKeyword("test keyword", mock_log)

        assert result == [mock_vulnerability]
        mock_search_cve.assert_called_once_with("test keyword", mock_log, None)

    @patch("modules.searchvuln.searchCVE", side_effect=KeyboardInterrupt)
    def test_search_keyword_keyboard_interrupt(self, mock_search_cve):
        """Verify it handles KeyboardInterrupt gracefully."""
        mock_log = MagicMock()
        keyword = "test keyword"

        result = SearchKeyword(keyword, mock_log)

        assert result == []
        mock_log.logger.assert_called_once_with("warning", f"Skipped vulnerability detection for {keyword}")

    @patch("modules.searchvuln.searchCVE")
    def test_search_keyword_generic_exception(self, mock_search_cve):
        """Verify it handles generic exceptions gracefully."""
        mock_log = MagicMock()
        test_exception = Exception("Generic error")
        mock_search_cve.side_effect = test_exception

        result = SearchKeyword("test keyword", mock_log)

        assert result == []
        mock_log.logger.assert_called_once_with("error", test_exception)