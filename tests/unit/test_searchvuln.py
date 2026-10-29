# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the searchvuln module.
"""
import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from autopwn_suite.cpe_match import affects, find_affected
from autopwn_suite.nist_search import Vulnerability, VulnerabilityLookup, cache, searchCVE
from autopwn_suite.searchvuln import (
    FindVulnerabilities,
    GenerateKeyword,
    GenerateKeywords,
    SearchKeyword,
    SearchSploits,
    VulnerableSoftware,
)
from tests.unit.test_vulnerability_db import feed_server as feed_server  # Shared pytest fixture.
from tests.unit.test_vulnerability_db import record


@pytest.mark.unit
class TestGenerateKeyword:
    """Tests for the GenerateKeyword function."""

    @pytest.mark.parametrize(
        "product, version, expected",
        [
            ("Apache httpd", "2.4.41", "Apache HTTP Server 2.4.41"),
            ("OpenSSH", "8.2p1", "OpenSSH 8.2p1"),
            ("vsftpd", "3.0.3", "vsftpd 3.0.3"),
            ("Product", "Unknown", ""),
            ("Unknown", "1.0", ""),
            # Nmap's role words and names become the names NVD descriptions use.
            ("Samba smbd", "3.0.20-Debian", "Samba 3.0.20"),
            ("Exim smtpd", "4.92", "Exim 4.92"),
            ("PostgreSQL DB", "9.6.6", "PostgreSQL 9.6.6"),
            ("Redis key-value store", "5.0.7", "Redis 5.0.7"),
            ("Squid http proxy", "3.5.27", "Squid 3.5.27"),
            ("Elasticsearch REST API", "7.6.2", "Elasticsearch 7.6.2"),
            ("Microsoft IIS httpd", "7.5", "Microsoft IIS 7.5"),
            ("MiniServ", "1.890", "Webmin 1.890"),
            ("Dropbear sshd", "2019.78", "Dropbear SSH 2019.78"),
            ("ISC BIND", "9.11.5-P4-5.1+deb10u5-Debian", "BIND 9.11.5P4"),
            ("MySQL", "5.5.5-10.3.23-MariaDB-0+deb10u1", "MariaDB 10.3.23"),
            # Only the upstream release of a version string is searched.
            ("OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5", "OpenSSH 8.2p1"),
            ("Werkzeug httpd", "2.0.2 (Python 3.8.10)", "Werkzeug 2.0.2"),
            ("Jetty", "9.4.18.v20190429", "Jetty 9.4.18"),
            ("Sendmail", "8.14.4/8.14.4", "Sendmail 8.14.4"),
            ("dnsmasq", "2.93+30", "dnsmasq 2.93"),
            ("Microsoft SQL Server 2008 R2", "10.50.1600.00; RTM", "Microsoft SQL Server 2008 R2 10.50.1600.00"),
            # A range, a wildcard or a protocol version names no release to search.
            ("Samba smbd", "3.X - 4.X", ""),
            ("Samba smbd", "4", ""),  # only the major version
            ("PostgreSQL DB", "8.3.0 - 8.3.7", ""),
            ("VNC", "protocol 3.3", ""),
            ("distccd", "v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))", ""),
            ("Apache Tomcat/Coyote JSP engine", "1.1", ""),
            ("UnrealIRCd", "", "UnrealIRCd"),
        ],
    )
    def test_generate_keyword_valid(self, product, version, expected):
        """Verify keyword generation for valid inputs."""
        assert GenerateKeyword(product, version) == expected

    def test_generate_keyword_ignored_product(self):
        """Verify that ignored products (like 'http') return an empty string."""
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
        expected_keywords = ["Apache HTTP Server 2.4.41", "OpenSSH 8.2p1", "vsftpd 3.0.3"]

        keywords = GenerateKeywords(host_array)

        assert sorted(keywords) == sorted(expected_keywords)

    @patch("autopwn_suite.searchvuln.CheckConnection", return_value=False)
    def test_searchsploits_no_connection(self, mock_check_connection):
        """Verify SearchSploits exits if there is no internet connection."""
        # Provide a non-empty HostArray to prevent an IndexError before the check.
        host_array = [["192.168.1.1"]]
        result = SearchSploits(host_array, MagicMock(), MagicMock(), MagicMock())
        assert result == []
        mock_check_connection.assert_called_once()

    @patch("autopwn_suite.searchvuln.CheckConnection", return_value=True)
    @patch("autopwn_suite.searchvuln.GenerateKeywords", return_value=[])
    def test_searchsploits_no_keywords(self, mock_gen_keywords, mock_check_connection):
        """Verify SearchSploits logs a warning if no keywords are generated."""
        mock_log = MagicMock()
        host_array = [["192.168.1.1", 80, "http", "nginx", "1.18.0"]]

        result = SearchSploits(host_array, mock_log, MagicMock(), MagicMock())

        assert result == []
        mock_log.logger.assert_called_with("warning", "Insufficient information for 192.168.1.1")

    @patch("autopwn_suite.searchvuln.CheckConnection", return_value=True)
    @patch("autopwn_suite.searchvuln.SearchKeyword")
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

    @patch("autopwn_suite.searchvuln.searchCVE")
    def test_search_keyword_success(self, mock_search_cve):
        """Verify it returns the result from searchCVE on success."""
        mock_log = MagicMock()
        mock_vulnerability = MagicMock()
        mock_search_cve.return_value = [mock_vulnerability]

        result = SearchKeyword("test keyword", mock_log)

        assert result == [mock_vulnerability]
        mock_search_cve.assert_called_once_with("test keyword", mock_log, None, strict=True)

    @patch("autopwn_suite.searchvuln.searchCVE", side_effect=KeyboardInterrupt)
    def test_search_keyword_keyboard_interrupt(self, mock_search_cve):
        """Verify it handles KeyboardInterrupt gracefully."""
        mock_log = MagicMock()
        keyword = "test keyword"

        result = SearchKeyword(keyword, mock_log)

        assert result == []
        mock_log.logger.assert_called_once_with("warning", f"Skipped vulnerability detection for {keyword}")

    @patch("autopwn_suite.searchvuln.searchCVE")
    def test_search_keyword_generic_exception(self, mock_search_cve):
        """Verify it handles generic exceptions gracefully."""
        mock_log = MagicMock()
        test_exception = Exception("Generic error")
        mock_search_cve.side_effect = test_exception

        result = SearchKeyword("test keyword", mock_log)

        assert result == []
        mock_log.logger.assert_called_once_with("error", test_exception)


@pytest.mark.unit
def test_hostile_banner_and_cve_text_is_printed_literally_instead_of_aborting():
    """Markup-looking text from a banner or an NVD record must not raise MarkupError."""
    console = Console(file=io.StringIO(), width=200, color_system=None)
    status_console = Console(file=io.StringIO(), width=200, color_system=None)
    vuln = Vulnerability("keyword", "CVE-2024-0001[/id]", "Remote flaw [/admin] in the parser", "[/severity]", 9.8,
                         "https://nvd.test/[/details]", "[/exploitability]")
    host_array = [["192.0.2.1", 21, "ftp", "vsftpd[bold]", "2.3.4"]]

    with patch("autopwn_suite.searchvuln.CheckConnection", return_value=True), \
         patch("autopwn_suite.searchvuln.SearchKeyword", return_value=[vuln]), \
         patch("autopwn_suite.searchvuln.get_terminal_width", return_value=100):
        result = SearchSploits(host_array, MagicMock(), console, status_console)

    output = console.file.getvalue()
    for text in ("vsftpd[bold] 2.3.4", "CVE-2024-0001[/id]", "Remote flaw [/admin] in the parser",
                 "[/severity]", "https://nvd.test/[/details]", "[/exploitability]"):
        assert text in output
    assert result[0].title == "vsftpd[bold] 2.3.4"
    assert result[0].CVEs == ["CVE-2024-0001[/id]"]



def _cve(cve_id, description, affected=()):
    return Vulnerability("term", cve_id, description, "HIGH", 7.5, "https://nvd.test/" + cve_id, 3.9, affected=affected)


def _entry(vendor, product, version="*", update="*", start_in=None, start_ex=None, end_in=None, end_ex=None):
    return (vendor, product, version, update, start_in, start_ex, end_in, end_ex)


@pytest.mark.unit
class TestFindVulnerabilities:
    """The product is searched and only CVEs that affect the detected version are kept."""

    def test_keeps_only_cves_whose_applicability_covers_the_version(self):
        results = [
            _cve("CVE-1", "Range flaw in OpenSSH before 9.8", (_entry("openbsd", "openssh", end_ex="9.8p1"),)),
            _cve("CVE-2", "Old flaw in OpenSSH before 7.4", (_entry("openbsd", "openssh", end_ex="7.4"),)),
            # Mentions OpenSSH 8.2p1, but NVD says it affects another product.
            _cve("CVE-3", "Plugin flaw when used with OpenSSH 8.2p1", (_entry("example", "plugin", end_ex="2.0"),)),
            # Not analyzed yet: kept only when the description names the version.
            _cve("CVE-4", "OpenSSH 8.2p1 crashes on a long banner"),
            _cve("CVE-5", "OpenSSH 8.2 crashes on a short banner"),
            # "Every version" says nothing about 8.2p1, so the description must name it.
            _cve("CVE-6", "OpenSSH packages signed in 2008 were modified", (_entry("openbsd", "openssh"),)),
            _cve("CVE-7", "OpenSSH 8.2p1 and others leak a banner", (_entry("openbsd", "openssh"),)),
        ]
        search = MagicMock(return_value=results)

        found = FindVulnerabilities("OpenSSH 8.2p1", search)

        search.assert_called_once_with("OpenSSH")
        assert [vuln.CVEID for vuln in found] == ["CVE-1", "CVE-4", "CVE-7"]

    def test_keyword_without_a_version_is_searched_as_is_and_not_filtered(self):
        results = [_cve("CVE-1", "Backdoor in UnrealIRCd", (_entry("unrealircd", "unrealircd", "3.2.8.1", "-"),))]
        search = MagicMock(return_value=results)

        assert FindVulnerabilities("UnrealIRCd", search) == results
        search.assert_called_once_with("UnrealIRCd")


@pytest.mark.unit
class TestCpeApplicability:
    """NVD CPE match semantics, as affects() reads them."""

    @pytest.mark.parametrize("entry, version, expected", [
        (_entry("openbsd", "openssh", end_ex="8.3"), "8.2p1", True),
        (_entry("openbsd", "openssh", end_ex="8.2"), "8.2p1", False),
        (_entry("openbsd", "openssh", start_in="8.5p1", end_ex="9.8p1"), "8.2p1", False),
        (_entry("openbsd", "openssh", start_ex="8.2p1", end_in="9.0"), "8.2p1", False),
        (_entry("openbsd", "openssh", start_in="8.2p1", end_in="8.2p1"), "8.2p1", True),
        (_entry("openbsd", "openssh"), "8.2p1", None),  # "every version" says nothing about this one
        (_entry("openbsd", "openssh", "8.2", "p1"), "8.2p1", True),
        (_entry("openbsd", "openssh", "8.2", "p2"), "8.2p1", False),
        (_entry("openbsd", "openssh", "8.2p1", "-"), "8.2p1", True),
        (_entry("proftpd", "proftpd", "1.3.3", "*"), "1.3.3c", True),  # any update of 1.3.3
        (_entry("proftpd", "proftpd", "1.3.5", "rc3"), "1.3.5", False),
        (_entry("proftpd", "proftpd", "1.3.5", "-"), "1.3.5", True),
        (_entry("openbsd", "openssh", "-", "-"), "8.2p1", False),
        (_entry("openbsd", "openssh", update="p2", end_in="7.2"), "7.2p2", True),  # up to 7.2p2
        (_entry("openbsd", "openssh", update="p2", end_in="7.2"), "7.3p1", False),
        (_entry("apache", "http_server", end_ex="2.4.10"), "2.4.9", True),  # numeric, not text, order
    ])
    def test_version_ranges_and_updates(self, entry, version, expected):
        assert affects((entry,), "OpenSSH" if entry[1] == "openssh" else entry[1].replace("_", " "), version) is expected

    @pytest.mark.parametrize("vendor, product, name, named", [
        ("apache", "http_server", "Apache HTTP Server", True),
        ("apache", "apache_http_server", "Apache HTTP Server", True),
        ("apache", "tomcat", "Apache HTTP Server", False),
        ("oracle", "http_server", "Apache HTTP Server", False),
        ("microsoft", "internet_information_services", "Microsoft IIS", True),
        ("microsoft", "internet_information_server", "Microsoft IIS", True),
        ("oracle", "mysql_server", "MySQL", True),
        ("isc", "bind", "BIND", True),
        ("eric_allman", "sendmail", "Sendmail", True),
        ("example", "openssh_plugin", "OpenSSH", False),
    ])
    def test_a_cpe_names_the_product_by_its_words(self, vendor, product, name, named):
        assert affects((_entry(vendor, product, end_ex="9.9"),), name, "1.0") is named

    def test_vulnerable_matches_are_read_and_others_ignored(self):
        record = {"cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.3"},
            {"vulnerable": True, "criteria": r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:short"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndIncluding": 9},
        ]}]}]}}

        assert find_affected(record) == (
            ("openbsd", "openssh", "*", "*", None, None, None, "9.3"),
            ("vendor", r"pro\:duct", "1.0", "*", None, None, None, None),
            ("openbsd", "openssh", "*", "*", None, None, None, None),
        )
        assert find_affected({"cve": {"id": "CVE-1"}}) == ()



def _openssh_record(cve_id, end_excluding):
    entry = record(cve_id, f"OpenSSH before {end_excluding} has a flaw")
    entry["cve"]["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
         "versionEndExcluding": end_excluding}]}]}]
    return entry


@pytest.mark.unit
@patch("autopwn_suite.nist_search.get")
def test_online_lookup_searches_the_product_and_keeps_the_cves_for_the_version(mock_get):
    cache.clear()
    mock_get.return_value.json.return_value = {"totalResults": 2, "vulnerabilities": [
        _openssh_record("CVE-2024-6387", "9.8p1"), _openssh_record("CVE-2016-6210", "7.3")]}
    try:
        found = FindVulnerabilities("OpenSSH 8.2p1", lambda term: searchCVE(term, MagicMock(), "key", strict=True))
        assert mock_get.call_args.kwargs["params"]["keywordSearch"] == "OpenSSH"
        assert [cve.CVEID for cve in found] == ["CVE-2024-6387"]
    finally:
        cache.clear()


@pytest.mark.unit
def test_offline_lookup_keeps_the_cves_for_the_version(feed_server, monkeypatch):
    from autopwn_suite.vulnerability_db import update_database
    feeds = feed_server[0]
    feeds[min(feeds)] = [_openssh_record("CVE-2025-0001", "9.8p1"), _openssh_record("CVE-2025-0002", "7.3")]
    update_database()
    monkeypatch.setattr("autopwn_suite.nist_search.get", lambda *a, **k: pytest.fail("Offline lookup contacted NVD"))
    lookup = VulnerabilityLookup("offline")
    try:
        found = FindVulnerabilities("OpenSSH 8.2p1", lambda term: lookup.search(term, MagicMock()))
        assert [cve.CVEID for cve in found] == ["CVE-2025-0001"]
    finally:
        lookup.close()
        cache.clear()
