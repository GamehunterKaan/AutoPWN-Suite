# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the searchvuln module.
"""
import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from autopwn_suite.cpe_match import affects, cut_short, find_affected, reaches
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
            ("MariaDB", "5.5.5-10.11.6", "MariaDB 10.11.6"),  # Nmap 7.99 keeps the 5.5.5- prefix
            ("MariaDB", "11.4.2-MariaDB-ubu2404", "MariaDB 11.4.2"),
            ("MySQL", "5.7.25-TiDB-v8.1.0", ""),  # not MySQL, whatever version it claims
            # Without the role word, these would name an operating system, a vendor, a common word or another
            # product, or search most of NVD.
            ("Android ftpd", "2.1", "Android ftpd 2.1"),
            ("OpenBSD ftpd", "6.4", "OpenBSD ftpd 6.4"),
            ("Microsoft ftpd", "6.0", "Microsoft ftpd 6.0"),
            ("AN httpd", "1.2.3", "AN httpd 1.2.3"),
            ("Hydra httpd", "1.0", "Hydra httpd 1.0"),
            ("Apache Mina sshd", "2.9.2", "Apache SSHD 2.9.2"),
            ("IBM httpd", "6.1", "IBM httpd 6.1"),
            ("Null httpd", "0.5.0", "Null httpd 0.5.0"),  # not "Null", in thousands of "NULL pointer" CVEs
            ("AOL smtpd", "3.0", "AOL smtpd 3.0"),  # not "AOL", which also finds AOLserver
            ("Web", "1.2.3", ""),
            ("TLS", "1.0", ""),
            # A short name can still be the product, and some role words tell a vendor's products apart.
            ("Boa HTTPd", "0.94.14rc21", "Boa 0.94.14rc21"),
            ("Thin httpd", "1.2.2", "Thin 1.2.2"),
            ("Titan ftpd", "8.40", "Titan 8.40"),
            ("Sun Java System httpd", "7.0", "Sun Java System Web Server 7.0"),
            ("Shoutcast/Icecast streaming audio", "2.3.2", "Icecast 2.3.2"),
            # But a short name before a slash may be a vendor or another product ("SAS", "Nut").
            ("SAS/IntrNet", "9.4 build 1520", "SAS/IntrNet 9.4"),
            ("Nut/OS Demo ftpd", "1.0", "Nut/OS Demo ftpd 1.0"),
            # Only the upstream release of a version string is searched.
            ("OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5", "OpenSSH 8.2p1"),
            ("Werkzeug httpd", "2.0.2 (Python 3.8.10)", "Werkzeug 2.0.2"),
            ("Jetty", "9.4.18.v20190429", "Jetty 9.4.18"),
            ("Sendmail", "8.14.4/8.14.4", "Sendmail 8.14.4"),
            ("dnsmasq", "2.93+30", "dnsmasq 2.93"),
            ("Apache Tomcat", "9.0.0-M1", "Apache Tomcat 9.0.0M1"),  # a pre-release stays one
            ("Gene6 ftpd", "3.10.0 beta 2", "Gene6 3.10.0beta2"),
            ("Apache Tomcat", "9.0.0.M1", "Apache Tomcat 9.0.0M1"),
            ("Example", "2.0.0-RC.1", "Example 2.0.0RC1"),
            ("FileZilla ftpd", "0.9.60 beta", "FileZilla 0.9.60"),  # FileZilla Server's label, not a pre-release
            ("VanDyke VShell", "4.6.3 beta", "VanDyke VShell 4.6.3beta"),
            ("MySQL", "5.6.9-rc-log", "MySQL 5.6.9rc"),
            ("MySQL", "6.0.4-alpha-community", "MySQL 6.0.4alpha"),
            ("Example", "2.0.0-rc-2ubuntu1", "Example 2.0.0rc"),
            ("Microsoft SQL Server 2008 R2", "10.50.1600.00; RTM", "Microsoft SQL Server 2008 R2 10.50.1600.00"),
            # A range, a wildcard or a protocol version names no release to search.
            ("Samba smbd", "3.X - 4.X", ""),
            ("Samba smbd", "4", ""),  # only the major version
            ("PostgreSQL DB", "8.3.0 - 8.3.7", ""),
            ("VNC", "protocol 3.3", ""),
            ("distccd", "v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))", ""),
            ("Apache Tomcat/Coyote JSP engine", "1.1", ""),
            # Nor does a bound or a choice, nor a development build.
            ("Tor", "0.3.1.1 or later", ""),
            ("vsftpd", "2.0.0 or later", ""),
            ("ArangoDB", "3.0 or 3.1", ""),
            ("Ventrilo", "2.1.2+", ""),
            ("BusyBox httpd", "1.6.0 -", ""),
            ("Metasploit Remote API", "4.4.0-dev", ""),
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


def _entry(vendor, product, version="*", update="*", start_in=None, start_ex=None, end_in=None, end_ex=None, part="a"):
    return (part, vendor, product, version, update, start_in, start_ex, end_in, end_ex)


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

    def test_a_release_named_as_the_fix_is_not_a_mention(self):
        results = [_cve("CVE-1", "OpenSSH before 8.2p1 leaks memory"),
                   _cve("CVE-2", "A crash, fixed in version 8.2p1"),
                   _cve("CVE-3", "Users should upgrade to 8.2p1"),
                   _cve("CVE-4", "OpenSSH 8.2p1 and earlier crash; upgrade to 8.3p1"),
                   _cve("CVE-5", "Fixed in 8.3p1; OpenSSH 8.2p1 crashes"),
                   _cve("CVE-6", "Fixed in versions 9.0p1, 8.2p1 and 7.9p1"),
                   _cve("CVE-7", "A crash, only partially fixed in 8.2p1"),
                   _cve("CVE-8", "OpenSSH before 8.2p1 build 3 crashes"),
                   _cve("CVE-9", "OpenSSH prior to 8.2p1, inclusive, crashes")]

        found = FindVulnerabilities("OpenSSH 8.2p1", MagicMock(return_value=results))

        assert [vuln.CVEID for vuln in found] == ["CVE-4", "CVE-5", "CVE-7", "CVE-8", "CVE-9"]

    @pytest.mark.parametrize("keyword, description", [
        ("Sambar 6.0", "Sambar Server before 6.0 beta 6 leaks files"),  # 6.0 comes after its beta 6
        ("Coolify 4.0.0", "Coolify prior to 4.0.0-beta.471 leaks passwords"),
        ("MDaemon 9.50", "Alt-N MDaemon before 9.50 has unknown impact"),
        ("Grav 2.0.25", "Sites on the built-in server are not affected. The issue is fixed in 2.0.25"),
    ])
    def test_a_fixed_release_is_not_a_mention_whatever_follows_it(self, keyword, description):
        assert FindVulnerabilities(keyword, lambda term: [_cve("CVE-1", description)]) == []

    def test_a_cve_its_description_says_the_release_fixed_is_left_out(self):
        """NVD sometimes writes "before 4.4" as "up to 4.4", which covers the portable 4.4p1."""
        results = [_cve("CVE-1", "Race in OpenSSH before 4.4", (_entry("openbsd", "openssh", end_in="4.4"),)),
                   _cve("CVE-2", "Race in OpenSSH before 4.5", (_entry("openbsd", "openssh", end_in="4.4"),)),
                   _cve("CVE-3", "Upgrading to 4.4 brought a race", (_entry("openbsd", "openssh", end_in="4.4"),))]
        bind = _cve("CVE-4", "ISC BIND 9.x before 9.9.8-P2 and 9.10.x before 9.10.3-P2 crash",
                    (_entry("isc", "bind", "9.10.3", "*"),))

        assert [vuln.CVEID for vuln in FindVulnerabilities("OpenSSH 4.4p1", lambda term: results)] == ["CVE-2", "CVE-3"]
        assert FindVulnerabilities("BIND 9.10.3P4", lambda term: [bind]) == []
        assert FindVulnerabilities("BIND 9.10.3P1", lambda term: [bind]) == [bind]

    @pytest.mark.parametrize("keyword, description", [
        ("BIND 9.10.3P4", "ISC BIND 9.x before 9.9.8-P2 and 9.10.x before 9.10.3-P2 crash"),
        ("IBM WebSphere Application Server 6.0.2.41", "IBM WebSphere Application Server (WAS) 6.0 before 6.0.2.41 and "
                                                      "6.1 before 6.1.0.31 allow XSS"),
        ("Jenkins 2.32.2", "Jenkins before versions 2.44, 2.32.2 leaks data"),
        ("CUPS 1.1.21rc2", "CUPS before 1.1.21rc1 crashes"),
        ("Asterisk 11.5.1", "Asterisk Open Source 1.8.17.x through 1.8.22.x, 1.8.23.x before 1.8.23.1, and 11.x before "
                            "11.5.1 crash"),
    ])
    def test_the_fix_of_the_product_is_left_out_whatever_its_applicability_says(self, keyword, description):
        with patch("autopwn_suite.searchvuln.affects", return_value=True):
            assert FindVulnerabilities(keyword, lambda term: [_cve("CVE-1", description)]) == []

    @pytest.mark.parametrize("keyword, description", [
        # A release that starts a range, or one in a list of affected releases.
        ("OpenSSL 1.0.2", "OpenSSL 1.0.1 before 1.0.1q and 1.0.2 before 1.0.2e crash"),
        ("PostgreSQL 8.1.0", "PostgreSQL 7.4 before 7.4.29, 8.0 before 8.0.25, 8.1 before 8.1.21 leak"),
        ("HAProxy 2.3.0", "HAProxy 2.1, 2.2 before 2.2.27, 2.3, 2.4 before 2.4.21 leak memory"),
        ("Samba 2.0.10", "Samba 2.2.x before 2.2.8a, 2.0.10 and earlier overflow"),
        ("MariaDB 10.3.34", "MariaDB Server before 10.3.34 thru 10.9.3 crashes"),
        # The fix is a vendor's build of the release.
        ("Lotus Domino 8.5.3", "IBM Lotus Domino 8.5 before 8.5.3 FP5 allows XSS"),
        ("Informix Dynamic Server 11.50", "IBM Informix Dynamic Server 11.50 before 11.50.xC5 overflows"),
        ("Novell GroupWise 8.0", "Novell GroupWise 8.x before 8.0 HP2 overflows"),
        ("Cisco Unified Communications Manager 6.1", "Cisco Unified Communications Manager 6.x before 6.1(1) crashes"),
        ("BIND 9.11.0a1", "ISC BIND 9.11.x before 9.11.0rc3 crashes"),
        ("CUPS 1.7.1b1", "CUPS before 1.7.1 crashes"),
        ("MantisBT 1.3.0beta1", "MantisBT before 1.3.0-beta.2 allows XSS"),
        # The release is another product's, or the sentence says it is not the fix.
        ("OpenSSH 5.1", "OpenSSH before 9.6, PuTTY before 0.80 and Tera Term before 5.1 allow Terrapin"),
        ("MongoDB 4.4.0", "MongoDB Server v4.4 versions prior to 4.4.1 crash. Versions before 4.4 are not affected"),
        ("OpenSSL 1.1.1d", "OpenSSL 1.1.1d to 1.1.1f crash. This did not affect OpenSSL versions prior to 1.1.1d."),
        ("Jenkins 1.498", "Jenkins upgrading from before 1.498 no longer creates a backup"),
        ("OpenSSH 4.4", "OpenSSH 4.3 crashes; upgrade to 4.4"),
        ("WebLogic 8.1", "BEA WebLogic Server before 8.1 Service Pack 4 leaks data"),
        ("Lotus Domino 6.5.4", "Lotus Domino versions before 6.5.4 fix pack 1 (FP1) crash"),
        ("Play Framework 2.8.0", "Play Framework 2.8.0 through 2.8.4 leak data to users migrating from a Play "
                                 "version prior to 2.8.0"),
        ("Atlassian JIRA 4.2", "The Gliffy plugin before 3.7.1 for Atlassian JIRA, and before 4.2 for Atlassian "
                               "Confluence, leaks data"),
        ("MariaDB 10.7.0", "MariaDB Server before 10.7 leaks a lock"),  # 10.7 may be the series
    ])
    def test_a_release_that_is_not_the_fix_of_the_product_keeps_its_cve(self, keyword, description):
        cve = _cve("CVE-1", description)
        with patch("autopwn_suite.searchvuln.affects", return_value=True):
            assert FindVulnerabilities(keyword, lambda term: [cve]) == [cve]

    @pytest.mark.parametrize("version, fixed, reached", [
        ("4.4p1", "4.4", True), ("9.11.5P4", "9.11.5P2", True), ("1.3.3c", "1.3.3c", True), ("2.4.0", "2.4", False),
        ("1.3.3d", "1.3.3c", True), ("1.1.21", "1.1.21rc1", True), ("4.4.0rc8", "4.4.0rc7", True),
        ("2.4.52", "2.4", False), ("9.12.0", "9.11.5P4", False), ("2.0.0rc1", "2.0.0", False), ("1.3.3b", "1.3.3c", False),
        # A pre-release or a vendor's own build of the release is not a later build of it.
        ("2.23b1", "2.23", False), ("9.11.0a1", "9.11.0rc3", False), ("8.0hp1", "8.0", False),
        ("9.9.8S1", "9.9.8P2", False), ("10.0.0cr5", "10.0.0", False),
    ])
    def test_a_version_reaches_its_release_and_later_builds_of_it(self, version, fixed, reached):
        assert reaches(version, fixed) is reached

    def test_a_shortened_version_gets_only_the_cves_of_its_whole_series(self):
        results = [_cve(f"CVE-{patch}", "Apache flaw", (_entry("apache", "http_server", start_in="2.4.0",
                                                                end_ex=f"2.4.{patch}"),)) for patch in range(1, 9)]
        results.append(_cve("CVE-9", "Apache flaw", (_entry("apache", "http_server", start_in="2.4.0", end_ex="2.5.0"),)))

        assert [vuln.CVEID for vuln in FindVulnerabilities("Apache HTTP Server 2.4", lambda term: results)] == ["CVE-9"]

    def test_an_operating_system_cve_is_not_reported_for_its_daemon(self):
        android = _cve("CVE-2010-4804", "The Android browser in Android before 2.3.4 allows file reads",
                       (_entry("google", "android", end_in="2.3.3", part="o"),))

        assert FindVulnerabilities("Android 2.1", MagicMock(return_value=[android])) == []

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
        # Portable 7.9p1 is release 7.9, which "up to 7.9" includes and "before 7.9" does not.
        (_entry("openbsd", "openssh", end_in="7.9"), "7.9p1", True),
        (_entry("openbsd", "openssh", end_ex="7.9"), "7.9p1", False),
        # A pre-release sorts below its release, and a letter release above it.
        (_entry("proftpd", "proftpd", end_in="1.3.5b"), "1.3.5rc3", True),
        (_entry("proftpd", "proftpd", end_ex="1.3.6"), "1.3.6rc2", True),
        (_entry("proftpd", "proftpd", end_in="1.3.6rc1"), "1.3.6", False),
        (_entry("proftpd", "proftpd", end_in="1.3.2rc2"), "1.3.2c", False),
        # NVD starts "9.0.0-M1 to 9.0.30" at 9.0.0, and spells Tomcat's milestones "milestone1".
        (_entry("apache", "tomcat", start_in="9.0.0", end_ex="9.0.31"), "9.0.0M1", True),
        (_entry("apache", "tomcat", start_in="8.0.0", end_in="8.0.36"), "8.0.0RC1", True),
        (_entry("apache", "tomcat", start_in="9.0.0M3", end_ex="9.0.31"), "9.0.0M1", False),
        (_entry("apache", "tomcat", start_ex="9.0.0", end_ex="9.0.31"), "9.0.0M1", False),
        (_entry("apache", "tomcat", "10.0.0", "milestone1"), "10.0.0M1", True),
        (_entry("example", "product", end_ex="2.0rc1"), "2.0beta3", True),
        (_entry("example", "product", "4.0.0", "-"), "4.0.0.Final", True),
        (_entry("openssl", "openssl", end_ex="1.0.1"), "1.0.0m", True),
        # 1.00 is 1.0, and 9.0.0 is 9.0.
        (_entry("freefloat", "ftp_server", "1.0", "-"), "1.00", True),
        (_entry("postgresql", "postgresql", "9.0", "*"), "9.0.0", True),
        # But BIND's 9.6 with any update (9.6-ESV-R9) is not 9.6.0-P1, nor update 1 of 10.6.0 release 10.6.1.
        (_entry("isc", "bind", "9.6", "*"), "9.6.0P1", False),
        # Old records list 9.2.0 as "9.2", which covers its pre-releases.
        (_entry("isc", "bind", "9.2", "*"), "9.2.0rc1", True),
        (_entry("zope", "zope", "2.6", "*"), "2.6.0b1", True),
        (_entry("symantec", "messaging_gateway", "10.6.0", "1"), "10.6.1", False),
        # Exim's 4.92 is a release of its own, which 4.92.2 fixed.
        (_entry("exim", "exim", end_ex="4.92.2"), "4.92", True),
        (_entry("microsoft", "iis", end_ex="10.1"), "10.0", True),
    ])
    def test_version_ranges_and_updates(self, entry, version, expected):
        assert affects((entry,), "OpenSSH" if entry[2] == "openssh" else entry[2].replace("_", " "), version) is expected

    def test_portable_openssh_is_left_to_the_releases_a_record_lists(self):
        """CVE-2024-6387 lists 8.5p1 and ends at 9.8, which 9.8p1 fixed; CVE-2025-26465 also lists 9.9p1."""
        regresshion = (_entry("openbsd", "openssh", end_ex="4.4"), _entry("openbsd", "openssh", start_in="8.6", end_in="9.8"),
                       _entry("openbsd", "openssh", "8.5", "p1"))
        later = (_entry("openbsd", "openssh", start_in="6.9", end_in="9.8"), _entry("openbsd", "openssh", "9.9", "p1"))

        assert affects(regresshion, "OpenSSH", "9.7p1") is True
        assert affects(regresshion, "OpenSSH", "9.8p1") is False
        assert affects(later, "OpenSSH", "9.8p1") is True

    @pytest.mark.parametrize("entry, expected", [
        (_entry("apache", "http_server", start_in="2.4.0", end_ex="2.4.52"), False),
        (_entry("apache", "http_server", end_ex="2.4.52"), False),
        (_entry("apache", "http_server", end_in="2.4.62"), False),
        (_entry("apache", "http_server", start_in="2.4.10"), False),
        (_entry("apache", "http_server", "2.4.0", "*"), False),
        (_entry("apache", "http_server", start_in="2.4.0", end_ex="2.5.0"), True),
        (_entry("apache", "http_server", start_in="2.2.0", end_in="2.5"), True),
        (_entry("apache", "http_server", start_in="2.2.0", end_in="2.4"), False),
        (_entry("apache", "http_server", start_in="2.2.0", end_in="2.4.0"), False),
        (_entry("apache", "http_server", "2.4", "*"), False),
    ])
    def test_a_shortened_version_is_covered_only_where_every_release_it_may_be_is(self, entry, expected):
        """Apache's "Apache/2.4" banner may be any 2.4.x."""
        assert affects((entry,), "Apache HTTP Server", "2.4", shortened=True) is expected

    def test_a_version_is_shortened_when_the_product_almost_never_releases_one_that_short(self):
        apache = [(_entry("apache", "http_server", start_in="2.4.0", end_ex=f"2.4.{patch}"),) for patch in range(10)]
        exim = [(_entry("exim", "exim", end_ex=end),) for end in ("4.92.2", "4.92", "4.94.2", "4.96")]

        assert cut_short(apache, "Apache HTTP Server", "2.4") is True
        assert cut_short(apache, "Apache HTTP Server", "2.4.41") is False
        assert cut_short(apache, "Apache HTTP Server", "2.4beta2") is False  # a pre-release names its release
        assert cut_short(exim, "Exim", "4.92") is False
        assert cut_short([(_entry("other", "product", end_ex="1.2.3"),)], "Exim", "4.92") is False
        assert cut_short([], "Exim", "4.92") is False

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
        # NVD's generic product words are optional.
        ("f5", "nginx_open_source", "nginx", True),
        ("ipswitch", "imail_server", "IMail", True),
        ("solarwinds", "serv-u_ftp_server", "Serv-U", True),
        ("example", "web_server", "Example", False),
        # A library named like the server.
        ("mongoosejs", "mongoose", "Mongoose", False),
        ("cesanta", "mongoose", "Mongoose", True),
    ])
    def test_a_cpe_names_the_product_by_its_words(self, vendor, product, name, named):
        assert affects((_entry(vendor, product, end_ex="9.9"),), name, "1.0") is named

    @pytest.mark.parametrize("part", ["o", "h"])
    def test_an_operating_system_or_device_cpe_names_no_service(self, part):
        assert affects((_entry("openbsd", "openbsd", end_in="6.6", part=part),), "OpenBSD", "6.4") is False

    def test_vulnerable_matches_are_read_and_others_ignored(self):
        record = {"cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.3"},
            {"vulnerable": True, "criteria": r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:short"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndIncluding": 9},
        ]}]}]}}

        assert find_affected(record) == (
            ("a", "openbsd", "openssh", "*", "*", None, None, None, "9.3"),
            ("a", "vendor", r"pro\:duct", "1.0", "*", None, None, None, None),
            ("a", "openbsd", "openssh", "*", "*", None, None, None, None),
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
