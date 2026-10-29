# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import re
from dataclasses import dataclass
from textwrap import wrap

from autopwn_suite.cpe_match import affects
from autopwn_suite.logger import banner, console_safe
from autopwn_suite.nist_search import searchCVE
from autopwn_suite.utils import CheckConnection, get_terminal_width


@dataclass
class VulnerableSoftware:
    title: str
    CVEs: list


# Nmap names many services by their role ("Samba smbd", "Redis key-value store"); NVD names the product.
_PRODUCT_NAMES = {
    "apache httpd": "Apache HTTP Server",
    "dropbear sshd": "Dropbear SSH",
    "isc bind": "BIND",  # Most ISC advisories say "BIND 9.x" without "ISC"
    "miniserv": "Webmin",
}
_ROLE_SUFFIX = re.compile(r"\s+(?:httpd|smtpd|sshd|smbd|imapd|pop3d|ftpd|db|http proxy|key-value store|rest api)$",
                          re.IGNORECASE)
# One release: dotted digits with an optional suffix such as p1, c or rc2. Not "3.X", "protocol 3.3", "v1" or a
# bare major version such as Samba's "4", which every "before 4.x.y" range would cover.
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]*)?", re.IGNORECASE)


def _release(version: str) -> str:
    """The upstream release in an Nmap version string, or "" when it names none or a range."""
    if re.search(r"\s-\s", version):  # "8.3.0 - 8.3.7"
        return ""
    # Keep ISC's patch level (BIND 9.11.5-P4 is NVD's 9.11.5 update p4); drop distribution suffixes.
    release = re.sub(r"^([0-9.]+)-(P[0-9]+)\b", r"\1\2", version.split(" ")[0], flags=re.IGNORECASE)
    release = release.split("-")[0].split("/")[0].split("+")[0].rstrip(";,")  # dnsmasq's 2.93+30
    release = re.sub(r"\.v[0-9]{8}.*$", "", release)  # Jetty's 9.4.18.v20190429
    return release if _VERSION.fullmatch(release) else ""


def GenerateKeyword(product: str, version: str) -> str:
    if product == "Unknown":
        product = ""

    if version == "Unknown":
        version = ""

    keyword = ""
    dontsearch = [
        "http",
        "https",
        "linux telnetd",
        "microsoft windows rpc",
        "metasploitable root shell",
        "gnu classpath grmiregistry",
        "apache tomcat/coyote jsp engine",  # 1.1 is the HTTP version, not Tomcat's
        "microsoft httpapi httpd",
    ]
    known_vulns = [
        "unrealircd"
    ]
    mariadb = re.match(r"[0-9.]+-([0-9][0-9.]*)-MariaDB", version)
    if product.lower() == "mysql" and mariadb:  # MariaDB answers as MySQL 5.5.5-<its version>-MariaDB
        product, version = "MariaDB", mariadb.group(1)
    release = _release(version)
    if product.lower() not in dontsearch and product != "" and (
        product.lower() in known_vulns or release != ""
    ):
        stripped_name = product.split("/")[0]
        stripped_name = _PRODUCT_NAMES.get(stripped_name.lower(), _ROLE_SUFFIX.sub("", stripped_name))
        keyword = f"{stripped_name} {release}".rstrip()

    return keyword


def FindVulnerabilities(keyword: str, search) -> list:
    """The CVEs that affect the product version a keyword from GenerateKeyword names.

    `search` takes a search term and returns Vulnerability objects. Most CVE descriptions give a range
    ("before 2.4.52") rather than each version, so search for the product and keep the CVEs whose NVD
    applicability covers the version. A CVE whose applicability says nothing about versions (not analyzed, or
    only "every version") must name the version in its description.
    """
    name, _space, version = keyword.rpartition(" ")
    if not name or not _VERSION.fullmatch(version):
        return list(search(keyword))
    mentioned = re.compile(r"(?<![\w.])" + re.escape(version) + r"(?![\w]|\.[0-9])", re.IGNORECASE)
    found = []
    for vulnerability in search(name):
        verdict = affects(vulnerability.affected, name, version)
        if verdict or (verdict is None and mentioned.search(vulnerability.description)):
            found.append(vulnerability)
    return found


def GenerateKeywords(HostArray: list) -> list:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])

        keyword = GenerateKeyword(product, version)
        if not keyword == "" and keyword not in keywords:
            keywords.append(keyword)

    return keywords


def SearchKeyword(keyword: str, log, apiKey=None, *, lookup=None) -> list:

    try:
        ApiResponseCVE = FindVulnerabilities(
            keyword, lambda term: lookup.search(term, log, apiKey) if lookup is not None
            else searchCVE(term, log, apiKey, strict=True))
    except KeyboardInterrupt:
        log.logger("warning", _("Skipped vulnerability detection for {keyword}").format(keyword=keyword))
    except Exception as e:
        log.logger("error", e)
        if lookup is not None:
            raise
    else:
        return ApiResponseCVE

    return []


def SearchSploits(HostArray: list, log, console, console2, apiKey=None, *, lookup=None) -> list:
    if not HostArray:
        return []
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if lookup is None and not CheckConnection(log):
        return []

    keywords = GenerateKeywords(HostArray)

    if len(keywords) == 0:
        log.logger("warning", _("Insufficient information for {target}").format(target=target))
        return []

    log.logger(
        "info",
        _("Searching vulnerability database for {count} keyword(s) ...").format(count=len(keywords)),
    )

    printed_banner = False
    with console2.status(
        _("[white]Searching vulnerabilities ...[/white]"), spinner="bouncingBar"
    ) as status:
        for keyword in keywords:
            status.start()
            status.update(
                _("[white]Searching vulnerability database for[/white] [red]{keyword}[/red] [white]...[/white]").format(
                    keyword=console_safe(keyword)
                )
            )
            ApiResponseCVE = (SearchKeyword(keyword, log, apiKey, lookup=lookup) if lookup is not None
                              else SearchKeyword(keyword, log, apiKey))
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(_("Possible vulnerabilities for {target}").format(target=target), "red", console)
                printed_banner = True

            console.print(_("┌─ [yellow]{label}[/yellow]").format(label=console_safe(f"[ {keyword} ]")))

            CVEs = []
            for CVE in ApiResponseCVE:
                CVEs.append(CVE.CVEID)
                console.print(f"│\n├─────┤ [red]{console_safe(CVE.CVEID)}[/red]\n│")

                wrapped_description = wrap(CVE.description, max(1, term_width - 50))
                console.print(_("│\t\t[cyan]Description: [/cyan]"))
                for line in wrapped_description:
                    console.print(f"│\t\t\t{console_safe(line)}")
                console.print(
                    _(
                        "│\t\t[cyan]Severity: [/cyan]{severity} - {severity_score}\n"
                        "│\t\t[cyan]Exploitability: [/cyan] {exploitability}\n"
                        "│\t\t[cyan]Details: [/cyan] {details_url}"
                    ).format(
                        severity=console_safe(CVE.severity),
                        severity_score=console_safe(CVE.severity_score),
                        exploitability=console_safe(CVE.exploitability),
                        details_url=console_safe(CVE.details_url),
                    )
                )

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            console.print("└" + "─" * (term_width - 1))

    return VulnsArray
