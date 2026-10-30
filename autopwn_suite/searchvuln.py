# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import re
from dataclasses import dataclass
from textwrap import wrap

from autopwn_suite.cpe_match import (
    affects,
    cut_short,
    is_system,
    known_products,
    product_queries,
    reaches,
    service_products,
)
from autopwn_suite.logger import banner, console_safe
from autopwn_suite.nist_search import searchCPE, searchCVE
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
    "apache mina sshd": "Apache SSHD",  # apache:sshd; apache:mina is another project
    "sun java system httpd": "Sun Java System Web Server",  # not its Application Server
    "shoutcast/icecast streaming audio": "Icecast",  # the version is Icecast's
    "boa httpd": "Boa",
}
_ROLE_SUFFIX = re.compile(r"\s+(?:httpd|smtpd|sshd|smbd|imapd|pop3d|ftpd|db|http proxy|key-value store|rest api)$",
                          re.IGNORECASE)
# Without its role word, the daemon would be named after its operating system or vendor ("OpenBSD ftpd",
# "Microsoft ftpd"), a word too common to search for ("simple httpd"), or another product ("Hydra httpd").
_NOT_PRODUCTS = {"android", "catwalk", "cisco", "embedded", "freebsd", "gatling", "google", "hermes", "hp-ux",
                 "hummingbird", "hydra", "ibm", "ima", "libra", "local", "medusa", "microsoft", "minix", "netbox",
                 "news", "nucleus", "null", "openbsd", "openvms", "oracle", "panda", "personal", "router", "sco",
                 "shareit", "simple", "solaris", "ultrix", "virtual", "vxworks", "web-server"}
# One release: dotted digits with an optional suffix such as p1, c or rc2. Not "3.X", "protocol 3.3", "v1" or a
# bare major version such as Samba's "4", which every "before 4.x.y" range would cover.
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]*)?", re.IGNORECASE)
# A description names the release that fixed the CVE: "before 2.4.52", "fixed in versions 11.5.0, 11.4.1", or
# advises it ("upgrade to 2.4.52", which may also name the release that brought the flaw). A list after a bare
# "before" is of ranges or affected releases ("before 0.9.8za, 1.0.0 before 1.0.0m"; "6.1, 7.0 before 7.0.0.27, 8.0").
_FIXED_IN = re.compile(r"(?:(?:before|prior to|earlier than|below|(?:less|lower|older) than|not including|"
                       r"(?P<advice>upgrade to|upgrading to|update to|updating to)|<)\s*(?:version\s+)?|"
                       r"(?:(?:before|prior to)\s*versions|(?:fixed|patched|addressed|resolved) in\s*(?:versions?)?)\s+"
                       r"(?:[0-9][\w.-]*(?:\s*,\s*|\s+(?:and|or)\s+))*)$", re.IGNORECASE)
# ... unless only partly ("not fully fixed in 1.2", "cannot upgrade to 1.2", "upgrading from before 1.2"), the
# sentence says what is not affected ("did not affect versions prior to 1.1.1d"), or
# the release is followed by a build before the fix ("before 6.3.7 build 1", "before 7.1.2-31", "before 8.0 hp2",
# "before 8.1 service pack 4", "before 11.50.xC5", "before 6.1(1)"), by the range it starts ("1.0.2 before
# 1.0.2e", "before 10.3.34 thru 10.9.3", "2.0.10 and earlier"), or by what says it is not the fix ("prior to 1.2,
# inclusive", "versions before 4.4 are not affected").
_NOT_FIXED = re.compile(r"(?:not|partially|incompletely|insufficiently|not (?:fully|completely)|cannot|can't|unable to|"
                        r"from)\s+(?:been\s+)?$", re.IGNORECASE)
_UNAFFECTED = re.compile(r"\b(?:not|never)\s+(?:be\s+)?(?:affect|impact|vulnerable)|\bunaffected\b", re.IGNORECASE)
_LATER_BUILD = re.compile(r"[-_(][0-9a-z]|\.[0-9a-z]|\s*(?:,\s*)?\(?inclusive|"
                          r"\s+(?!(?:and|or|to|through|thru|until|from|in|on|versions?)\b)[a-z][a-z-]*(?:\s+[a-z][a-z-]*)?\s*[0-9]|"
                          r"\s+(?:before|prior to|through|thru|to|up to|until|-)\s|\s*(?:and|or) (?:earlier|prior|below|lower|older)|"
                          r"\s+(?:are|is|were|was|have|has)\s+(?:not|unaffected)\b", re.IGNORECASE)
# A pre-release of the fix ("before 6.0 beta 6") still makes the release itself the fixed one.
_PRE_RELEASE_AFTER = re.compile(r"[-._\s]*(?:alpha|beta|rc|pre|preview|dev|snapshot|m(?=[0-9]))[-.\s]*[0-9]*(?![a-z])",
                                re.IGNORECASE)
# The release is the fix only for what follows ("before 4.2 for Atlassian Confluence", "before 3.2.3 on HP-UX").
_ELSEWHERE = re.compile(r"\s+(?:for|on)\s", re.IGNORECASE)
# Between a product's name and the phrase that names its fix, only versions, asides and words such as these: "ISC
# BIND 9.x before 9.9.8-P2 and 9.10.x before 9.10.3-P2", "WebSphere Application Server (WAS) before 6.0.2.41".
# Another word may name another product ("Tera Term before 5.1").
_BETWEEN = frozenset({"and", "or", "the", "all", "x", "version", "versions", "release", "releases", "series", "branch",
                      "before", "prior", "to", "through", "thru", "earlier", "than", "server", "edition", "community",
                      "enterprise", "open", "source", "lts", "application", "http", "web"})
# A release a description names, with its suffix: 2.4.52, 1.3.3c, 9.10.3-P2.
_NAMED_RELEASE = re.compile(r"(?<![\w.])[0-9]+(?:\.[0-9]+)+(?:-?[a-z]+[0-9]*)?(?!\w)", re.IGNORECASE)


def _release(version: str) -> str:
    """The upstream release in an Nmap version string, or "" when it names none, a range or a bound."""
    # "8.3.0 - 8.3.7", "1.6.0 -", "0.3.1.1 or later", "3.0 or 3.1", "2.1.2+", "4.4.0-dev"
    if re.search(r"\s-(?:\s|$)|\bor\b|\b(?:after|before|earlier|later|newer|older)\b|\+\s*$|^[0-9.]+-(?:dev|snapshot)",
                 version, re.IGNORECASE):
        return ""
    # Keep a pre-release (2.0.0-rc1, 1.0 beta 2) and ISC's patch level (BIND 9.11.5-P4 is NVD's 9.11.5 update
    # p4); drop distribution suffixes (MySQL's 5.6.9-rc-log).
    release = re.sub(r"^([0-9.]*[0-9])[-.\s]*(alpha|beta|rc|m(?=[0-9]))(?:[-.\s]*([0-9]+)(?![0-9a-z~]))?", r"\1\2\3",
                     version, flags=re.IGNORECASE)
    release = re.sub(r"^([0-9.]+)-(P[0-9]+)\b", r"\1\2", release.split(" ")[0], flags=re.IGNORECASE)
    release = release.split("-")[0].split("/")[0].split("+")[0].rstrip(";,")  # dnsmasq's 2.93+30
    release = re.sub(r"\.v[0-9]{8}.*$", "", release)  # Jetty's 9.4.18.v20190429
    return release if _VERSION.fullmatch(release) else ""


def GenerateKeyword(product: str, version: str, cpes=()) -> str:
    """The search keyword for a service: the product as NVD names it and its release. `cpes` are the CPEs Nmap
    reported for the service; a daemon of an operating system or device they name is searched as the system
    ("VxWorks ftpd" with cpe:/o:windriver:vxworks as VxWorks)."""
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
        "tls",  # the protocol version
        "web",
    ]
    known_vulns = [
        "unrealircd"
    ]
    # MariaDB answers as MySQL 5.5.5-<its version>-MariaDB, which Nmap reports as MariaDB 5.5.5-<its version>.
    if product.lower() == "mariadb" or product.lower() == "mysql" and "-mariadb" in version.lower():
        product, version = "MariaDB", re.sub(r"^5\.5\.5-", "", version)
    if product.lower() == "mysql" and re.search(r"-(?:oceanbase|tidb|vitess)", version, re.IGNORECASE):
        version = ""  # Another database that announces the MySQL version it is compatible with
    if product.lower() == "filezilla ftpd":
        version = re.sub(r"\s+beta$", "", version, flags=re.IGNORECASE)  # FileZilla Server labels every release so
    release = _release(version)
    if product.lower() not in dontsearch and product != "" and (
        product.lower() in known_vulns or release != ""
    ):
        stripped_name = product.split("/")[0]
        stripped_name = _PRODUCT_NAMES.get(product.lower()) or _PRODUCT_NAMES.get(
            stripped_name.lower(), _ROLE_SUFFIX.sub("", stripped_name))
        # "AN httpd" stays "AN httpd" rather than "AN", a search for most of NVD, and "SAS/IntrNet" stays whole.
        if " " not in stripped_name and stripped_name not in _PRODUCT_NAMES.values() and (
                len(stripped_name) <= 3 or stripped_name.lower() in _NOT_PRODUCTS and not is_system(cpes, stripped_name)):
            stripped_name = product
        keyword = f"{stripped_name} {release}".rstrip()

    return keyword


def _named_as_fix(description, start, end, name=None):
    """Whether the release at description[start:end] is the one that fixed the CVE and, given the product's name,
    whether the description says so of that product rather than only advising an upgrade."""
    before = description[max(0, start - 80):start]
    fix = _FIXED_IN.search(before)
    if fix is None or _NOT_FIXED.search(before, 0, fix.start()):
        return False
    sentence = max(before.rfind(". ", 0, fix.start()), before.rfind("; ", 0, fix.start())) + 1
    if _UNAFFECTED.search(before, sentence, fix.start()):
        return False
    if name is None:
        return bool(_PRE_RELEASE_AFTER.match(description, end)) or not _LATER_BUILD.match(description, end)
    if fix.group("advice") or _LATER_BUILD.match(description, end) or _ELSEWHERE.match(description, end):
        return False
    words = set(re.findall(r"[\w.-]+", name.lower()))
    at = start - len(before) + fix.start()
    walked = re.findall(r"[\w.-]+", re.sub(r"\([^()]*\)", " ", description[max(0, at - 240):at].lower()))
    for index in range(len(walked) - 1, -1, -1):
        if walked[index] in words:  # but not "migrating from a Play version prior to 2.8.0"
            return [word for word in walked[max(0, index - 3):index] if word not in ("a", "an", "the")][-1:] != ["from"]
        if not (walked[index] in _BETWEEN or re.fullmatch(r"v?[0-9][\w.-]*", walked[index])):
            return False
    return False


def FindVulnerabilities(keyword: str, search, cpes=(), cpe_search=None) -> list:
    """The CVEs that affect the product version a keyword from GenerateKeyword names.

    `search` takes a search term and returns Vulnerability objects. Most CVE descriptions give a range
    ("before 2.4.52") rather than each version, so search for the product and keep the CVEs whose NVD
    applicability covers the version; a version with fewer numbers than the product's releases (Apache's "2.4")
    is covered only where every release it may be is. Given the CPEs Nmap reported for the service (`cpes`),
    `cpe_search` also fetches the CVEs whose applicability names the product they identify (it takes an NVD
    product name, see searchCPE), and the applicability counts only for that product once a result names it;
    otherwise for the CPEs the product's name matches (see autopwn_suite.cpe_match). A CVE whose applicability
    says nothing about versions
    (not analyzed, or only "every version") must name the version in its description, other than as the
    release that fixed it. A CVE whose description names the version, or an earlier build of its release, as
    the fix of that product is left out whatever its applicability says ("before 4.4" for OpenSSH 4.4p1).
    """
    name, _space, version = keyword.rpartition(" ")
    if not name or not _VERSION.fullmatch(version):
        return list(search(keyword))
    mention = re.compile(r"(?<![\w.])" + re.escape(version) + r"(?![\w]|\.[0-9])", re.IGNORECASE)

    def mentioned(description):
        return any(not _named_as_fix(description, match.start(), match.end()) for match in mention.finditer(description))

    def fixed(description):
        return any(reaches(version, match.group().replace("-", "")) and
                   _named_as_fix(description, match.start(), match.end(), name)
                   for match in _NAMED_RELEASE.finditer(description))

    results = list(search(name))
    products = service_products(cpes, name)
    if cpe_search is not None:
        # Many records list the product without their description naming it (HTTP/2 Rapid Reset for nginx).
        seen = {vulnerability.CVEID for vulnerability in results}
        for product in product_queries(products):
            for vulnerability in cpe_search(product):
                if vulnerability.CVEID not in seen:
                    seen.add(vulnerability.CVEID)
                    results.append(vulnerability)
    records = [vulnerability.affected for vulnerability in results]
    products = known_products(records, products, name)
    shortened = cut_short(records, name, version, products)
    found = []
    for vulnerability in results:
        verdict = affects(vulnerability.affected, name, version, shortened, products)
        if (verdict or (verdict is None and mentioned(vulnerability.description))) and not fixed(
                vulnerability.description):
            found.append(vulnerability)
    return found


def port_cpes(scan_result, host, protocol, port) -> tuple:
    """The CPEs Nmap reported for the service on a port, from its scan (a PortScanner); empty without them."""
    if scan_result is None:
        return ()
    try:
        cpes = scan_result[host][protocol][port].get("cpes")
    except (KeyError, IndexError, TypeError, AttributeError):
        return ()
    return tuple(cpes) if isinstance(cpes, list) else ()


def _services(HostArray: list, scan_result=None) -> dict:
    """Each keyword to search and the CPEs Nmap reported for the first service it names."""
    services = {}
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])
        cpes = port_cpes(scan_result, port[0], port[5] if len(port) > 5 else "tcp", port[1])

        keyword = GenerateKeyword(product, version, cpes)
        if not keyword == "" and keyword not in services:
            services[keyword] = cpes

    return services


def GenerateKeywords(HostArray: list, scan_result=None) -> list:
    return list(_services(HostArray, scan_result))


def SearchKeyword(keyword: str, log, apiKey=None, *, lookup=None, cpes=()) -> list:

    try:
        ApiResponseCVE = FindVulnerabilities(
            keyword, lambda term: lookup.search(term, log, apiKey) if lookup is not None
            else searchCVE(term, log, apiKey, strict=True), cpes,
            lambda product: lookup.search_cpe(product, log, apiKey) if lookup is not None
            else searchCPE(product, log, apiKey, strict=True))
    except KeyboardInterrupt:
        log.logger("warning", _("Skipped vulnerability detection for {keyword}").format(keyword=keyword))
    except Exception as e:
        log.logger("error", e)
        if lookup is not None:
            raise
    else:
        return ApiResponseCVE

    return []


def SearchSploits(HostArray: list, log, console, console2, apiKey=None, *, lookup=None, scan_result=None) -> list:
    if not HostArray:
        return []
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if lookup is None and not CheckConnection(log):
        return []

    services = _services(HostArray, scan_result)
    keywords = list(services)

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
            ApiResponseCVE = (SearchKeyword(keyword, log, apiKey, lookup=lookup, cpes=services[keyword])
                              if lookup is not None else SearchKeyword(keyword, log, apiKey, cpes=services[keyword]))
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
