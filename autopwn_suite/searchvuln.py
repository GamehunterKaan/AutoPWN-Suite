# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from dataclasses import dataclass
from textwrap import wrap

from autopwn_suite.logger import banner, console_safe
from autopwn_suite.nist_search import searchCVE
from autopwn_suite.utils import CheckConnection, get_terminal_width


@dataclass
class VulnerableSoftware:
    title: str
    CVEs: list


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
    ]
    known_vulns = [
        "unrealircd"
    ]
    if product.lower() not in dontsearch and product != "" and (
        product.lower() in known_vulns or version != ""
    ):
        stripped_name = product.split("/")[0]
        stripped_version = version.split(" ")[0].split("-")[0]
        keyword = f"{stripped_name} {stripped_version}".rstrip()

    return keyword


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
        ApiResponseCVE = (lookup.search(keyword, log, apiKey) if lookup is not None
                          else searchCVE(keyword, log, apiKey, strict=True))
    except KeyboardInterrupt:
        log.logger("warning", f"Skipped vulnerability detection for {keyword}")
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
        log.logger("warning", f"Insufficient information for {target}")
        return []

    log.logger(
        "info", f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    printed_banner = False
    with console2.status(
        "[white]Searching vulnerabilities ...[/white]", spinner="bouncingBar"
    ) as status:
        for keyword in keywords:
            status.start()
            status.update(
                "[white]Searching vulnerability database for[/white] "
                + f"[red]{console_safe(keyword)}[/red] [white]...[/white]"
            )
            ApiResponseCVE = (SearchKeyword(keyword, log, apiKey, lookup=lookup) if lookup is not None
                              else SearchKeyword(keyword, log, apiKey))
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(f"Possible vulnerabilities for {target}", "red", console)
                printed_banner = True

            console.print(f"┌─ [yellow]{console_safe(f'[ {keyword} ]')}[/yellow]")

            CVEs = []
            for CVE in ApiResponseCVE:
                CVEs.append(CVE.CVEID)
                console.print(f"│\n├─────┤ [red]{console_safe(CVE.CVEID)}[/red]\n│")

                wrapped_description = wrap(CVE.description, max(1, term_width - 50))
                console.print("│\t\t[cyan]Description: [/cyan]")
                for line in wrapped_description:
                    console.print(f"│\t\t\t{console_safe(line)}")
                console.print(
                    f"│\t\t[cyan]Severity: [/cyan]{console_safe(CVE.severity)} - {console_safe(CVE.severity_score)}\n"
                    + f"│\t\t[cyan]Exploitability: [/cyan] {console_safe(CVE.exploitability)}\n"
                    + f"│\t\t[cyan]Details: [/cyan] {console_safe(CVE.details_url)}"
                )

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            console.print("└" + "─" * (term_width - 1))

    return VulnsArray
