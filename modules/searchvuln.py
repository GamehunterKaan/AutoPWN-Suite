from dataclasses import dataclass
from textwrap import wrap

from modules.logger import banner
from modules.nist_search import searchCVE
from modules.utils import CheckConnection, get_terminal_width
from rich.progress_bar import ProgressBar


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
        "ssh",
        "vnc",
        "http",
        "https",
        "ftp",
        "sftp",
        "smtp",
        "smb",
        "smbv2",
        "linux telnetd",
        "microsoft windows rpc",
        "metasploitable root shell",
        "gnu classpath grmiregistry",
    ]

    if product.lower() not in dontsearch and product != "":
        keyword = f"{product} {version}".rstrip()

    return keyword


def GenerateKeywords(HostArray: list) -> list:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])

        keyword = GenerateKeyword(product, version)
        if not keyword == "" and not keyword in keywords:
            keywords.append(keyword)

    return keywords


def SearchKeyword(keyword: str, log, apiKey=None) -> list:

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
    except KeyboardInterrupt:
        log.logger("warning", f"Skipped vulnerability detection for {keyword}")
    except Exception as e:
        log.logger("error", e)
    else:
        return ApiResponseCVE

    return []


def SearchSploits(HostArray: list, log, console, console2, apiKey=None) -> list:
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if not CheckConnection(log):
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
                + f"[red]{keyword}[/red] [white]...[/white]"
            )
            ApiResponseCVE = SearchKeyword(keyword, log, apiKey)
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(f"Possible vulnerabilities for {target}", "red", console)
                printed_banner = True

            console.print(f"┌─ [yellow][ {keyword} ][/yellow]")

            CVEs = []
            for CVE in ApiResponseCVE:
                CVEs.append(CVE.CVEID)
                console.print(f"│\n├─────┤ [red]{CVE.CVEID}[/red]\n│")

                wrapped_description = wrap(CVE.description, term_width - 50)
                console.print(f"│\t\t[cyan]Description: [/cyan]")
                for line in wrapped_description:
                    console.print(f"│\t\t\t{line}")
                console.print(
                    f"│\t\t[cyan]Severity: [/cyan]{CVE.severity} - {CVE.severity_score}\n"
                    + f"│\t\t[cyan]Exploitability: [/cyan] {CVE.exploitability}\n"
                    + f"│\t\t[cyan]Details: [/cyan] {CVE.details_url}"
                )

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            console.print("└" + "─" * (term_width - 1))

    return VulnsArray
