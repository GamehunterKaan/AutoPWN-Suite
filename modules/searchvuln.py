from dataclasses import dataclass
from textwrap import wrap

from modules.logger import banner
from modules.nist_search import searchCVE
from modules.utils import CheckConnection, clear_line, get_terminal_width


@dataclass
class VulnerableSoftware:
    title : str
    CVEs : list


def GenerateKeywords(HostArray : list) -> list:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])
        templist = []
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
                "metasploitable root shell"
            ]

        if product == "Unknown":
            product = ""

        if version == "Unknown":
            version = ""

        if product.lower() not in dontsearch and product != "":
            query = (f"{product} {version}").rstrip()
            templist.append(query)

        for entry in templist:
            if entry not in keywords and entry != "":
                keywords.append(entry)

    return keywords


def SearchKeyword(keyword : str, log, apiKey=None) -> list:
    clear_line()
    print(
        "Searching vulnerability database for keyword"
        + f" {keyword}... CTRL-C to skip", end="\r"
    )

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
    except KeyboardInterrupt:
        log.logger(
            "warning", f"Skipping vulnerability detection for keyword {keyword}"
        )
    except Exception as e:
        log.logger("error", e)
    else:
        return ApiResponseCVE

    return []


def SearchSploits(HostArray : list, log, console, apiKey=None) -> list:
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
        "info",
        f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    printed_banner = False
    for keyword in keywords:
        ApiResponseCVE = SearchKeyword(keyword, log, apiKey)

        if len(ApiResponseCVE) == 0:
            continue

        if not printed_banner:
            banner(f"Possible vulnerabilities for {target}", "red", console)
            printed_banner = True

        clear_line()
        console.print(f"┌─ [yellow][ {keyword} ][/yellow]")

        CVEs = []
        for CVE in ApiResponseCVE:
            CVEs.append(CVE.CVEID)
            console.print(
                f"│\n├─────┤ [red]{CVE.CVEID}[/red]\n│"
            )

            wrapped_description = wrap(CVE.description, term_width-50)
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
        console.print("└" + "─" * (term_width-1))

    clear_line()
    return VulnsArray
