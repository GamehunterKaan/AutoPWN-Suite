from dataclasses import dataclass
from textwrap import wrap

from modules.logger import banner
from modules.nvdlib.cpe import searchCPE
from modules.nvdlib.cve import searchCVE
from modules.utils import CheckConnection, clear_line, get_terminal_width


@dataclass
class Vuln:
    Software : str
    CVEs : list


#generate keywords to search for from the information gathered from the target
def GenerateKeywords(HostArray) -> list:
    keywords = []
    for port in HostArray:
        service = str(port[2])
        product = str(port[3])
        version = str(port[4])
        templist = []
        #dont search if keyword is equal to any of these
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
                "microsoft windows rpc"
            ]

        if service == "Unknown":
            service = ""

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


def SearchKeyword(keyword, log, apiKey=None):
    clear_line()
    print(
        "Searching vulnerability database for keyword"
        + f" {keyword}... CTRL-C to skip", end="\r"
    )

    try:
        ApiResponseCPE = searchCPE(keyword=keyword, key=apiKey)
        ApiResponseCVE = searchCVE(keyword=keyword, key=apiKey)
    except KeyboardInterrupt:
        log.logger(
            "warning", f"Skipping vulnerability detection for keyword {keyword}"
        )
    except Exception as e:
        log.logger("error", e)
    else:
        tempTitleList, TitleList = [], []
        for CPE in ApiResponseCPE:
            tempTitleList.append(CPE.title)

        for title in tempTitleList:
            if title not in TitleList and title != "":
                TitleList.append(title)

        CPETitle = ""
        if len(TitleList) != 0:
            CPETitle = min(TitleList)

        return CPETitle, ApiResponseCVE

    return "", []


def SearchSploits(HostArray, log, console, apiKey=None) -> list:
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if not CheckConnection():
        log.logger(
            "error",
            "Connection error was raised. Skipping vulnerability detection."
        )
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
        CPETitle, ApiResponseCVE = SearchKeyword(keyword, log, apiKey)

        if CPETitle == "" and len(ApiResponseCVE) == 0:
            continue
        elif CPETitle == "" and len(ApiResponseCVE) != 0:
            Title = keyword
        elif CPETitle != "":
            Title = CPETitle

        if not printed_banner:
            banner(f"Possible vulnerabilities for {target}", "red", console)
            printed_banner = True

        VulnObject = Vuln(Software=Title, CVEs=[])

        clear_line()
        console.print(f"┌─ [yellow][{Title}][/yellow]")

        for CVE in ApiResponseCVE:
            console.print(
                f"│\n├─────┤ [red]{CVE.id}[/red]\n│"
            )

            description = str(CVE.cve.description.description_data[0].value)
            severity = str(CVE.score[2])
            score = str(CVE.score[1])
            details = CVE.url

            try:
                exploitability = str(CVE.v3exploitability)
            except AttributeError:
                try:
                    exploitability = str(CVE.v2exploitability)
                except AttributeError:
                    exploitability = (
                           f"Could not fetch exploitability score for {CVE.id}"
                        )

            wrapped_description = wrap(description, term_width-50)
            console.print(f"│\t\t[cyan]Description: [/cyan]")
            for line in wrapped_description:
                console.print(f"│\t\t\t{line}")
            console.print(
                f"│\t\t[cyan]Severity: [/cyan]{severity} - {score}\n"
                + f"│\t\t[cyan]Exploitability: [/cyan] {exploitability}\n"
                + f"│\t\t[cyan]Details: [/cyan] {details}"
            )

            VulnObject.CVEs.append(str(CVE.id))

        VulnsArray.append(VulnObject)
        console.print("└" + "─" * (term_width-1))

    clear_line()
    return VulnsArray
