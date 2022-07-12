from dataclasses import dataclass
from os import get_terminal_size
from textwrap import wrap

from nvdlib import searchCPE, searchCVE

from modules.logger import banner
from modules.utils import CheckConnection


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
                "linux telnetd"
            ]

        #if any of these equal to "Unknown" set them to empty string
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
    term_width, _ = get_terminal_size()
    print(" " * term_width, end="\r") # we have to clear screen here
    print(
        "Searching vulnerability database for keyword"
        + f" {keyword}... CTRL-C to skip", end="\r"
    )

    try:
        if apiKey is None:
            ApiResponseCPE = searchCPE(keyword=keyword)
            ApiResponseCVE = searchCVE(keyword=keyword)
        else:
            ApiResponseCPE = searchCPE(keyword=keyword, key=apiKey)
            ApiResponseCVE = searchCVE(keyword=keyword, key=apiKey)

    except KeyboardInterrupt:
        log.logger(
            "error", f"Skipping vulnerability detection for keyword {keyword}"
        )
    except LookupError:
        log.logger(
            "error",
            f"NIST API returned an invalid response for keybord {keyword}"
        )
    except Exception as e:
        log.logger("error", f"Error: {e}")
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
    term_width, _ = get_terminal_size()

    if not CheckConnection():
        log.logger(
            "error", 
            "Connection error was raised. Skipping vulnerability detection."
        )
        return []

    keywords = GenerateKeywords(HostArray)

    if len(keywords) == 0:
        log.logger("error", f"Insufficient information for {target}")
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

        print(" " * term_width, end="\r") # we have to clear screen here
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

    print(" " * term_width, end="\r") # we have to clear screen here
    return VulnsArray
