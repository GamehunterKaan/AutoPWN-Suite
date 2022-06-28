from textwrap import wrap
from dataclasses import dataclass

from rich.console import Console

from nvdlib import searchCPE, searchCVE
from modules.logger import banner


@dataclass
class Vuln:
    Software : str
    CVEs : list


#generate keywords to search for from the information gathered from the target
def GenerateKeywords(HostArray):
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
            query1 = (f"{product} {version}").rstrip()
            templist.append(query1)

        for entry in templist:
            if entry not in keywords and entry != "":
                keywords.append(entry)

    return keywords


def SearchKeyword(keyword, log, apiKey=None):
    #search for the keyword in the NVD database
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


def SearchSploits(HostArray, term_width, term_cols, log, console, apiKey=None):
    VulnsArray = []
    target = str(HostArray[0][0])

    banner(f"Possible vulnerabilities for {target}", "red", term_width)

    keywords = GenerateKeywords(HostArray)

    if len(keywords) == 0:
        log.logger("error", f"Insufficient information for {target}")
        return []

    log.logger(
        "info",
        f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    for keyword in keywords:
        #https://github.com/vehemont/nvdlib
        #search the NIST vulnerabilities database for the generated keywords
        CPETitle, ApiResponseCVE = SearchKeyword(keyword, apiKey)

        #if the keyword is found in the NVD database, print the title of the vulnerable software
        if CPETitle == "" and len(ApiResponseCVE) == 0:
            continue
        elif CPETitle == "" and len(ApiResponseCVE) != 0:
            Title = keyword
        elif CPETitle != "":
            Title = CPETitle

        # create a Vuln object
        VulnObject = Vuln(Software=Title, CVEs=[])

        console.print(f"┌─[yellow][{Title}][/yellow]")

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

            wrapped_description = wrap(description, term_cols-50)
            console.print(f"│\t\t[cyan]Description: [/cyan]")
            for line in wrapped_description:
                print(f"│\t\t\t{line}")
            console.print(
                f"│\t\[cyan]Severity: [/cyan]{severity} - {score}\n"
                + f"│\t\t[cyan]Exploitability: [/cyan] {exploitability}\n"
                + f"│\t\t[cyan]Details: [/cyan] {details}"
            )

            VulnObject.CVEs.append(str(CVE.id))

        VulnsArray.append(VulnObject)
        print("└" + "─" * (term_width-1))

    return VulnsArray
