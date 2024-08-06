import shodan
from zoomeye.sdk import ZoomEye
from dataclasses import dataclass
from textwrap import wrap
from time import sleep

from modules.keyword_generator import (generate_keywords,
                                       generate_keywords_with_ai)
from modules.logger import banner
from modules.nist_search import searchCVE
from modules.utils import CheckConnection, get_terminal_width


@dataclass
class VulnerableSoftware:
    title: str
    CVEs: list
    severity_score: float
    exploitability: float


def SearchKeyword(keyword: str, log, apiKey=None) -> list:

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
        #log.logger("warning", f"Skipped vulnerability detection for {keyword}")
    except Exception as e:
        log.logger("error", e)
    else:
        return ApiResponseCVE

    return []


def SearchSploits(HostArray: list, log, console, args, apiKey=None) -> list:
    VulnsArray = []
    target = str(HostArray[0][0])
    term_width = get_terminal_width()

    if not CheckConnection(log):
        return []

    ApiResponseCVE = []
    keywords = generate_keywords(HostArray)
    if args.openai_api_key:
        log.logger("info", "Using OpenAI API for vulnerability detection.")
        GPTkeywords = generate_keywords_with_ai(args.openai_api_key, HostArray)
        for GPTkeyword in GPTkeywords:
            ApiResponseCVE.extend(SearchKeyword(GPTkeyword, log, apiKey))
                    
    if len(keywords) == 0:
        log.logger("warning", f"Insufficient information for {target}")
        return []

    log.logger(
        "info", f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    printed_banner = False
    for keyword in keywords:
        with console.status(
            f"[white]Searching vulnerability database for[/white] [red]{keyword}[/red] [white]...[/white]",
            spinner="bouncingBar"
        ) as status:
            ApiResponseCVE = SearchKeyword(keyword, log, apiKey)
            sleep(1)  # Adding a delay to ensure proper logging and searching
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

            VulnObject = VulnerableSoftware(
                title=keyword,
                CVEs=CVEs,
                severity_score=CVE.severity_score,
                exploitability=CVE.exploitability
            )
            VulnsArray.append(VulnObject)
            console.print("└" + "─" * (term_width - 1))


    # Sort vulnerabilities by severity and exploitability
    VulnsArray.sort(key=lambda x: (x.severity_score, x.exploitability), reverse=True)
    
    
    return VulnsArray


def GetShodanVulns(host, shodan_api_key, log):
    api = shodan.Shodan(shodan_api_key)
    try:
        host_info = api.host(host)
        vulns = host_info.get("vulns", [])
        log.logger("INFO", f"Found {len(vulns)} vulnerabilities for {host} from Shodan.")
        open_ports = [service['port'] for service in host_info.get('data', [])]
        formatted_vulns = []
        for vuln in vulns:
            formatted_vulns.append({
                'title': vuln,
                'CVEs': [vuln],
                'severity_score': 0.0,
                'exploitability': 0.0
            })
        return formatted_vulns, open_ports
    except shodan.APIError as e:
        log.logger("ERROR", f"Error fetching Shodan vulnerabilities: {e}")
        return []

def GetZoomEyeVulns(host, zoomeye_api_key, log):
    # Initialize ZoomEye API client
    api = ZoomEye(api_key=zoomeye_api_key)
    
    try:
        # Perform the search
        results = api.dork_search(f"ip:{host}", page=1)
        vulns = results.get('matches', [])
        log.logger("INFO", f"Found {len(vulns)} vulnerabilities for {host} from ZoomEye.")
        return vulns
    except Exception as e:
        log.logger("ERROR", f"Error fetching ZoomEye vulnerabilities: {e}")
        return []