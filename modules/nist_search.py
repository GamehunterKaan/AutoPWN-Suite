from dataclasses import dataclass
from time import sleep

import shodan
from requests import get

cache = {}

@dataclass
class Vulnerability:
    title: str
    CVEID: str
    description: str
    severity: str
    severity_score: float
    details_url: str
    exploitability: float

    def __str__(self) -> str:
        result = (
            f"Title : {self.title}\n"
            f"CVE_ID : {self.CVEID}\n"
            f"Description : {self.description}\n"
            f"Severity : {self.severity} - {self.severity_score}\n"
            f"Details : {self.details_url}\n"
            f"Exploitability : {self.exploitability}\n"
        )
        if hasattr(self, 'args') and self.args.tag:
            return result + " - Nist Search"
        return result


def FindVars(vuln: dict) -> tuple:
    CVE_ID = vuln["cve"]["id"]
    description = vuln["cve"]["descriptions"][0]["value"]
    exploitability = 0.0
    severity_score = 0.0
    severity = "UNKNOWN"

    metrics = vuln["cve"].get("metrics")
    if metrics is not None and len(metrics) > 0:
        metrics_types = list(metrics.keys())
        metrics_types.sort(reverse=True)
        for score_type in metrics_types:
            if exploitability == 0.0:
                exploitability = metrics[score_type][0].get("exploitabilityScore", 0.0)
            if severity_score == 0.0:
                severity_score = metrics[score_type][0].get("cvssData", {}).get("baseScore", 0.0)
            if severity == "UNKNOWN":
                severity = metrics[score_type][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

    details_url = "https://nvd.nist.gov/vuln/detail/" + CVE_ID

    return CVE_ID, description, severity, severity_score, details_url, exploitability


def searchShodan(keyword: str, log, shodan_api_key: str, args) -> list[Vulnerability]:
    api = shodan.Shodan(shodan_api_key)
    vulns = []

    try:
        results = api.search(keyword)
        for result in results['matches']:
            for vuln in result.get('vulns', []):
                vulns.append(Vulnerability(
                    CVEID=vuln,
                    description=result['vulns'][vuln].get('summary', 'No description available'),
                    severity='N/A',
                    severity_score='N/A',
                    details_url=f"https://www.shodan.io/search?query={vuln}",
                    exploitability='N/A'
                ))

        # Handle the case where max_exploits is specified
        if args and args.max_exploits:
            if len(vulns) > args.max_exploits:
                vulns = vulns[:args.max_exploits]
                log_msg = f"Using the first {args.max_exploits} vulnerabilities"
                if args.tag:
                    log_msg += " - Shodan Search"
                log.logger("info", log_msg)

    except shodan.APIError as e:
        log.logger("error", f"Shodan API error: {e}")

    log_msg = f"Found {len(vulns)} vulnerabilities for {keyword}"
    if args.tag:
        log_msg += " - Shodan Search"
    log.logger("info", log_msg)

    return vulns


def searchCVE(keyword: str, log, apiKey=None, args=None) -> list[Vulnerability]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    if apiKey:
        sleep_time = 0.1
        headers = {"apiKey": apiKey}
    else:
        sleep_time = 8
        headers = {}
    parameters = {"keywordSearch": keyword}

    if keyword in cache:
        return cache[keyword]

    data = None  # Initialize 'data' here
    for tries in range(3):
        try:
            sleep(sleep_time)
            response = get(url, params=parameters, headers=headers)
            data = response.json()
        except Exception as e:
            if response.status_code == 403:
                log.logger(
                    "error",
                    "Requests are being rate limited by NIST API,"
                    + " please get a NIST API key to prevent this.",
                )
                sleep(sleep_time)
        else:
            break

    if data is None or "vulnerabilities" not in data:
        return []

    Vulnerabilities = []
    for vuln in data.get("vulnerabilities", []):
        title = keyword
        (
            CVE_ID,
            description,
            severity,
            severity_score,
            details_url,
            exploitability,
        ) = FindVars(vuln)
        VulnObject = Vulnerability(
            title=title,
            CVEID=CVE_ID,
            description=description,
            severity=severity,
            severity_score=severity_score,
            details_url=details_url,
            exploitability=exploitability,
        )

        Vulnerabilities.append(VulnObject)

    cache[keyword] = Vulnerabilities
    # Sort vulnerabilities by severity and exploitability
    Vulnerabilities.sort(key=lambda x: (x.severity_score, x.exploitability), reverse=True)
    
    # Handle the case where max_exploits is specified
    
    log_msg = f"Found {len(Vulnerabilities)} vulnerabilities for {keyword}"
    if args and args.tag:
        log_msg += " - NIST Search"
    log.logger("info", log_msg)
    
    
    if args and args.max_exploits and len(Vulnerabilities) > args.max_exploits:
        Vulnerabilities = Vulnerabilities[:args.max_exploits]
        log_msg = f"Using the first {args.max_exploits} vulnerabilities"
        if args.tag:
            log_msg += " - NIST Search"
        log.logger("info", log_msg)

    # Display the number of vulnerabilities found
    return Vulnerabilities
