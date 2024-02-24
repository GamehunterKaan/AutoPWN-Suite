from dataclasses import dataclass
from time import sleep

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
        return (
            f"Title : {self.title}\n"
            + f"CVE_ID : {self.CVEID}\n"
            + f"Description : {self.description}\n"
            + f"Severity : {self.severity} - {self.severity_score}\n"
            + f"Details : {self.details_url}\n"
            + f"Exploitability : {self.exploitability}"
        )


def FindVars(vuln: dict) -> tuple:
    CVE_ID = vuln["cve"]["id"]
    description = vuln["cve"]["descriptions"][0]["value"]
    exploitability = 0.0
    severity_score = 0.0
    severity = "UNKNOWN"

    metrics = vuln["cve"].get("metrics")
    if metrics is not None and len(metrics) > 0:
        # In testing this appears to contain cvssMetricV31 and cvssMetricV2
        # Get a list of the score types and sort them in reverse order to get v3 first
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


def searchCVE(keyword: str, log, apiKey=None) -> list[Vulnerability]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    # https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH+8.8
    if apiKey:
        sleep_time = 0.1
        headers = {"apiKey": apiKey}
    else:
        sleep_time = 8
        headers = {}
    parameters = {"keywordSearch": keyword}

    if keyword in cache:
        return cache[keyword]

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

    Vulnerabilities = []
    if not data or not "vulnerabilities" in data:
        return []

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
    return Vulnerabilities
