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
    CVE_ID = vuln["cve"]["CVE_data_meta"]["ID"]
    description = vuln["cve"]["description"]["description_data"][0]["value"]

    exploitability = 0.0
    severity_score = 0.0
    severity = "UNKNOWN"

    if "baseMetricV3" in vuln["impact"].keys():
        if "exploitabilityScore" in vuln["impact"]["baseMetricV3"]:
            exploitability = vuln["impact"]["baseMetricV3"]["exploitabilityScore"]
        elif "cvssV3" in vuln["impact"]["baseMetricV3"]:
            exploitability = vuln["impact"]["baseMetricV3"]["cvssV3"][
                "exploitabilityScore"
            ]

        if "cvssV3" in vuln["impact"]["baseMetricV3"]:
            if "baseSeverity" in vuln["impact"]["baseMetricV3"]["cvssV3"]:
                severity = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

            if "baseScore" in vuln["impact"]["baseMetricV3"]["cvssV3"]:
                severity_score = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]

    elif "baseMetricV2" in vuln["impact"].keys():
        if "exploitabilityScore" in vuln["impact"]["baseMetricV2"].keys():
            exploitability = vuln["impact"]["baseMetricV2"]["exploitabilityScore"]
        elif "cvssV2" in vuln["impact"]["baseMetricV2"]:
            exploitability = vuln["impact"]["baseMetricV2"]["cvssV2"][
                "exploitabilityScore"
            ]

        if "cvssV2" in vuln["impact"]["baseMetricV2"]:
            if "baseSeverity" in vuln["impact"]["baseMetricV2"]["cvssV2"]:
                severity = vuln["impact"]["baseMetricV2"]["cvssV2"]["baseSeverity"]
            elif "severity" in vuln["impact"]["baseMetricV2"].keys():
                severity = vuln["impact"]["baseMetricV2"]["severity"]

            if "baseScore" in vuln["impact"]["baseMetricV2"]["cvssV2"]:
                severity_score = vuln["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]

    details_url = vuln["cve"]["references"]["reference_data"][0]["url"]

    return CVE_ID, description, severity, severity_score, details_url, exploitability


def searchCVE(keyword: str, log, apiKey=None) -> list[Vulnerability]:
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?"
    if apiKey:
        sleep_time = 0.6
        paramaters = {"keyword": keyword, "apiKey": apiKey}
    else:
        sleep_time = 6
        paramaters = {"keyword": keyword}

    if keyword in cache:
        return cache[keyword]

    for tries in range(3):
        try:
            sleep(sleep_time)
            request = get(url, params=paramaters)
            data = request.json()
        except Exception as e:
            if request.status_code == 403:
                log.logger(
                    "error",
                    "Requests are being rate limited by NIST API,"
                    + " please get a NIST API key to prevent this.",
                )
                sleep(sleep_time)
        else:
            break

    Vulnerabilities = []
    if not "result" in data:
        return []

    for vuln in data["result"]["CVE_Items"]:
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
