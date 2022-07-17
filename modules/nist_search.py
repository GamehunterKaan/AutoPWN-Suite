from requests import get
from dataclasses import dataclass

@dataclass
class Vulnerability:
    title : str
    CVEID : str
    description : str
    severity : str
    severity_score : float
    details_url : str
    exploitability : float

    def __str__(self) -> str:
        return (
            f"Title : {self.title}\n"
            + f"CVE_ID : {self.CVEID}\n"
            + f"Description : {self.description}\n"
            + f"Severity : {self.severity} - {self.severity_score}\n"
            + f"Details : {self.details_url}\n"
            + f"Exploitability : {self.exploitability}"
        )


def searchCVE(keyword : str, apiKey=None) -> list[Vulnerability]:
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?"
    if apiKey:
        paramaters = {"keyword": keyword, "apiKey": apiKey}
    else:
        paramaters = {"keyword": keyword}

    for tries in range(3):
        try:
            data = get(url, params=paramaters).json()
        except Exception as e:
            if tries < 3:
                continue
            else:
                return []

    Vulnerabilities = []
    for vuln in data["result"]["CVE_Items"]:
        title = keyword
        CVE_ID = vuln["cve"]["CVE_data_meta"]["ID"]
        description = vuln["cve"]["description"]["description_data"][0]["value"]

        if "baseMetricV3" in vuln["impact"].keys():
            if "exploitabilityScore" in vuln["impact"]["baseMetricV3"]:
                exploitability = vuln["impact"]["baseMetricV3"]["exploitabilityScore"]
            elif "cvssV3" in vuln["impact"]["baseMetricV3"]:
                exploitability = vuln["impact"]["baseMetricV3"]["cvssV3"]["exploitabilityScore"]
            else:
                exploitability = 0.0
            if "cvssV3" in vuln["impact"]["baseMetricV3"]:
                if "baseSeverity" in vuln["impact"]["baseMetricV3"]["cvssV3"]:
                    severity = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                else:
                    severity = "UNKNOWN"
                if "baseScore" in vuln["impact"]["baseMetricV3"]["cvssV3"]:
                    severity_score = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                else:
                    severity_score = 0.0
            else:
                severity = "UNKNOWN"
                severity_score = 0.0
        elif "baseMetricV2" in vuln["impact"].keys():
            if "exploitabilityScore" in vuln["impact"]["baseMetricV2"].keys():
                exploitability = vuln["impact"]["baseMetricV2"]["exploitabilityScore"]
            elif "cvssV2" in vuln["impact"]["baseMetricV2"]:
                exploitability = vuln["impact"]["baseMetricV2"]["cvssV2"]["exploitabilityScore"]
            else:
                exploitability = 0.0
            if "cvssV2" in vuln["impact"]["baseMetricV2"]:
                if "baseSeverity" in vuln["impact"]["baseMetricV2"]["cvssV2"]:
                    severity = vuln["impact"]["baseMetricV2"]["cvssV2"]["baseSeverity"]
                elif "severity" in vuln["impact"]["baseMetricV2"].keys():
                    severity = vuln["impact"]["baseMetricV2"]["severity"]
                else:
                    severity = "UNKNOWN"
                if "baseScore" in vuln["impact"]["baseMetricV2"]["cvssV2"]:
                    severity_score = vuln["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                else:
                    severity_score = 0.0
            else:
                severity = "UNKNOWN"
                severity_score = 0.0

        details_url = vuln["cve"]["references"]["reference_data"][0]["url"]

        VulnObject = Vulnerability(
            title=title,
            CVEID=CVE_ID,
            description=description,
            severity=severity,
            severity_score=severity_score,
            details_url=details_url,
            exploitability=exploitability
        )

        Vulnerabilities.append(VulnObject)

    return Vulnerabilities