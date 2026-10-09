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
    data_source: str = "online"
    database_updated_at: str = None

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
    descriptions = vuln["cve"].get("descriptions", [])
    description = next((entry["value"] for entry in descriptions
                        if entry.get("lang") == "en" and entry.get("value")),
                       next((entry["value"] for entry in descriptions if entry.get("value")), ""))
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
            entries = metrics[score_type]
            if not entries:
                continue
            entries = sorted(entries, key=lambda entry: entry.get("type") != "Primary")
            metric = next((entry for entry in entries
                           if isinstance(entry.get("cvssData", {}).get("baseScore"), (int, float))), None)
            if metric is None:
                continue
            # Take severity and score from the same preferred metric. A valid
            # zero score must not be overwritten by an older CVSS version.
            exploitability = metric.get("exploitabilityScore", 0.0)
            severity_score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"].get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
            break

        if severity == "UNKNOWN" and severity_score > 0.0:
            if severity_score >= 9.0:
                severity = "CRITICAL"
            elif severity_score >= 7.0:
                severity = "HIGH"
            elif severity_score >= 4.0:
                severity = "MEDIUM"
            elif severity_score >= 0.1:
                severity = "LOW"

    details_url = "https://nvd.nist.gov/vuln/detail/" + CVE_ID

    return CVE_ID, description, severity, severity_score, details_url, exploitability


class VulnerabilityLookup:
    """One scan's provider selection; auto falls back once, never silently updates."""

    def __init__(self, source="auto", database=None, *, lazy=False):
        if source not in ("auto", "online", "offline"):
            raise ValueError("Vulnerability source must be auto, online, or offline")
        self.source = source
        self.database = database
        self.local = None
        if source == "offline" and not lazy:
            self._open_local()

    def _open_local(self):
        from modules.vulnerability_db import OfflineDatabase
        if self.local is None:
            self.local = OfflineDatabase(self.database)
        self.source = "offline"

    def search(self, keyword, log, api_key=None):
        if self.source == "offline":
            if self.local is None:
                self._open_local()
                log.logger("info", f"Using local NVD database: {self.local.metadata['count']} CVEs; "
                           f"updated {self.local.metadata['updated_at']}.")
            return self.local.search(keyword)
        try:
            return searchCVE(keyword, log, api_key, strict=True)
        except Exception:
            if self.source != "auto":
                raise
            self._open_local()
            log.logger("warning", "NVD unavailable; using the local vulnerability database "
                       f"updated {self.local.metadata['updated_at']} for this scan.")
            return self.local.search(keyword)

    def close(self):
        if self.local is not None:
            self.local.close()


def searchCVE(keyword: str, log, apiKey=None, *, strict=False, force_refresh=False) -> list[Vulnerability]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    # https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH+8.8
    if apiKey:
        sleep_time = 0.1
        headers = {"apiKey": apiKey}
    else:
        sleep_time = 8
        headers = {}
    parameters = {"keywordSearch": keyword}

    if keyword in cache and not force_refresh:
        return cache[keyword]

    Vulnerabilities = []
    start_index = 0
    while True:
        page = None
        last_error = None
        for tries in range(3):
            response = None
            try:
                sleep(sleep_time)
                response = get(url, params=dict(parameters), headers=headers, timeout=20)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                    raise ValueError("NVD response has no vulnerabilities array")
                total = data.get("totalResults", start_index + len(data["vulnerabilities"]))
                if not isinstance(total, int) or total < 0:
                    raise ValueError("NVD response has invalid totalResults")
                if data.get("startIndex", start_index) != start_index:
                    raise ValueError("NVD returned the wrong result page")
                if not data["vulnerabilities"] and start_index < total:
                    raise ValueError("NVD returned an empty page before all results")
                parsed = []
                for vuln in data["vulnerabilities"]:
                    (CVE_ID, description, severity, severity_score,
                     details_url, exploitability) = FindVars(vuln)
                    parsed.append(Vulnerability(keyword, CVE_ID, description, severity,
                                                severity_score, details_url, exploitability))
                page = parsed
            except Exception as error:
                last_error = error
                if response is not None and response.status_code in (403, 429):
                    log.logger(
                        "error",
                        "Requests are being rate limited by NIST API,"
                        + " please get a NIST API key to prevent this.",
                    )
                if tries < 2:
                    sleep(sleep_time)
            else:
                break
        if page is None:
            if strict:
                raise RuntimeError(f"NVD lookup failed for {keyword}") from last_error
            log.logger("warning", f"NVD lookup failed for {keyword}; vulnerability coverage is incomplete.")
            return []
        Vulnerabilities.extend(page)
        start_index += len(page)
        if start_index >= total:
            break
        parameters["startIndex"] = start_index

    cache[keyword] = Vulnerabilities
    return Vulnerabilities
