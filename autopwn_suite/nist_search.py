# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from dataclasses import dataclass
from threading import Lock
from time import monotonic, sleep

from requests import get

from autopwn_suite.cpe_match import find_affected
from autopwn_suite.text import printable
from autopwn_suite.vulnerability_categories import categorize, find_weaknesses

# Dashboard and scheduled scans are long-lived and run concurrently. A successful NVD answer is
# reused for CACHE_LIFETIME seconds, so CVEs published later are seen; the lock guards both
# dictionaries. An entry in `cache` without a timestamp counts as expired.
CACHE_LIFETIME = 3600
cache = {}
_cache_stored_at = {}
_cache_lock = Lock()


def _cached(keyword):
    """Return the unexpired cached result for keyword, or None."""
    with _cache_lock:
        stored_at = _cache_stored_at.get(keyword)
        if keyword in cache and stored_at is not None and monotonic() - stored_at < CACHE_LIFETIME:
            return cache[keyword]
        cache.pop(keyword, None)
        _cache_stored_at.pop(keyword, None)
    return None


def _store(keyword, vulnerabilities):
    """Cache a complete result and drop every expired entry."""
    with _cache_lock:
        now = monotonic()
        for expired in [key for key, stored_at in _cache_stored_at.items() if now - stored_at >= CACHE_LIFETIME]:
            del _cache_stored_at[expired]
            cache.pop(expired, None)
        cache[keyword] = vulnerabilities
        _cache_stored_at[keyword] = now


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
    weaknesses: tuple = ()
    affected: tuple = ()  # Vulnerable CPE matches (autopwn_suite.cpe_match.find_affected)

    def __post_init__(self):
        # The NVD, or a database copied from another machine, controls these texts, and they reach the console, the
        # dashboard and the API: one line each, without control or layout characters.
        for name in ("CVEID", "description", "severity", "details_url"):
            setattr(self, name, printable(getattr(self, name)))

    @property
    def categories(self) -> tuple:
        """The kinds of vulnerability this CVE is (see autopwn_suite.vulnerability_categories)."""
        return categorize(self.weaknesses, self.description)

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
    scored = False

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
            if not scored:
                severity_score = metric["cvssData"]["baseScore"]
                severity = metric["cvssData"].get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
                scored = True
            # CVSS v4 metrics carry no exploitabilityScore, and 0.0 would read as "not
            # exploitable": take it from the newest version that has one.
            if isinstance(metric.get("exploitabilityScore"), (int, float)):
                exploitability = metric["exploitabilityScore"]
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
            raise ValueError(_("Vulnerability source must be auto, online, or offline"))
        self.source = source
        self.database = database
        self.local = None
        if source == "offline" and not lazy:
            self._open_local()

    def _open_local(self):
        from autopwn_suite.vulnerability_db import OfflineDatabase
        if self.local is None:
            self.local = OfflineDatabase(self.database)
        self.source = "offline"

    def search(self, keyword, log, api_key=None):
        return self._find(keyword, log, api_key, "search", searchCVE)

    def search_cpe(self, product, log, api_key=None):
        """The CVEs whose applicability names an NVD CPE product (see searchCPE), from the same source."""
        return self._find(product, log, api_key, "search_cpe", searchCPE)

    def _find(self, keyword, log, api_key, method, online):
        if self.source == "offline":
            if self.local is None:
                self._open_local()
                log.logger(
                    "info",
                    _("Using local NVD database: {count} CVEs; updated {updated_at}.").format(
                        count=self.local.metadata["count"], updated_at=self.local.metadata["updated_at"]
                    ),
                )
            return getattr(self.local, method)(keyword)
        try:
            return online(keyword, log, api_key, strict=True)
        except Exception:
            if self.source != "auto":
                raise
            from autopwn_suite.vulnerability_db import DatabaseUnavailable
            try:
                self._open_local()
            except DatabaseUnavailable as unavailable:
                raise DatabaseUnavailable(
                    _("NVD lookup failed and no local vulnerability database is available. Retry later, "
                    "use an NVD API key to avoid rate limits, or download the database with "
                    "--update-vuln-db while connected.")
                ) from unavailable
            log.logger("warning", _("NVD unavailable; using the local vulnerability database "
                       "updated {updated_at} for this scan.").format(updated_at=self.local.metadata['updated_at']))
            return getattr(self.local, method)(keyword)

    def close(self):
        if self.local is not None:
            self.local.close()


def searchCVE(keyword: str, log, apiKey=None, *, strict=False, force_refresh=False) -> list[Vulnerability]:
    # https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH+8.8
    return _query({"keywordSearch": keyword}, keyword, keyword, log, apiKey, strict, force_refresh)


def searchCPE(product: str, log, apiKey=None, *, strict=False, force_refresh=False) -> list[Vulnerability]:
    """The CVEs whose applicability names an NVD CPE product (`cpe_match.product_queries`), of any part,
    vendor and version: https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:*:*:nginx"""
    return _query({"virtualMatchString": f"cpe:2.3:*:*:{product}"}, product, ("cpe", product), log, apiKey, strict,
                  force_refresh)


def _query(parameters, keyword, cache_key, log, apiKey, strict, force_refresh) -> list[Vulnerability]:
    """Every page of an NVD CVE API query, cached under `cache_key`; `keyword` names it in results and messages."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    if apiKey:
        sleep_time = 0.1
        headers = {"apiKey": apiKey}
    else:
        sleep_time = 8
        headers = {}

    if not force_refresh:
        cached = _cached(cache_key)
        if cached is not None:
            return cached

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
                                                severity_score, details_url, exploitability,
                                                weaknesses=find_weaknesses(vuln),
                                                affected=find_affected(vuln)))
                page = parsed
            except Exception as error:
                last_error = error
                if response is not None and response.status_code in (403, 429):
                    log.logger(
                        "error",
                        _("Requests are being rate limited by NIST API, please get a NIST API key to prevent this."),
                    )
                if tries < 2:
                    sleep(sleep_time)
            else:
                break
        if page is None:
            if strict:
                raise RuntimeError(_("NVD lookup failed for {keyword}").format(keyword=keyword)) from last_error
            log.logger(
                "warning",
                _("NVD lookup failed for {keyword}; vulnerability coverage is incomplete.").format(keyword=keyword),
            )
            return []
        Vulnerabilities.extend(page)
        start_index += len(page)
        if start_index >= total:
            break
        parameters["startIndex"] = start_index

    _store(cache_key, Vulnerabilities)
    return Vulnerabilities
