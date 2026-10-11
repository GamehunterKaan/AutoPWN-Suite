"""Run the web checks and return structured findings for callers."""

import ipaddress
from urllib.parse import urldefrag, urlsplit, urlunsplit

from requests import get
from requests.exceptions import RequestException

from modules.logger import banner
from modules.random_user_agent import random_user_agent
from modules.web.crawler import crawl
from modules.web.dirbust import dirbust
from modules.web.http import origin, same_origin, scoped_get
from modules.web.lfi import LFIScanner
from modules.web.passive import inspect_response
from modules.web.query import query_parts
from modules.web.sqli import SQLIScanner
from modules.web.xss import XSSScanner
from modules.web.additional import additional_checks


def target_urls(target):
    target = str(target).strip()
    if "://" in target:
        origin(target)
        parts = urlsplit(urldefrag(target)[0])
        return [urlunsplit(parts._replace(path=parts.path or "/"))]
    try:
        address = ipaddress.ip_address(target)
        if address.version == 6:
            target = f"[{target}]"
    except ValueError:
        pass
    candidates = [f"http://{target}/", f"https://{target}/"]
    for candidate in candidates:
        origin(candidate)
    return candidates


def web_endpoints(host, port_rows, scan_result=None):
    """Use observed TCP web services, including TLS and nonstandard ports."""
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    services = scan_result.get("scan", {}).get(host, {}).get("tcp", {}) if isinstance(scan_result, dict) else {}
    targets = []
    for row in port_rows:
        if row[0] != host or (len(row) > 5 and row[5] == "udp"):
            continue
        service = str(row[2]).lower()
        if "http" not in service:
            continue
        port = int(row[1])
        tls = services.get(port, {}).get("tunnel") == "ssl" or "https" in service or "ssl" in service
        scheme = "https" if tls else "http"
        target = f"{scheme}://{authority}:{port}/"
        if target not in targets:
            targets.append(target)
    return targets or [host]


def webvuln(target, log, console):
    """Test a host, host:port or explicit URL; return observations and candidates."""
    try:
        candidates = target_urls(target)
    except ValueError:
        log.logger("error", "Invalid target for web vulnerability checks.")
        return []
    headers = {"User-Agent": next(random_user_agent(log))}
    response = None
    for candidate in candidates:
        try:
            response = scoped_get(get, candidate, headers=headers, allow_upgrade=True)
        except RequestException:
            continue
        target_url = response.url if isinstance(response.url, str) else candidate
        break
    if response is None:
        log.logger("warning", f"No reachable in-scope web endpoint on {target}.")
        return []
    banner(f"Testing web application on {target_url} ...", "purple", console)
    results = inspect_response(target_url, response, console)
    # These checks also run for static sites with no query parameters.
    results.extend(dirbust(target_url, console, log))
    urls = crawl(target_url, log)
    results.extend(additional_checks(target_url, urls, response, log, console, headers))
    testable_urls = sorted(url for url in urls if same_origin(target_url, url) and query_parts(url)[1])
    log.logger("info", f"Found {len(testable_urls)} testable urls.")
    scanners = [(LFIScanner(log, console), "test_lfi"), (SQLIScanner(log, console), "test_sqli"),
                (XSSScanner(log, console), "test_xss")]
    for url in testable_urls:
        for scanner, method in scanners:
            results.extend(getattr(scanner, method)(url))
    log.logger("info", f"Web checks completed: {len(results)} findings (candidates, advisories and observations).")
    return results
