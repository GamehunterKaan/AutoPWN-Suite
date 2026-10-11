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
from modules.web.runtime import ACTIVE, ScanContext, WebBudgetExceeded, allowed, enabled, options, stage


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


def _execute_webvuln(target, log, console):
    """Test a host, host:port or explicit URL; return observations and candidates."""
    try:
        candidates = target_urls(target)
    except ValueError:
        log.logger("error", "Invalid target for web vulnerability checks.")
        return []
    headers = {"User-Agent": next(random_user_agent(log))}
    response = None
    current = ACTIVE.get()
    if current:
        current.discovery = True
    for candidate in candidates:
        try:
            response = scoped_get(get, candidate, headers=headers, allow_upgrade=True)
        except RequestException:
            continue
        target_url = response.url if isinstance(response.url, str) else candidate
        break
    if current:
        current.discovery = False
    if response is None:
        log.logger("warning", f"No reachable in-scope web endpoint on {target}.")
        return []
    banner(f"Testing web application on {target_url} ...", "purple", console)
    current = ACTIVE.get()
    if current:
        current.target = target_url
    results = inspect_response(target_url, response, console) if enabled("headers") else []
    # These checks also run for static sites with no query parameters.
    if any(enabled(name) for name in ("directories", "exposed_files", "errors")):
        stage("Directory and content discovery")
        results.extend(dirbust(target_url, console, log))
    controls = options()
    urls = {target_url}
    if any(enabled(name) for name in ("cors", "redirects", "sqli", "boolean_sqli", "xss", "lfi", "host_headers", "errors", "directories")):
        stage("Discovering links and GET forms")
        urls = crawl(target_url, log, max_pages=controls["max_pages"], max_urls=controls["max_urls"], max_depth=controls["max_depth"]) if current else crawl(target_url, log)
    results.extend(additional_checks(target_url, urls, response, log, console, headers))
    testable_urls = sorted(url for url in urls if same_origin(target_url, url) and query_parts(url)[1])
    log.logger("info", f"Found {len(testable_urls)} testable urls.")
    scanners = [(LFIScanner(log, console), "test_lfi", "lfi"), (SQLIScanner(log, console), "test_sqli", "sqli"),
                (XSSScanner(log, console), "test_xss", "xss")]
    for url in testable_urls:
        for scanner, method, name in scanners:
            if enabled(name):
                stage({"lfi": "File inclusion", "sqli": "SQL injection", "xss": "Reflected XSS"}[name])
                results.extend(getattr(scanner, method)(url))
    log.logger("info", f"Web checks completed: {len(results)} findings (candidates, advisories and observations).")
    return results


def webvuln(target, log, console, *, controls=None, should_stop=None, progress=None, on_finding=None, on_complete=None):
    context = ScanContext(target, log, controls=controls, should_stop=should_stop, progress=progress, on_finding=on_finding)
    class ScanLog:
        def logger(self, level, message):
            if level in ("warning", "error") and any(word in str(message).lower() for word in ("limited", "incomplete", "budget", "failed", "unable", "unavailable", "not checked", "no reachable", "connection error")):
                if str(message) not in context.issues:
                    context.issues.append(str(message))
            log.logger(level, message)
    try:
        with context.activate():
            results = _execute_webvuln(target, ScanLog(), console)
            return [result for result in results if allowed(result["type"])]
    except WebBudgetExceeded:
        return context.findings
    finally:
        if on_complete:
            on_complete({"status": "stopped" if context.should_stop() else "partial" if context.issues else "completed", "requests": context.requests,
                         "issues": context.issues, "target": context.target, "controls": context.options})
