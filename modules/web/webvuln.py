"""Run the web checks and return structured findings for callers."""

import ipaddress
from urllib.parse import urldefrag, urlsplit, urlunsplit

from requests import get
from requests.exceptions import RequestException

from modules.logger import banner
from modules.nmap_progress import ScanCancelled
from modules.random_user_agent import random_user_agent
from modules.web.crawler import crawl
from modules.web.dirbust import dirbust
from modules.web.http import origin, same_origin, scoped_get
from modules.web.lfi import LFIScanner
from modules.web.passive import inspect_response
from modules.web.query import query_parts
from modules.web.sqli import SQLIScanner
from modules.web.xss import XSSScanner
from modules.web.additional import additional_checks, critical_checks
from modules.web.planning import prioritize_urls, skip_discovered_url
from modules.web.runtime import ACTIVE, ScanContext, WebBudgetExceeded, allowed, enabled, options, stage, run_task, task_done


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
    if isinstance(scan_result, dict):
        services = scan_result.get("scan", {}).get(host, {}).get("tcp", {})
    elif scan_result is not None:
        try:
            services = scan_result[host].get("tcp", {})
        except KeyError:
            services = {}
    else:
        services = {}
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
    results = []
    controls = options()
    selected = set()
    fast_scanners = [(LFIScanner(log, console), "test_lfi", "lfi"),
                     (SQLIScanner(log, console), "test_sqli", "sqli")]

    def test_priority_endpoints(discovered, limit):
        candidates = (url for url in discovered if same_origin(target_url, url)
                      and query_parts(url)[1] and (url == target_url or not skip_discovered_url(url))
                      and any(enabled(name) and not task_done(name, url) for name in ("lfi", "sqli", "boolean_sqli", "xss")))
        for url in prioritize_urls(candidates, target_url):
            if len(selected) >= limit:
                break
            if url in selected:
                continue
            selected.add(url)
            for scanner, method, name in fast_scanners:
                if enabled(name):
                    stage({"lfi": "Priority file inclusion", "sqli": "Priority SQL injection"}[name])
                    results.extend(run_task(name, url, lambda: getattr(scanner, method)(url)))

    # Reserve the early part of endpoint coverage for fast high-impact probes.
    # They run while crawling, before a large site can exhaust the request cap.
    early_limit = max(1, controls["max_endpoints"] // 4)
    test_priority_endpoints({target_url}, early_limit)

    def on_discovered(discovered):
        previous_phase = current.phase if current else None
        try:
            test_priority_endpoints(discovered, early_limit)
        finally:
            if current:
                current.phase = previous_phase
                current.publish_progress()

    urls = {target_url}
    if any(enabled(name) for name in ("cors", "redirects", "sqli", "boolean_sqli", "xss", "lfi", "host_headers", "errors", "directories")):
        stage("Discovering links and GET forms")
        urls = crawl(target_url, log, max_pages=controls["max_pages"], max_urls=controls["max_urls"], max_depth=controls["max_depth"],
                     on_discovered=on_discovered) if current else crawl(target_url, log)
    testable_urls = prioritize_urls(url for url in urls if same_origin(target_url, url) and query_parts(url)[1]
                                   and (url == target_url or not skip_discovered_url(url)))
    log.logger("info", f"Found {len(testable_urls)} testable urls.")
    remaining = [url for url in testable_urls if any(enabled(name) and not task_done(name, url)
                 for name in ("lfi", "sqli", "boolean_sqli", "xss"))]
    if len(set(remaining) | selected) > controls["max_endpoints"]:
        log.logger("warning", "Injection endpoint budget reached; coverage is limited.")
    test_priority_endpoints(testable_urls, controls["max_endpoints"])
    chosen = prioritize_urls(selected, target_url)
    results.extend(critical_checks(target_url, chosen, response, log, console, headers))
    if enabled("xss"):
        scanner = XSSScanner(log, console)
        for url in chosen:
            stage("Reflected XSS")
            results.extend(run_task("xss", url, lambda: scanner.test_xss(url)))
    # Discovery of exposed content and generic protection advisories comes after
    # injection checks, so it cannot consume their entire request budget.
    if any(enabled(name) for name in ("directories", "exposed_files", "errors")):
        stage("Directory and content discovery")
        results.extend(dirbust(target_url, console, log))
    results.extend(additional_checks(target_url, urls, response, log, console, headers, include_boolean=False))
    if enabled("headers"):
        results.extend(run_task("headers", target_url, lambda: inspect_response(target_url, response, console)))
    log.logger("info", f"Web checks completed: {len(results)} findings (candidates, advisories and observations).")
    return results


def webvuln(target, log, console, *, controls=None, should_stop=None, progress=None, on_finding=None, on_complete=None, checkpoint=None):
    context = ScanContext(target, log, controls=controls, should_stop=should_stop, progress=progress, on_finding=on_finding, checkpoint=checkpoint)
    class ScanLog:
        def logger(self, level, message):
            if level in ("warning", "error") and any(word in str(message).lower() for word in ("limited", "incomplete", "budget", "failed", "unable", "unavailable", "not checked", "no reachable", "connection error")):
                context.problem_revision += 1
                if str(message) not in context.issues:
                    context.issues.append(str(message))
            log.logger(level, message)
    try:
        with context.activate():
            results = _execute_webvuln(target, ScanLog(), console)
            # Include findings emitted before an earlier interruption as well.
            combined = context.findings + results
            unique = {}
            for index, result in enumerate(combined):
                if allowed(result["type"]):
                    unique[result.get("id", f"legacy-{index}")] = result
            return list(unique.values())
    except WebBudgetExceeded:
        return context.findings
    except ScanCancelled:
        raise
    except Exception:
        context.issue("Web checks failed; coverage is incomplete.")
        raise
    finally:
        context.state["requests"] = context.state.get("requests", 0) + context.requests
        context.state["attempts"] = context.state.get("attempts", 0) + 1
        if on_complete:
            on_complete({"status": "stopped" if context.should_stop() else "partial" if context.issues else "completed", "requests": context.requests,
                         "total_requests": context.state["requests"], "attempts": context.state["attempts"],
                         "completed_tasks": len(context.state["tasks"]),
                         "issues": context.issues, "target": context.target, "controls": context.options})
