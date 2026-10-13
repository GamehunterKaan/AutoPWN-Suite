"""Run the additional checks within an explicit endpoint/request budget."""

from requests.exceptions import RequestException

from modules.web.boolean_sqli import BooleanSQLIScanner
from modules.web.content import inspect_content
from modules.web.http import ProbeClient, same_origin
from modules.web.probes import check_cors, check_host_headers, check_methods, check_redirects
from modules.web.query import query_parts
from modules.web.tls import check_tls
from modules.web.runtime import enabled, options, stage
from modules.web.planning import prioritize_urls


def _boolean_checks(client, endpoints, console, controls):
    results = []
    if enabled("boolean_sqli"):
        boolean = BooleanSQLIScanner(client, console, max_parameters=controls["max_parameters"])
        for url in endpoints:
            if query_parts(url)[1] and not client.exhausted:
                stage("Blind SQL injection")
                results.extend(boolean.test(url))
    return results


def critical_checks(target_url, urls, response, log, console, headers=None):
    """Run high-impact boolean checks before secondary response observations."""
    if not enabled("boolean_sqli"):
        return []
    controls = options()
    client = ProbeClient(target_url, log, headers, max_requests=controls["request_budget"])
    client.baselines[target_url] = response
    endpoints = prioritize_urls(url for url in urls if same_origin(target_url, url) and query_parts(url)[1])
    return _boolean_checks(client, endpoints[:controls["max_endpoints"]], console, controls)


def additional_checks(target_url, urls, response, log, console, headers=None, *, include_boolean=True):
    controls = options()
    client = ProbeClient(target_url, log, headers, max_requests=controls["request_budget"])
    client.baselines[target_url] = response
    ordered = prioritize_urls({target_url} | {url for url in urls if same_origin(target_url, url)}, target_url)
    limit = controls["max_endpoints"]
    if len(ordered) > limit:
        log.logger("warning", f"Additional web checks limited to {limit} discovered endpoints; coverage is limited.")
    endpoints = ordered[:limit]
    results = _boolean_checks(client, endpoints, console, controls) if include_boolean else []
    if enabled("tls"):
        stage("TLS and certificates")
        results.extend(check_tls(target_url, log, console))
    if enabled("methods"):
        stage("HTTP method checks")
        results.extend(check_methods(client, target_url, console))
    for url in endpoints:
        try:
            baseline = client.baseline(url)
        except RequestException:
            log.logger("warning", f"Additional response checks incomplete on {url}.")
            continue
        results.extend(inspect_content(url, baseline, console))
        if enabled("cors"):
            stage("CORS policy")
            results.extend(check_cors(client, url, console))
        if enabled("redirects") and query_parts(url)[1]:
            stage("Open redirects")
            results.extend(check_redirects(client, url, console, max_parameters=controls["max_parameters"]))
        if client.exhausted:
            break
    # Host-derived URL generation is an advisory about the endpoint. Probe one
    # representative per path instead of repeating it for every query value.
    if enabled("host_headers"):
        from urllib.parse import urlsplit
        tested_paths = set()
        for url in endpoints:
            path = urlsplit(url).path
            if path not in tested_paths and not client.exhausted:
                tested_paths.add(path)
                stage("Host header advisories")
                results.extend(check_host_headers(client, url, console))
    log.logger("info", f"Additional web checks used {client.requests}/{client.max_requests} HTTP probes.")
    return results
