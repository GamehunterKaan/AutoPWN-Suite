"""Run the additional checks within an explicit endpoint/request budget."""

from requests.exceptions import RequestException

from modules.web.boolean_sqli import BooleanSQLIScanner
from modules.web.content import inspect_content
from modules.web.http import ProbeClient, same_origin
from modules.web.probes import check_cors, check_host_headers, check_methods, check_redirects
from modules.web.query import query_parts
from modules.web.tls import check_tls
from modules.web.runtime import enabled, options, stage


def additional_checks(target_url, urls, response, log, console, headers=None):
    controls = options()
    client = ProbeClient(target_url, log, headers, max_requests=controls["request_budget"])
    client.baselines[target_url] = response
    ordered = [target_url] + sorted(url for url in urls if url != target_url and same_origin(target_url, url))
    limit = controls["max_endpoints"]
    if len(ordered) > limit:
        log.logger("warning", f"Additional web checks limited to {limit} discovered endpoints; coverage is limited.")
    endpoints = ordered[:limit]
    results = []
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
        if enabled("host_headers"):
            stage("Host headers")
            results.extend(check_host_headers(client, url, console))
        if client.exhausted:
            break
    boolean = BooleanSQLIScanner(client, console, max_parameters=controls["max_parameters"])
    for url in endpoints:
        if enabled("boolean_sqli") and query_parts(url)[1] and not client.exhausted:
            stage("Blind SQL injection")
            results.extend(boolean.test(url))
    log.logger("info", f"Additional web checks used {client.requests}/{client.max_requests} HTTP probes.")
    return results
