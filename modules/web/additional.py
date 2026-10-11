"""Run the additional checks within an explicit endpoint/request budget."""

from requests.exceptions import RequestException

from modules.web.boolean_sqli import BooleanSQLIScanner
from modules.web.content import inspect_content
from modules.web.http import ProbeClient, same_origin
from modules.web.probes import check_cors, check_host_headers, check_methods, check_redirects
from modules.web.query import query_parts
from modules.web.tls import check_tls


def additional_checks(target_url, urls, response, log, console, headers=None):
    client = ProbeClient(target_url, log, headers)
    client.baselines[target_url] = response
    ordered = [target_url] + sorted(url for url in urls if url != target_url and same_origin(target_url, url))
    if len(ordered) > 10:
        log.logger("warning", "Additional web checks limited to 10 discovered endpoints; coverage is limited.")
    endpoints = ordered[:10]
    results = check_tls(target_url, log, console)
    results.extend(check_methods(client, target_url, console))
    for url in endpoints:
        try:
            baseline = client.baseline(url)
        except RequestException:
            log.logger("warning", f"Additional response checks incomplete on {url}.")
            continue
        results.extend(inspect_content(url, baseline, console))
        results.extend(check_cors(client, url, console))
        if query_parts(url)[1]:
            results.extend(check_redirects(client, url, console))
        results.extend(check_host_headers(client, url, console))
        if client.exhausted:
            break
    boolean = BooleanSQLIScanner(client, console)
    for url in endpoints:
        if query_parts(url)[1] and not client.exhausted:
            results.extend(boolean.test(url))
    log.logger("info", f"Additional web checks used {client.requests}/{client.max_requests} HTTP probes.")
    return results
