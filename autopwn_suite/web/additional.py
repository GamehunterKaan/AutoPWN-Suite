# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Run the additional checks within an explicit endpoint/request budget."""

from urllib.parse import urlsplit, urlunsplit

from requests.exceptions import RequestException

from autopwn_suite.web.boolean_sqli import BooleanSQLIScanner
from autopwn_suite.web.content import inspect_content
from autopwn_suite.web.http import ProbeClient, same_origin
from autopwn_suite.web.planning import prioritize_urls
from autopwn_suite.web.probes import check_cors, check_host_headers, check_methods, check_redirects
from autopwn_suite.web.query import query_parts
from autopwn_suite.web.runtime import enabled, options, run_task, stage, task_done
from autopwn_suite.web.tls import check_tls


def _boolean_checks(client, endpoints, console, controls):
    results = []
    if enabled("boolean_sqli"):
        boolean = BooleanSQLIScanner(client, console, max_parameters=controls["max_parameters"])
        for url in endpoints:
            if query_parts(url)[1] and not client.exhausted:
                stage("Blind SQL injection")
            results.extend(run_task("boolean_sqli", url, lambda: boolean.test(url)))
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
    def host_key(url):
        return urlunsplit(urlsplit(url)._replace(query="", fragment=""))
    def pending(url):
        names = ["content"] if any(enabled(name) for name in ("directories", "exposed_files", "errors")) else []
        names += [name for name in ("cors",) if enabled(name)]
        if enabled("redirects") and query_parts(url)[1]:
            names.append("redirects")
        if include_boolean and enabled("boolean_sqli") and query_parts(url)[1]:
            names.append("boolean_sqli")
        return (any(not task_done(name, url) for name in names)
                or (enabled("host_headers") and not task_done("host_headers", host_key(url))))
    ordered = [url for url in ordered if pending(url)]
    if len(ordered) > limit:
        log.logger("warning", f"Additional web checks limited to {limit} discovered endpoints; coverage is limited.")
    endpoints = ordered[:limit]
    results = _boolean_checks(client, endpoints, console, controls) if include_boolean else []
    if enabled("tls"):
        stage("TLS and certificates")
        results.extend(run_task("tls", target_url, lambda: check_tls(target_url, log, console)))
    if enabled("methods"):
        stage("HTTP method checks")
        results.extend(run_task("methods", target_url, lambda: check_methods(client, target_url, console)))
    for url in endpoints:
        try:
            baseline = client.baseline(url)
        except RequestException:
            log.logger("warning", f"Additional response checks incomplete on {url}.")
            continue
        if any(enabled(name) for name in ("directories", "exposed_files", "errors")):
            results.extend(run_task("content", url, lambda: inspect_content(url, baseline, console)))
        if enabled("cors"):
            stage("CORS policy")
            results.extend(run_task("cors", url, lambda: check_cors(client, url, console)))
        if enabled("redirects") and query_parts(url)[1]:
            stage("Open redirects")
            results.extend(run_task("redirects", url, lambda: check_redirects(client, url, console, max_parameters=controls["max_parameters"])))
        if client.exhausted:
            break
    # Host-derived URL generation is an advisory about the endpoint. Probe one
    # representative per path instead of repeating it for every query value.
    if enabled("host_headers"):
        tested_paths = set()
        for url in endpoints:
            path = urlsplit(url).path
            if path not in tested_paths and not client.exhausted:
                tested_paths.add(path)
                stage("Host header advisories")
                results.extend(run_task("host_headers", host_key(url), lambda: check_host_headers(client, url, console)))
    log.logger("info", _("Additional web checks used {used}/{total} HTTP probes.").format(used=client.requests, total=client.max_requests))
    return results
