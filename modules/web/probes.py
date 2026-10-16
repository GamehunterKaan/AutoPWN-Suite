# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Small, repeatable CORS, redirect, HTTP method and host-header probes."""

import re
from secrets import token_hex
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from modules.web.findings import emit, finding
from modules.web.http import is_html
from modules.web.query import parameter_indexes, probe_url, query_parts
from modules.web.runtime import begin_parameter, finish_parameter, parameter_done


def _publish(console, results):
    for result in results:
        emit(console, result)
    return results


def check_cors(client, url, console):
    """Header evidence only: authenticated data access still requires review."""
    results = []
    try:
        origins = [f"https://autopwn-{token_hex(12)}.invalid" for _ in range(2)]
        responses = [client.send(url, headers={"Origin": origin}) for origin in origins]
        if all(200 <= response.status_code < 300
               and response.headers.get("Access-Control-Allow-Origin", "").strip() == origin
               and response.headers.get("Access-Control-Allow-Credentials", "").strip() == "true"
               for response, origin in zip(responses, origins, strict=False)):
            results.append(finding("CORS", url, "Two arbitrary origins allowed with credentials; authenticated data exposure not verified", severity="medium",
                                   reproduction={"strategy": "cors", "requests": [{"url": url, "headers": {"Origin": origin}} for origin in origins]}))
        if any(response.headers.get("Access-Control-Allow-Origin", "").strip() == "*"
               and response.headers.get("Access-Control-Allow-Credentials", "").strip() == "true" for response in responses):
            results.append(finding("CORS_CONFIG", url, "Wildcard origin combined with credentials; browsers reject credentialed reads", confidence="advisory",
                                   reproduction={"strategy": "cors_config", "requests": [{"url": url, "headers": {"Origin": origin}} for origin in origins]}))
        nulls = [client.send(url, headers={"Origin": "null"}) for _ in range(2)]
        if all(200 <= response.status_code < 300
               and response.headers.get("Access-Control-Allow-Origin", "").strip() == "null"
               and response.headers.get("Access-Control-Allow-Credentials", "").strip() == "true" for response in nulls):
            results.append(finding("CORS", url, "Repeatable null-origin access with credentials; authenticated data exposure not verified", severity="medium",
                                   reproduction={"strategy": "cors", "requests": [{"url": url, "headers": {"Origin": "null"}} for _ in nulls]}))
    except RequestException:
        client.log.logger("warning", f"CORS probes incomplete on {url}.")
    return _publish(console, results)


def check_redirects(client, url, console, *, max_parameters=5):
    base, params = query_parts(url)
    names = {"next", "url", "redirect", "redirect_url", "redirect_uri", "return", "returnto", "return_to", "returnurl", "continue", "dest", "destination", "goto"}
    indexes = list(parameter_indexes(params, names=names))
    if len(indexes) > max_parameters:
        client.log.logger("warning", f"Redirect parameter budget reached on {url}; coverage is limited.")
    results = []
    for index in indexes[:max_parameters]:
        if parameter_done("redirects", url, index):
            continue
        revision = begin_parameter()
        for prefix in ("https://", "//"):
            successful = []
            try:
                for _ in range(2):
                    host = f"autopwn-{token_hex(12)}.invalid"
                    test_url = probe_url(base, params, index, f"{prefix}{host}/redirect-check")
                    response = client.send(test_url)
                    location = urljoin(test_url, response.headers.get("Location", ""))
                    destination = urlsplit(location)
                    if response.status_code in (301, 302, 303, 307, 308) and destination.scheme in ("http", "https") and destination.hostname == host:
                        successful.append(test_url)
            except (RequestException, ValueError):
                client.log.logger("warning", f"Redirect probes incomplete on {url}.")
                break
            if len(successful) == 2:
                results.append(finding("OPEN_REDIRECT", successful[0], "Two controlled external destinations accepted in Location; destinations were not visited",
                                       parameter=params[index].split("=", 1)[0], severity="medium",
                                       reproduction={"strategy": "redirect", "parameter": params[index].split("=", 1)[0], "requests": [{"url": probe} for probe in successful]}))
                break
        finish_parameter("redirects", url, index, revision)
    return _publish(console, results)


def check_methods(client, url, console):
    results = []
    try:
        response = client.send(url, method="OPTIONS")
        if 200 <= response.status_code < 300 or response.status_code == 405:
            methods = {part.strip().upper() for part in response.headers.get("Allow", "").split(",")}
            advertised = methods & {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}
            if advertised:
                results.append(finding("HTTP_METHODS", url, "Advertised methods: " + ", ".join(sorted(advertised)) + "; write methods were not tested",
                                       severity="info", confidence="observation", reproduction={"strategy": "methods", "requests": [{"url": url, "method": "OPTIONS"}]}))
        marker = token_hex(12)
        traces = [client.send(url, method="TRACE", headers={"X-Autopwn-Trace": marker}) for _ in range(2)]
        if all(response.status_code == 200 and re.search(r"^TRACE \S+ HTTP/\d(?:\.\d)?\s*$", response.text, re.M)
               and re.search(r"^X-Autopwn-Trace:\s*" + re.escape(marker) + r"\s*$", response.text, re.I | re.M) for response in traces):
            results.append(finding("TRACE_ENABLED", url, "Repeatable TRACE request-line and marker-header echo; no credentials were sent",
                                   severity="low", confidence="observation", reproduction={"strategy": "trace", "marker": marker,
                                   "requests": [{"url": url, "method": "TRACE", "headers": {"X-Autopwn-Trace": marker}} for _ in traces]}))
    except RequestException:
        client.log.logger("warning", f"HTTP method probes incomplete on {url}.")
    return _publish(console, results)


def _controlled_url(response, marker):
    values = [response.headers.get("Location", "")]
    if is_html(response):
        soup = BeautifulSoup(response.text, "html.parser")
        values.extend(node.get(attribute, "") for node in soup.find_all(["a", "link", "script", "img", "form"])
                      for attribute in ("href", "src", "action"))
    for value in values:
        try:
            parts = urlsplit(value)
            if (parts.scheme in ("http", "https") or value.startswith("//")) and parts.hostname == marker:
                return True
        except ValueError:
            continue
    return False


def check_host_headers(client, url, console):
    results = []
    for header in ("Host", "X-Forwarded-Host"):
        matched = []
        try:
            for _ in range(2):
                marker = f"autopwn-{token_hex(12)}.invalid"
                parts = urlsplit(url)
                query = parts.query + ("&" if parts.query else "") + "__autopwn_probe=" + token_hex(12)
                test_url = urlunsplit(parts._replace(query=query, fragment=""))
                response = client.send(test_url, headers={header: marker})
                if 200 <= response.status_code < 400 and _controlled_url(response, marker):
                    matched.append({"url": test_url, "headers": {header: marker}})
        except RequestException:
            client.log.logger("warning", f"Host-header probes incomplete on {url}.")
            break
        if len(matched) == 2:
            results.append(finding("HOST_HEADER", url, f"Two {header} values influenced redirect or generated URL hosts; exploit impact not verified",
                                   parameter=header, severity="low", confidence="advisory",
                                   reproduction={"strategy": "host_header", "header": header, "requests": matched}))
    return _publish(console, results)
