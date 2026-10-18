# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Directory discovery with randomized controls for catch-all responses."""

from difflib import SequenceMatcher
from os.path import dirname
from secrets import token_hex
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from requests import get
from requests.exceptions import RequestException

from autopwn_suite.random_user_agent import random_user_agent
from autopwn_suite.web.content import inspect_content
from autopwn_suite.web.findings import emit, finding
from autopwn_suite.web.http import bounded_request, resolve_url, same_origin
from autopwn_suite.web.runtime import enabled, run_task, task_done


def _normalized(value, url):
    path = urlsplit(url).path
    for reflected in (url, quote(url, safe=""), quote(path, safe=""), unquote(path), path):
        value = value.replace(reflected, "{requested_path}")
    return value


def _catch_all(response, url, controls):
    text = _normalized(response.text, url)[:20_000]
    location = _normalized(resolve_url(url, response.headers.get("Location", "")) or "", url)
    for control_url, control in controls:
        if control.status_code != response.status_code:
            continue
        if response.status_code in (301, 302, 303, 307, 308):
            if location and location == _normalized(resolve_url(control_url, control.headers.get("Location", "")) or "", control_url):
                return True
        elif SequenceMatcher(None, text, _normalized(control.text, control_url)[:20_000]).ratio() >= .98:
            return True
    return False


def dirbust(target_url, console, log):
    parts = urlsplit(target_url)
    # Directory discovery is relative to the application path, never its query.
    target_url = urlunsplit(parts._replace(path=parts.path.rstrip("/") + "/", query="", fragment=""))
    try:
        with open(f"{dirname(__file__)}/../data/web_discovery.txt", "r", encoding="utf-8") as file:
            dirs = list(dict.fromkeys(line.strip() for line in file if line.strip() and not line.startswith("#")))
            if not enabled("directories"):
                sensitive = (".env", ".git", ".bak", ".old", ".sql", "backup", "web.config", "phpinfo", "debug")
                dirs = [path for path in dirs if (enabled("exposed_files") and any(part in path for part in sensitive[:7]))
                        or (enabled("errors") and any(part in path for part in sensitive[7:]))]
    except OSError:
        log.logger("error", "Web discovery database not found.")
        return []
    dirs = [path for path in dirs if not task_done("directory", f"{target_url}{path}")]
    if not dirs:
        return []
    headers = {"User-Agent": next(random_user_agent(log))}
    controls = []
    try:
        for suffix in ("", ".php"):
            url = f"{target_url}__autopwn_missing_{token_hex(12)}{suffix}"
            controls.append((url, bounded_request(get, url, headers=headers, timeout=10, allow_redirects=False)))
    except RequestException:
        log.logger("error", "Directory baseline request failed.")
        log.logger("warning", "Directory discovery skipped: unable to establish a missing-path baseline.")
        return []
    if any(response.autopwn_truncated for _, response in controls):
        log.logger("warning", "Directory baseline incomplete: response size limit reached.")
        return []
    found = []
    # Missing paths can reveal a detailed framework error even without a hit.
    found.extend(inspect_content(*controls[0], console))
    def check_directory(test_url):
        found = []
        try:
            response = bounded_request(get, test_url, headers=headers, timeout=10, allow_redirects=False)
        except RequestException:
            log.logger("error", f"Directory discovery request failed on {test_url}.")
            return found
        if response.status_code >= 500:
            found.extend(inspect_content(test_url, response, console))
        if not (200 <= response.status_code < 400 or response.status_code in (401, 403)):
            return found
        if _catch_all(response, test_url, controls):
            return found
        evidence = f"HTTP {response.status_code}; differs from missing-path controls"
        if response.status_code in (301, 302, 303, 307, 308):
            evidence += f"; redirect to {response.headers.get('Location', '')}"
        result = finding("DIR", test_url, evidence, severity="info", confidence="observation",
                         reproduction={"strategy": "directory", "requests": [{"url": url, "role": "missing-path control"} for url, _ in controls] + [{"url": test_url, "role": "probe"}]})
        if enabled("directories"):
            found.append(result)
            emit(console, result)
        found.extend(inspect_content(test_url, response, console))
        if response.status_code in (301, 302, 307, 308):
            try:
                destination = urljoin(test_url, response.headers.get("Location", ""))
                if same_origin(test_url, destination) and urlsplit(destination).path == urlsplit(test_url).path.rstrip("/") + "/":
                    canonical = bounded_request(get, destination, headers=headers, timeout=10, allow_redirects=False)
                    found.extend(inspect_content(destination, canonical, console))
            except (RequestException, ValueError):
                log.logger("warning", f"Directory content check incomplete on {test_url}.")
        return found

    for directory in dirs:
        test_url = f"{target_url}{directory}"
        found.extend(run_task("directory", test_url, lambda: check_directory(test_url)))
    return found
