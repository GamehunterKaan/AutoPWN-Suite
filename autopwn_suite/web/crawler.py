# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Discover same-origin links and GET forms within configured crawl limits."""

from collections import deque
from urllib.parse import urldefrag, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from requests import get
from requests.exceptions import RequestException

from autopwn_suite.random_user_agent import random_user_agent
from autopwn_suite.web.http import is_html, resolve_url, same_origin, scoped_get
from autopwn_suite.web.options import LIMITS
from autopwn_suite.web.planning import prioritize_urls, skip_discovered_url
from autopwn_suite.web.runtime import ACTIVE


def crawl(target_url, log, *, max_pages=LIMITS["max_pages"][0], max_urls=LIMITS["max_urls"][0], max_depth=LIMITS["max_depth"][0], on_discovered=None) -> set[str]:
    parts = urlsplit(urldefrag(target_url)[0])
    target_url = urlunsplit(parts._replace(path=parts.path or "/"))
    if not same_origin(target_url, target_url) or max_pages <= 0 or max_urls <= 0:
        return set()
    log.logger("info", f"Crawling web application at {target_url} ...")
    current = ACTIVE.get()
    graph = current.state.setdefault("crawl", {}) if current else {}
    urls, visited = {target_url}, set()
    fetched = 0
    limited = False
    pending = deque([(target_url, 0)])
    if on_discovered:
        on_discovered({target_url})
    while pending:
        if current:
            current.checkpoint()
        page, depth = pending.popleft()
        if page in visited:
            continue
        if page not in graph and fetched >= max_pages:
            limited = True
            continue
        visited.add(page)
        if page in graph:
            links = graph[page]
        else:
            revision = current.problem_revision if current else 0
            links = link_finder(page, log)
            fetched += 1
            if not current or current.problem_revision == revision:
                # Keep what this page can still add to the crawl: its links in crawl order, up to one past the
                # largest URL budget a scan can have (a resume with raised limits reads this list again, and the
                # extra link tells the crawl its budget ran out). A hostile page with 55,000 links would otherwise
                # leave about 11 MB in the job's checkpoint for every page it serves.
                links = graph[page] = prioritize_urls(url for url in links if not skip_discovered_url(url))[:LIMITS["max_urls"][2] + 1]
        discovered = set()
        for url in prioritize_urls(links):
            if not same_origin(target_url, url) or url in urls or skip_discovered_url(url):
                continue
            if depth >= max_depth:
                limited = True
                continue
            if len(urls) >= max_urls:
                limited = True
                break
            urls.add(url)
            discovered.add(url)
            if depth < max_depth:
                pending.append((url, depth + 1))
        if on_discovered and discovered:
            on_discovered(discovered)
    if limited:
        log.logger("warning", "Web crawl budget reached; coverage is limited.")
    return urls


def link_finder(target_url, log) -> set[str]:
    try:
        response = scoped_get(get, target_url, headers={"User-Agent": next(random_user_agent(log))})
    except RequestException:
        log.logger("error", f"Unable to crawl {target_url}; coverage is incomplete.")
        return set()
    page_url = response.url if isinstance(response.url, str) else target_url
    if isinstance(response.status_code, int) and response.status_code >= 400:
        if response.status_code not in (404, 410):
            message = f"Unable to crawl {target_url}: HTTP {response.status_code}; coverage is incomplete."
            current = ACTIVE.get()
            if current:
                current.issue(message)
            else:
                log.logger("warning", message)
        return set()
    if not same_origin(target_url, page_url) or not is_html(response):
        return set()
    soup = BeautifulSoup(response.text, "html.parser")
    urls = set()
    base = soup.find("base", href=True)
    base_url = resolve_url(page_url, base["href"]) if base else page_url
    if not base_url or not same_origin(target_url, base_url):
        base_url = page_url
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if not href or href.startswith("#"):
            continue
        url = resolve_url(base_url, href)
        if url and same_origin(target_url, url):
            urls.add(url)
    # Build URLs only for GET forms. Do not submit POST, passwords or uploads.
    for form in soup.find_all("form"):
        if form.get("method", "get").lower() != "get":
            continue
        if form.find("input", attrs={"type": lambda value: value and value.lower() in ("password", "file")}):
            continue
        action = resolve_url(base_url, form.get("action") or page_url)
        if not action or not same_origin(target_url, action):
            continue
        params = []
        for control in form.find_all(["input", "textarea", "select"]):
            name = control.get("name")
            kind = control.get("type", "text").lower()
            if not name or control.has_attr("disabled") or kind in ("submit", "button", "reset", "image"):
                continue
            if kind in ("checkbox", "radio") and not control.has_attr("checked"):
                continue
            if control.name == "select":
                options = control.find_all("option", disabled=False)
                selected = [option for option in options if option.has_attr("selected")]
                for option in selected or options[:1]:
                    params.append((name, option.get("value", option.get_text())))
            else:
                value = control.get_text() if control.name == "textarea" else control.get("value", "on" if kind in ("checkbox", "radio") else "")
                params.append((name, value))
        if params:
            # Browsers replace an action's query when submitting a GET form.
            urls.add(urlunsplit(urlsplit(action)._replace(query=urlencode(params))))
    return urls
