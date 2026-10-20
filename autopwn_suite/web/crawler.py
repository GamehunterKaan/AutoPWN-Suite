# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Discover same-origin links and GET forms within configured crawl limits."""

from collections import deque
from itertools import islice
from urllib.parse import urldefrag, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from bs4.element import CData, NavigableString, Tag
from requests import get
from requests.exceptions import RequestException

from autopwn_suite.random_user_agent import random_user_agent
from autopwn_suite.web.http import is_html, resolve_url, same_origin, scoped_get
from autopwn_suite.web.options import LIMITS
from autopwn_suite.web.planning import prioritize_urls, skip_discovered_url
from autopwn_suite.web.runtime import ACTIVE

# html.parser nests unclosed <form>, <select> and <textarea> tags, so looking through the whole subtree of each
# one is quadratic on a hostile page (tens of seconds for 48 KB). Every walk below is cut to a fixed number of
# elements, and all the walks of one page together to MAX_PAGE_NODES; both are far above what an ordinary page
# has, and the page is reported as only partly analysed when one was reached.
MAX_FORMS = 100
MAX_FORM_ELEMENTS = 5_000
MAX_CONTROLS = 2_000
MAX_OPTION_ELEMENTS = 200
MAX_PAGE_NODES = 200_000
# A web server answers a request line of more than about 8,000 characters with an error, so a longer link is no use
# to a scan, and a hostile page can multiply the length of all its links by pointing <base href> at a long URL
# (6 such pages left 240 million characters in the crawl checkpoint).
MAX_URL_LENGTH = 8_192
MAX_LINK_CHARACTERS = 4_000_000  # the links of one page, and the links a crawl keeps for resuming, in total


class _Walk:
    """The tree walks of the form analysis of one page."""

    def __init__(self):
        self.left = MAX_PAGE_NODES
        self.cut = False  # a walk stopped before the end of its subtree

    def below(self, tag, limit):
        """The first `limit` nodes below `tag` in document order, fewer once the page's nodes are used up.

        tag.descendants first walks to the last descendant of the tag, which for a nested page is the whole rest of
        it, so even a few nodes cost time in proportion to the page. This walk visits only what it returns."""
        allowed = min(limit, self.left)
        nodes, pending = [], [iter(tag.contents)]
        while pending and len(nodes) <= allowed:
            for node in pending[-1]:
                nodes.append(node)
                if isinstance(node, Tag):
                    pending.append(iter(node.contents))
                break
            else:
                pending.pop()
        self.cut = self.cut or len(nodes) > allowed
        nodes = nodes[:allowed]
        self.left -= len(nodes)
        return nodes

    def text(self, tag):
        # tag.get_text() would read a whole nested subtree
        return "".join(islice((node for node in self.below(tag, 200) if type(node) in (NavigableString, CData)), 50))


def _coverage_note(log, message):
    current = ACTIVE.get()
    if current:
        current.issue(message)
    else:
        log.logger("warning", message)


def crawl(target_url, log, *, max_pages=LIMITS["max_pages"][0], max_urls=LIMITS["max_urls"][0], max_depth=LIMITS["max_depth"][0], on_discovered=None) -> set[str]:
    parts = urlsplit(urldefrag(target_url)[0])
    target_url = urlunsplit(parts._replace(path=parts.path or "/"))
    if not same_origin(target_url, target_url) or max_pages <= 0 or max_urls <= 0:
        return set()
    log.logger("info", _("Crawling web application at {url} ...").format(url=target_url))
    current = ACTIVE.get()
    graph = current.state.setdefault("crawl", {}) if current else {}
    stored = sum(len(url) for links in graph.values() for url in links)
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
                # Keep what this page can still add to the crawl: the links the crawl can follow, in the order it
                # follows them, up to one past the largest URL budget a scan can have (at most that many URLs are
                # known when the page is read, so one of them is always new, and the extra one tells the crawl its
                # budget ran out). The crawl and a resume with raised limits read this list as it is. A hostile
                # page with 55,000 links would otherwise leave about 11 MB in the job's checkpoint for every page.
                followable = (url for url in prioritize_urls(links) if same_origin(target_url, url) and not skip_discovered_url(url))
                links = list(islice(followable, LIMITS["max_urls"][2] + 1))
                # A page that would take the store past its size is crawled from this list and read again on a resume.
                if stored + sum(map(len, links)) <= MAX_LINK_CHARACTERS:
                    graph[page] = links
                    stored += sum(map(len, links))
            else:
                links = prioritize_urls(links)
        discovered = set()
        for url in links:
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
            message = _("Unable to crawl {url}: HTTP {status}; coverage is incomplete.").format(
                url=target_url, status=response.status_code
            )
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
    if len(base_url) > MAX_URL_LENGTH:  # every link and form action of the page would be longer than a server accepts
        _coverage_note(log, f"Links on {page_url} were not followed because its base URL is longer than {MAX_URL_LENGTH} characters; coverage is incomplete.")
        return set()
    characters, dropped = 0, False

    def keep(url):
        """False once the links of the page have used up their share, which ends the search for more."""
        nonlocal characters, dropped
        if len(url) > MAX_URL_LENGTH:
            dropped = True
        elif url not in urls:
            if characters + len(url) > MAX_LINK_CHARACTERS:
                dropped = True
                return False
            urls.add(url)
            characters += len(url)
        return True

    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if not href or href.startswith("#"):
            continue
        url = resolve_url(base_url, href)
        if url and same_origin(target_url, url) and not keep(url):
            break
    # Build URLs only for GET forms. Do not submit POST, passwords or uploads.
    forms = soup.find_all("form", limit=MAX_FORMS + 1)
    limited = len(forms) > MAX_FORMS
    walk = _Walk()
    controls_left = MAX_CONTROLS
    for form in forms[:MAX_FORMS]:
        if form.get("method", "get").lower() != "get":
            continue
        tags = [node for node in walk.below(form, MAX_FORM_ELEMENTS) if isinstance(node, Tag)]
        if any(tag.name == "input" and (tag.get("type") or "").lower() in ("password", "file") for tag in tags):
            continue
        action = resolve_url(base_url, form.get("action") or page_url)
        if not action or not same_origin(target_url, action):
            continue
        params = []
        for control in tags:
            if control.name not in ("input", "textarea", "select"):
                continue
            if controls_left <= 0:
                limited = True
                break
            controls_left -= 1
            name = control.get("name")
            kind = control.get("type", "text").lower()
            if not name or control.has_attr("disabled") or kind in ("submit", "button", "reset", "image"):
                continue
            if kind in ("checkbox", "radio") and not control.has_attr("checked"):
                continue
            if control.name == "select":
                options = [node for node in walk.below(control, MAX_OPTION_ELEMENTS) if isinstance(node, Tag) and node.name == "option" and not node.has_attr("disabled")]
                selected = [option for option in options if option.has_attr("selected")]
                for option in selected or options[:1]:
                    params.append((name, option["value"] if option.has_attr("value") else walk.text(option)))
            else:
                value = walk.text(control) if control.name == "textarea" else control.get("value", "on" if kind in ("checkbox", "radio") else "")
                params.append((name, value))
        if params:
            # Browsers replace an action's query when submitting a GET form.
            keep(urlunsplit(urlsplit(action)._replace(query=urlencode(params))))
    if limited or walk.cut:
        _coverage_note(log, f"Only part of the forms of {page_url} were analysed; coverage is incomplete.")
    if dropped:
        _coverage_note(log, f"Links on {page_url} that are longer than {MAX_URL_LENGTH} characters, or beyond {MAX_LINK_CHARACTERS:,} characters in all, were not followed; coverage is incomplete.")
    return urls
