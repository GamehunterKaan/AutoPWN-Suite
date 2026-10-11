"""Discover same-origin links and GET forms within a small crawl budget."""

from collections import deque
from urllib.parse import urldefrag, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from requests import get
from requests.exceptions import RequestException

from modules.random_user_agent import random_user_agent
from modules.web.http import is_html, resolve_url, same_origin, scoped_get


def crawl(target_url, log, *, max_pages=25, max_urls=50, max_depth=2) -> set[str]:
    parts = urlsplit(urldefrag(target_url)[0])
    target_url = urlunsplit(parts._replace(path=parts.path or "/"))
    if not same_origin(target_url, target_url) or max_pages <= 0 or max_urls <= 0:
        return set()
    log.logger("info", f"Crawling web application at {target_url} ...")
    urls, visited = {target_url}, set()
    limited = False
    pending = deque([(target_url, 0)])
    while pending and len(visited) < max_pages:
        page, depth = pending.popleft()
        if page in visited:
            continue
        visited.add(page)
        for url in sorted(link_finder(page, log)):
            if not same_origin(target_url, url) or url in urls:
                continue
            if depth >= max_depth:
                limited = True
                continue
            if len(urls) >= max_urls:
                limited = True
                break
            urls.add(url)
            if depth < max_depth:
                pending.append((url, depth + 1))
    if limited or pending or len(urls) >= max_urls:
        log.logger("warning", "Web crawl budget reached; coverage is limited.")
    return urls


def link_finder(target_url, log) -> set[str]:
    try:
        response = scoped_get(get, target_url, headers={"User-Agent": next(random_user_agent(log))})
    except RequestException as exc:
        log.logger("error", f"Unable to crawl {target_url}: {exc}")
        return set()
    page_url = response.url if isinstance(response.url, str) else target_url
    if not same_origin(target_url, page_url) or not is_html(response):
        return set()
    if isinstance(response.status_code, int) and response.status_code >= 400:
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
