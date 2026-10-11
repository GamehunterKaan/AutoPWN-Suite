from bs4 import BeautifulSoup
from modules.random_user_agent import random_user_agent
from requests import get
from requests import packages
from requests.exceptions import ConnectionError, RequestException
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit


packages.urllib3.disable_warnings()

def crawl(target_url, log) -> set[str]:
    parts = urlsplit(target_url)
    if not parts.path:
        target_url = urlunsplit(parts._replace(path="/"))

    try:
        get(target_url, headers={"User-Agent": next(random_user_agent(log))}, verify=False, timeout=10)
    except ConnectionError:
        log.logger("error", f"Connection error raised.")
        return set()
    except RequestException as exc:
        log.logger("error", f"Unable to crawl {target_url}: {exc}")
        return set()

    log.logger("info", f"Crawling web application at {target_url} ...")

    urls = link_finder(target_url, log)
    if len(urls) < 25:
        temp_urls = set()
        for url in urls:
            new_urls = link_finder(url, log)
            for new_url in new_urls:
                temp_urls.add(new_url)

        for url in temp_urls:
            urls.add(url)

    return urls


def link_finder(target_url, log) -> set[str]:
    urls = set()
    try:
        reqs = get(target_url, headers={"User-Agent": next(random_user_agent(log))}, verify=False, timeout=10)
    except RequestException as exc:
        log.logger("error", f"Unable to crawl {target_url}: {exc}")
        return urls
    origin = urlsplit(target_url)
    # Resolve against the response URL when a same-origin redirect moved the page.
    page_url = reqs.url if isinstance(reqs.url, str) else target_url
    page_origin = urlsplit(page_url)
    if (page_origin.scheme, page_origin.netloc) != (origin.scheme, origin.netloc):
        return urls
    soup = BeautifulSoup(reqs.text, "html.parser")
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if not href or href.startswith("#"):
            continue
        url = urldefrag(urljoin(page_url, href))[0]
        parsed = urlsplit(url)
        if parsed.scheme in ("http", "https") and (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc):
            urls.add(url)

    return urls
