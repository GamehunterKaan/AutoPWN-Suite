from bs4 import BeautifulSoup
from modules.random_user_agent import random_user_agent
from requests import get


def crawl(target_url, log) -> set:
    if not target_url.endswith("/"):
        target_url += "/"

    try:
        get(target_url, headers={"User-Agent": next(random_user_agent(log))})
    except ConnectionError:
        log.logger("error", f"Connection error raised.")
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


def link_finder(target_url, log):
    if not target_url.endswith("/"):
        target_url += "/"

    urls = set()

    reqs = get(target_url, headers={"User-Agent": next(random_user_agent(log))})
    soup = BeautifulSoup(reqs.text, "html.parser")
    for link in soup.find_all("a", href=True):
        url = link["href"]
        if url == None or url == "" or "#" in url:
            continue
        if not url.startswith("http"):
            if url.startswith("./"):
                url = f"{target_url}{url.lstrip('./')}"
            elif url.startswith("/"):
                url = f"{target_url}{url.lstrip('/')}"
            else:
                url = f"{target_url}{url}"

            if url not in urls:
                urls.add(url)
        else:
            if url.startswith(target_url):
                if url not in urls:
                    urls.add(url)

    return urls
