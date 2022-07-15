from bs4 import BeautifulSoup
from modules.random_user_agent import random_user_agent
from requests import get


def crawl(target_url, log) -> set:
    if not target_url.endswith("/"):
        target_url += "/"

    for tries in range(3):
        try:
            reqs = get(
                target_url, headers={
                    "User-Agent": next(random_user_agent(log))
                }
            )
            soup = BeautifulSoup(reqs.text, "html.parser")
        except ConnectionError:
            if tries < 3:
                log.logger(
                    "error",
                    f"Connection error raised, retrying again: {tries}."
                )
                continue
            else:
                log.logger(
                    "error",
                    "Connection error raised, reached a maximum of 3 tries."
                )
                raise SystemExit

    log.logger(
        "info", 
        f"Crawling web application at {target_url} ..."
    )

    urls = set()
    for link in soup.find_all("a", href=True):
        url = link["href"]
        if url == None:
            continue
        if not url.startswith("http"):
            if "#" in url or url is None or url == "":
                continue
            elif url.startswith("./"):
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

    temp_urls = set()
    # ^^^ to prevent "RuntimeError: Set changed size during iteration"

    if len(urls) < 10:
        for each_url in urls:
            try:
                reqs = get(each_url)
                soup = BeautifulSoup(reqs.text, "html.parser")
            except ConnectionError:
                log.logger(
                    "error",
                    f"Connection error raised on: {each_url}, skipping ..."
                )
                continue
            else:
                for link in soup.find_all("a", href=True):
                    url = link["href"]
                    if url == "" or url is None or "#" in url:
                        continue

                    if not url.startswith("http"):
                        if url.startswith("./"):
                            url = f"{each_url}{url.lstrip('./')}"
                        elif url.startswith("/"):
                            url = f"{each_url}{url.lstrip('/')}"
                        else:
                            url = f"{each_url}{url}"

                        if url not in urls:
                            temp_urls.add(url)
                    else:
                        if url.startswith(each_url):
                            if url not in urls:
                                temp_urls.add(url)
    for url in temp_urls:
        urls.add(url)

    return urls