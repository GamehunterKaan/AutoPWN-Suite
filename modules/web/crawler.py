from requests import get

from bs4 import BeautifulSoup
from modules.random_user_agent import random_user_agent


def crawl(target_url):
    if not target_url.endswith("/"):
        target_url += "/"

    reqs = get(
            target_url, headers={
                    "User-Agent": next(random_user_agent())
                }
        )
    soup = BeautifulSoup(reqs.text, "html.parser")

    urls = set()
    for link in soup.find_all("a", href=True):
        url = link["href"]

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

    if len(urls) < 10:
        for each_url in urls:
            reqs = get(each_url)
            soup = BeautifulSoup(reqs.text, "html.parser")

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
                        urls.add(url)
                else:
                    if url.startswith(each_url):
                        if url not in urls:
                            urls.add(url)

    return urls
