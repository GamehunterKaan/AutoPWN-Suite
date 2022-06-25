from requests import get

from modules.logger import Logger, banner
from modules.web.crawler import crawl
from modules.web.lfi import TestLFI


def webvuln(target):
    """
    Test for web vulnerabilities
    """
    log = Logger()
    test_lfi = TestLFI()

    def get_url(target):
        """
        Get the target url
        """

        url_ = f"http://{target}"
        for _ in range(3): # do 3 tries
            try:
                get(url_, timeout=10)
            except ConnectionError:
                continue
            else:
                return url_

        return None

    target_url = get_url(target)

    if target_url is None:
        return

    banner(f"Testing web application on {target} ...", "purple")
    urls = crawl(target_url)
    tested_urls = []
    for url in urls: # test for lfi
        if "?" in url:
            print(f"Testing for LFI on {url}", end="\r")
            test_lfi(url)
            tested_urls.append(url)

    if len(tested_urls) == 0:
        log.logger("error", "No testable URLs found")
