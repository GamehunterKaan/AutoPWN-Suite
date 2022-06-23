from requests import get

from modules.logger import error, banner, colors
from modules.web.crawler import crawl
from modules.web.lfi import TestLFI


def webvuln(target):
    """
    Test for web vulnerabilities
    """
    test_lfi = TestLFI()

    def get_url(target):
        """
        Get the target url
        """
        url_ = f"http://{target}"
        for _ in range(3):
            try:
                get(url_, timeout=10)
            except Exception as e:
                continue
            else:
                return url_

        return None

    target_url = get_url(target)
    if target_url is not None:
        #banner("got url " + target_url)
        banner(f"Testing web application on {target} ...", colors.purple)
        # crawl the target_url
        urls = crawl(target_url)
        # test for lfi
        tested_urls = []
        for url in urls:
            if "?" in url:
                print(f"Testing for LFI on {url}", end="\r")
                tested_urls.append(url)
                test_lfi.test_lfi(url)

        if len(tested_urls) == 0:
            error("No testable URLs found")
