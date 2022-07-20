from modules.logger import banner
from modules.random_user_agent import random_user_agent
from modules.web.crawler import crawl
from modules.web.dirbust import dirbust
from modules.web.lfi import TestLFI
from modules.web.sqli import TestSQLI
from modules.web.xss import TestXSS
from requests import get


def webvuln(target, log, console) -> None:
    """
    Test for web vulnerabilities
    """

    LFI = TestLFI(log, console)
    SQLI = TestSQLI(log, console)
    XSS = TestXSS(log, console)

    def get_url(target):
        """
        Get the target url
        """
        headers = {"User-Agent": next(random_user_agent(log))}
        url_ = [f"http://{target}/", f"https://{target}/"]
        for url in url_:
            try:
                get(url, headers=headers, timeout=10)
            except Exception as e:
                return None
            else:
                return url

    target_url = get_url(target)

    if target_url is None:
        return

    urls = crawl(target_url, log)
    tested_urls, testable_urls = [], []
    for url in urls:
        if "?" in url:
            testable_urls.append(url)

    log.logger("info", f"Found {len(testable_urls)} testable urls.")

    if len(testable_urls) == 0:
        return

    banner(f"Testing web application on {target} ...", "purple", console)

    dirbust(target_url, console, log)

    for url in testable_urls:
        LFI.test_lfi(url)
        SQLI.test_sqli(url)
        XSS.test_xss(url)
        tested_urls.append(url)
