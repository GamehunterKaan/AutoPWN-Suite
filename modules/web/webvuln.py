from modules.logger import banner
from modules.web.crawler import crawl
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

        url_ = [f"http://{target}", f"https://{target}"]
        for url in url_:
            for _ in range(3): # do 3 tries
                try:
                    get(url, timeout=10)
                except Exception as e:
                    continue
                else:
                    return url

        return None

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
        log.logger("warning","No testable urls found for current host.")
        return

    banner(f"Testing web application on {target} ...", "purple", console)

    for url in testable_urls:
        LFI.test_lfi(url)
        SQLI.test_sqli(url)
        XSS.test_xss(url)
        tested_urls.append(url)