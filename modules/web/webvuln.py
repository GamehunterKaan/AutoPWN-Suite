from requests import get
from modules.logger import error, banner, colors
from modules.web.crawler import crawl
from modules.web.lfi import test_lfi

def get_url(target):
    """
    Get the target url
    """
    request = get("http://" + target)
    if request.status_code == 200:
        return "http://" + target
    
    request = get("https://" + target)
    if request.status_code == 200:
        return "https://" + target

    return None

def webvuln(target):
    """
    Test for web vulnerabilities
    """
    target_url = get_url(target)
    #banner("got url " + target_url)
    banner("Testing web application on " + target + "...", colors.purple)
    # crawl the target_url
    urls = crawl(target_url)
    # test for lfi
    tested_urls = []
    for url in urls:
        if "?" in url:
            print("Testing for LFI on " + url, end="\r")
            tested_urls.append(url)
            test_lfi(url)
    
    if len(tested_urls) == 0:
        error("No testable URLs found")