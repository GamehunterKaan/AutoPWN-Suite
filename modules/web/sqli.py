from requests import get
from requests import packages


packages.urllib3.disable_warnings()

class SQLIScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = []
        self.sqli_test = "'1"
        self.sql_dbms_errors = [
            "sql syntax",
            "valid mysql result",
            "valid postgresql result",
            "sql server",
            "sybase message",
            "oracle error",
            "microsoft access driver",
            "you have an error",
            "corresponds to your",
            "syntax to use near",
            "sqlite.exception",
        ]

    def exploit_sqli(self, base_url, url_params) -> None:
        for param in url_params:
            param_no_value = param.split("=")[0]
            main_url = f"{base_url}?{param_no_value}"

            if not main_url in self.tested_urls:
                self.tested_urls.append(main_url)
                test_url = f"{main_url}={self.sqli_test}"
            else:
                continue

            try:
                response = get(test_url, verify=False)
            except ConnectionError:
                self.log.logger("error", f"Connection error raised on: {test_url}, skipping")
                return  # Exit if we can't connect

            response_text_lower = response.text.lower()
            for error in self.sql_dbms_errors:
                if error in response_text_lower:
                    self.console.print(
                        f"[red][[/red][green]+[/green][red]][/red]"
                        + f" [white]SQLI :[/white] {test_url}"
                    )
                    return  # Exit after finding the first vulnerability for this URL

    def test_sqli(self, url) -> None:
        """
        Test for SQLI
        """
        try:
            base_url, params = url.split("?")[0], url.split("?")[1]
            params_dict = params.split("&")
            self.exploit_sqli(base_url, params_dict)
        except ConnectionError:
            pass
