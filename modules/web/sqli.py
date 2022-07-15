from requests import get


class TestSQLI:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.sqli_test = "'"
        self.sql_dbms_errors = [
            "sql syntax",
            "valid mysql result",
            "valid postgresql result",
            "sql server",
            "sybase message",
            "oracle error",
            "microsoft access driver",
            "you have an error"
            "corresponds to your",
            "syntax to use near",
            "sqlite.exception",
        ]

    def exploit_sqli(self, base_url, url_params) -> None:
        for param in url_params:
            test_url = f"{base_url}?{param}={self.sqli_test}"

            try:
                response = get(test_url)
            except ConnectionError:
                self.log.logger(
                    "errro",
                    f"Connection error raised on: {test_url}, skipping"
                )
            else:
                for error in self.sql_dbms_errors:
                    if response.text.find(error) != -1:
                        self.console.print(
                            f"[red][[/red][green]+[/green][red]][/red]"
                            + f" [white]SQLI :[/white] {test_url}"
                        )
                        break


    def test_sqli(self, url) -> None:
        """
        Test for SQLI
        """
        base_url, params = url.split("?")[0], url.split("?")[1]
        params_dict = params.split("&")
        self.exploit_sqli(base_url, params_dict)