import re

from requests import get
from requests.exceptions import RequestException

from modules.web.findings import emit, finding
from modules.web.http import scoped_get
from modules.web.query import parameter_indexes, probe_url, query_parts

class SQLIScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = set()
        self.findings = []
        self.sqli_test = "'1"
        self.sql_dbms_errors = [
            r"you have an error in your sql syntax",
            r"warning.*?mysql(?:i)?[_\W]",
            r"postgresql.*?error|pg_query\(\).*?failed|psycopg\w*\.errors\.syntaxerror",
            r"unclosed quotation mark after the character string",
            r"microsoft.*?(?:odbc|oledb).*?sql server|sqlserverexception",
            r"\bORA-\d{5}\b",
            r"microsoft.*?(?:jet|access).*?database",
            r"sqlite(?:3)?\.(?:operationalerror|exception)|sqlite_error|sqlite.*?syntax error",
            r"syntax error.*?at or near",
        ]

    def _errors(self, text):
        return {pattern for pattern in self.sql_dbms_errors if re.search(pattern, text, re.I)}

    def exploit_sqli(self, base_url, url_params):
        original = f"{base_url}?{'&'.join(url_params)}"
        indexes = [index for index in parameter_indexes(url_params) if (original, index) not in self.tested_urls]
        if not indexes:
            return []
        try:
            baseline = self._errors(scoped_get(get, original).text)
        except RequestException:
            self.log.logger("error", f"Connection error raised on: {original}, skipping")
            return []
        found = []
        for index in indexes:
            self.tested_urls.add((original, index))
            for payload in (self.sqli_test, "'", '"'):
                test_url = probe_url(base_url, url_params, index, payload)
                try:
                    new_errors = self._errors(scoped_get(get, test_url).text) - baseline
                    if not new_errors:
                        continue
                    repeated = self._errors(scoped_get(get, test_url).text) - baseline
                except RequestException:
                    self.log.logger("error", f"Connection error raised on: {test_url}, skipping")
                    break
                if new_errors & repeated:
                    result = finding("SQLI", test_url, "Repeatable database error absent from the baseline",
                                     parameter=url_params[index].split("=", 1)[0], severity="high")
                    found.append(result)
                    emit(self.console, result)
                    break
        self.findings.extend(found)
        return found

    def test_sqli(self, url):
        """Test each query input with bounded, error-based probes."""
        base_url, params = query_parts(url)
        return self.exploit_sqli(base_url, params) if params else []
