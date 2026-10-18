# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import re

from requests import get
from requests.exceptions import RequestException

from autopwn_suite.web.findings import emit, finding
from autopwn_suite.web.http import scoped_get
from autopwn_suite.web.query import parameter_indexes, probe_url, query_parts
from autopwn_suite.web.runtime import begin_parameter, finish_parameter, parameter_done


class SQLIScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = set()
        self.findings = []
        self.sqli_test = "'1"
        # The target controls the body, and re holds the GIL while it matches, so every gap between two words is
        # bounded (an error message keeps its words close together) and the body is cut before matching.
        self.sql_dbms_errors = [
            r"you have an error in your sql syntax",
            r"warning.{0,200}?mysql(?:i)?[_\W]",
            r"postgresql.{0,200}?error|pg_query\(\).{0,200}?failed|psycopg\w*\.errors\.syntaxerror",
            r"unclosed quotation mark after the character string",
            r"microsoft.{0,200}?(?:odbc|oledb).{0,200}?sql server|sqlserverexception",
            r"\bORA-\d{5}\b",
            r"microsoft.{0,200}?(?:jet|access).{0,200}?database",
            r"sqlite(?:3)?\.(?:operationalerror|exception)|sqlite_error|sqlite.{0,200}?syntax error",
            r"syntax error.{0,200}?at or near",
        ]

    def _errors(self, text):
        text = text[:50_000]
        return {pattern for pattern in self.sql_dbms_errors if re.search(pattern, text, re.I)}

    def exploit_sqli(self, base_url, url_params):
        original = f"{base_url}?{'&'.join(url_params)}"
        indexes = [index for index in parameter_indexes(url_params) if (original, index) not in self.tested_urls and not parameter_done("sqli", original, index)]
        if not indexes:
            return []
        try:
            baseline = self._errors(scoped_get(get, original).text)
        except RequestException:
            self.log.logger("error", f"Connection error raised on: {original}, skipping")
            return []
        found = []
        for index in indexes:
            revision = begin_parameter()
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
                                     parameter=url_params[index].split("=", 1)[0], severity="high",
                                     reproduction={"strategy": "sqli_error", "requests": [
                                         {"url": original, "role": "baseline"}, {"url": test_url, "role": "probe"}, {"url": test_url, "role": "repeat"}]})
                    found.append(result)
                    emit(self.console, result)
                    break
            finish_parameter("sqli", original, index, revision)
        self.findings.extend(found)
        return found

    def test_sqli(self, url):
        """Test each query input with bounded, error-based probes."""
        base_url, params = query_parts(url)
        return self.exploit_sqli(base_url, params) if params else []
