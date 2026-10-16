# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Identify reflected payloads in active HTML contexts, without executing JS."""

from random import choices
from string import ascii_letters

from bs4 import BeautifulSoup
from requests import get
from requests.exceptions import RequestException

from modules.web.findings import emit, finding
from modules.web.http import is_html, scoped_get
from modules.web.query import parameter_indexes, probe_url, query_parts
from modules.web.runtime import begin_parameter, finish_parameter, parameter_done


def reflection_context(response, payload, marker):
    if not is_html(response) or payload not in response.text:
        return None
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(True):
        if any(parent.name in ("textarea", "title", "style", "xmp", "noscript", "template") for parent in node.parents):
            continue
        if node.name == "script" and not node.has_attr("src"):
            kind = node.get("type", "").lower().strip()
            if kind in ("", "module", "text/javascript", "application/javascript") and marker in node.get_text():
                return "script element"
        for name, value in node.attrs.items():
            if name.lower().startswith("on") and isinstance(value, str) and marker in value:
                return "HTML event handler"
    return None


class XSSScanner:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = set()
        self.findings = []
        self.xss_test = [
            "<script>alert('PAYLOAD')</script>",
            "<img src=x onerror=\"alert('PAYLOAD')\">",
            "\"><svg onload=\"alert('PAYLOAD')\"></svg>",
            "</textarea><script>alert('PAYLOAD')</script>",
        ]

    def exploit_xss(self, base_url, url_params):
        original = f"{base_url}?{'&'.join(url_params)}"
        found = []
        for index in parameter_indexes(url_params):
            if (original, index) in self.tested_urls or parameter_done("xss", original, index):
                continue
            revision = begin_parameter()
            self.tested_urls.add((original, index))
            for test in self.xss_test:
                marker = "".join(choices(ascii_letters, k=16))
                payload = test.replace("PAYLOAD", marker)
                test_url = probe_url(base_url, url_params, index, payload)
                try:
                    context = reflection_context(scoped_get(get, test_url), payload, marker)
                except RequestException:
                    self.log.logger("error", f"Connection error raised on: {test_url}, skipping")
                    break
                if context:
                    result = finding("XSS", test_url, f"Unescaped reflection in {context}; browser execution not verified",
                                     parameter=url_params[index].split("=", 1)[0], severity="medium",
                                     reproduction={"strategy": "xss_reflection", "marker": marker, "payload": payload,
                                                   "requests": [{"url": test_url, "role": "probe"}]})
                    found.append(result)
                    emit(self.console, result)
                    break
            finish_parameter("xss", original, index, revision)
        self.findings.extend(found)
        return found

    def test_xss(self, url):
        base_url, params = query_parts(url)
        return self.exploit_xss(base_url, params) if params else []
