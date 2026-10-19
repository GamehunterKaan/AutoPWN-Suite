# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Conservative boolean comparisons without timing probes or data extraction."""

from html import escape
from secrets import randbelow
from urllib.parse import parse_qsl, quote, urlsplit

from requests.exceptions import RequestException

from autopwn_suite.web.findings import emit, finding
from autopwn_suite.web.query import parameter_indexes, probe_url, query_parts
from autopwn_suite.web.runtime import begin_parameter, finish_parameter, parameter_done
from autopwn_suite.web.similarity import similarity as _similar
from autopwn_suite.web.sqli import SQLIScanner


def _shape(response, url, payload=""):
    text = response.text[:100_000]
    # Remove complete reflected probes, not arbitrary short tokens or results.
    values = [url, urlsplit(url).query]
    if payload:
        values.extend([payload, quote(payload, safe="%/"), escape(payload), escape(payload, quote=False)])
    for value in sorted(set(values), key=len, reverse=True):
        if len(value) > 4:
            text = text.replace(value, "{probe}")
    return text


def _kind(response):
    return response.status_code, response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()


class BooleanSQLIScanner:
    def __init__(self, client, console, *, max_parameters=5):
        self.client = client
        self.console = console
        self.max_parameters = max_parameters
        self.tested = set()
        self.errors = SQLIScanner(client.log, console)

    def test(self, url):
        base, params = query_parts(url)
        indexes = [index for index in parameter_indexes(params) if not parameter_done("boolean_sqli", url, index)]
        if not indexes:
            return []
        if len(indexes) > self.max_parameters:
            self.client.log.logger("warning", f"Boolean SQLi parameter budget reached on {url}; coverage is limited.")
        try:
            baseline = self.client.baseline(url)
            repeated = self.client.send(url)
        except RequestException:
            self.client.log.logger("warning", f"Boolean SQLi baseline incomplete on {url}.")
            return []
        status = baseline.status_code
        if not 200 <= status < 300 or _kind(repeated) != _kind(baseline):
            return []
        if getattr(baseline, "autopwn_truncated", False) or getattr(repeated, "autopwn_truncated", False):
            self.client.log.logger("warning", f"Boolean SQLi baseline incomplete on {url}: response size limit reached.")
            return []
        baseline_text = _shape(baseline, url)
        if _similar(baseline_text, _shape(repeated, url)) < .98 or self.errors._errors(baseline.text):
            self.client.log.logger("info", f"Boolean SQLi skipped: unstable or error baseline on {url}.")
            return []
        found = []
        for index in indexes[:self.max_parameters]:
            if (url, index) in self.tested:
                continue
            revision = begin_parameter()
            self.tested.add((url, index))
            original = parse_qsl(params[index], keep_blank_values=True)[0][1]
            for suffix in ("", "'", '"'):
                false_texts, true_urls = [], []
                comparison_requests = [{"url": url, "role": "baseline"}, {"url": url, "role": "baseline_repeat"}]
                try:
                    nonce = 10000 + randbelow(90000)
                    for number in (nonce, nonce + 100000):
                        comment = "-- " if suffix else ""
                        true = f"{original}{suffix} AND {number}={number}{comment}"
                        false = f"{original}{suffix} AND {number}={number + 1}{comment}"
                        true_url = probe_url(base, params, index, true)
                        false_url = probe_url(base, params, index, false)
                        true_response = self.client.send(true_url)
                        false_response = self.client.send(false_url)
                        comparison_requests.extend([{ "url": true_url, "role": "true"}, {"url": false_url, "role": "false"}])
                        if any(_kind(response) != _kind(baseline) or getattr(response, "autopwn_truncated", False)
                               or self.errors._errors(response.text) for response in (true_response, false_response)):
                            break
                        if _similar(baseline_text, _shape(true_response, true_url, true)) < .98:
                            break
                        false_text = _shape(false_response, false_url, false)
                        if _similar(baseline_text, false_text) > .85:
                            break
                        false_texts.append(false_text)
                        true_urls.append(true_url)
                except RequestException:
                    self.client.log.logger("warning", f"Boolean SQLi probes incomplete on {url}.")
                    break
                if len(false_texts) == 2 and _similar(*false_texts) >= .98:
                    result = finding("SQLI_BOOLEAN", true_urls[0], "Two distinct true/false pairs changed results consistently against a stable baseline; no data was extracted",
                                     parameter=params[index].split("=", 1)[0], severity="high",
                                     reproduction={"strategy": "boolean_sqli", "requests": comparison_requests})
                    found.append(result)
                    emit(self.console, result)
                    break
            finish_parameter("boolean_sqli", url, index, revision)
        return found
