# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Consistent, reviewable web findings without treating probes as proof."""

import re

from rich.text import Text

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def printable(value):
    """Drop control characters except newline and tab: a target controls these strings (a Location header, a crawled
    link) and ESC, CR or a C1 code in them would drive the operator's terminal and could forge result lines."""
    return _CONTROL.sub("", value) if isinstance(value, str) else value


def finding(kind, url, evidence, *, parameter=None, severity="low", confidence="candidate", reproduction=None):
    from autopwn_suite.web.runtime import ACTIVE
    result = {"type": kind, "url": printable(url), "parameter": printable(parameter),
              "severity": severity, "confidence": confidence, "evidence": printable(evidence)}
    current = ACTIVE.get()
    return current.annotate(result, reproduction) if current else result


def emit(console, result):
    from autopwn_suite.web.runtime import ACTIVE, allowed
    current = ACTIVE.get()
    if current:
        if not allowed(result["type"]):
            return
        current.record_finding(result)
    # Target-controlled URLs and evidence must not be parsed as Rich markup.
    console.print(Text(f"[+] {result['type']} ({result['confidence']}, {result['severity']}): "
                       f"{result['url']} — {result['evidence']}"))
