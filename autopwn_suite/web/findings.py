# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Consistent, reviewable web findings without treating probes as proof."""

from rich.text import Text

from autopwn_suite.text import printable, wire_url


def finding(kind, url, evidence, *, parameter=None, severity="low", confidence="candidate", reproduction=None):
    from autopwn_suite.web.runtime import ACTIVE, redact_text
    # Evidence can quote a URL the target chose (a Location header): its credential-named query values go, as in `url`.
    result = {"type": kind, "url": wire_url(url), "parameter": printable(parameter),
              "severity": severity, "confidence": confidence,
              "evidence": redact_text(evidence, names_only=True) if isinstance(evidence, str) else evidence}
    current = ACTIVE.get()
    return current.annotate(result, reproduction) if current else result


def emit(console, result):
    from autopwn_suite.web.runtime import ACTIVE, allowed
    current = ACTIVE.get()
    if current:
        if not allowed(result["type"]):
            return
        current.record_finding(result)
    # Target-controlled URLs and evidence must not be parsed as Rich markup, and the line must stay one line.
    console.print(Text(printable(f"[+] {result['type']} ({result['confidence']}, {result['severity']}): "
                                 f"{result['url']} — {result['evidence']}")))
