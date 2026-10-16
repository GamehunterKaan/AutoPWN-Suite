# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Consistent, reviewable web findings without treating probes as proof."""

from rich.text import Text


def finding(kind, url, evidence, *, parameter=None, severity="low", confidence="candidate", reproduction=None):
    from modules.web.runtime import ACTIVE
    result = {"type": kind, "url": url, "parameter": parameter,
              "severity": severity, "confidence": confidence, "evidence": evidence}
    current = ACTIVE.get()
    return current.annotate(result, reproduction) if current else result


def emit(console, result):
    from modules.web.runtime import ACTIVE, allowed
    current = ACTIVE.get()
    if current:
        if not allowed(result["type"]):
            return
        current.record_finding(result)
    # Target-controlled URLs and evidence must not be parsed as Rich markup.
    console.print(Text(f"[+] {result['type']} ({result['confidence']}, {result['severity']}): "
                       f"{result['url']} — {result['evidence']}"))
