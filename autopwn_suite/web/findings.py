# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Consistent, reviewable web findings without treating probes as proof."""

import re

from rich.text import Text

# Tab, line feed and the Unicode line and paragraph separators become one space, so text cannot start a line of its own.
_SINGLE_LINE = str.maketrans({0x09: " ", 0x0A: " ", 0x2028: " ", 0x2029: " "})
_MULTILINE = str.maketrans({0x09: " ", 0x2028: " ", 0x2029: " "})
# Every other character that acts on a terminal or changes how a line is displayed is removed. This includes the
# carriage return, vertical tab, form feed and NEL, which end a line on some terminals and which a URL parser also
# drops, so a URL stays in one piece for `redact_text`.
_REMOVED_RANGES = (
    (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x9F),  # C0 controls other than tab and line feed (ESC, CR), DEL, C1 controls
    (0x061C, 0x061C),  # Arabic letter mark
    (0x200B, 0x200F),  # zero-width space and joiners, left-to-right and right-to-left marks
    (0x202A, 0x202E),  # bidirectional embeddings and overrides
    (0x2060, 0x206F),  # word joiner, invisible operators, bidirectional isolates, deprecated format characters
    (0xFEFF, 0xFEFF),  # byte order mark (zero-width no-break space)
    (0xFFF9, 0xFFFB),  # interlinear annotation
    (0xE0000, 0xE007F),  # tag characters
)
_REMOVED = re.compile("[" + "".join(f"{chr(low)}-{chr(high)}" for low, high in _REMOVED_RANGES) + "]")


def printable(value, *, multiline=False):
    """Make text that a scanned host or a data provider controls safe to print, store and export (a Location header,
    a crawled link, a banner, an NVD description): ESC, a C1 code or a bidirectional override would drive the
    operator's terminal or reorder what it shows, and a line break would start a line of its own, which can forge a
    result line. The default is single-line text; `multiline=True` keeps only "\\n" for the rare field that is
    several lines by nature (NSE script output). Anything that is not a string is returned unchanged."""
    if not isinstance(value, str):
        return value
    return _REMOVED.sub("", value.translate(_MULTILINE if multiline else _SINGLE_LINE))


def finding(kind, url, evidence, *, parameter=None, severity="low", confidence="candidate", reproduction=None):
    from autopwn_suite.web.runtime import ACTIVE, redact_text
    # Evidence can quote a URL the target chose (a Location header): its credential-named query values go, as in `url`.
    result = {"type": kind, "url": printable(url), "parameter": printable(parameter),
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
