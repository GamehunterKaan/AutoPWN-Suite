# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Text that a scanned host or a data provider controls (a header, a link, a banner, a description) can carry
characters that drive the operator's terminal or start a line of its own. This module has no package imports, so
every module that prints, stores or sends such text can use it."""

import re
from urllib.parse import quote

# Tab, line feed and the Unicode line and paragraph separators become one space, so text cannot start a line of its own.
_SINGLE_LINE = str.maketrans({0x09: " ", 0x0A: " ", 0x2028: " ", 0x2029: " "})
_MULTILINE = str.maketrans({0x09: " ", 0x2028: " ", 0x2029: " "})
# Every other character that acts on a terminal or changes how a line is displayed is removed. This includes the
# carriage return, vertical tab, form feed and NEL, which end a line on some terminals and which a URL parser also
# drops, so a URL stays in one piece for `redact_text`.
_REMOVED_RANGES = (
    (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x9F),  # C0 controls other than tab and line feed (ESC, CR), DEL, C1 controls
    (0x061C, 0x061C),  # Arabic letter mark
    (0x180E, 0x180E),  # Mongolian vowel separator (zero-width)
    (0x200B, 0x200F),  # zero-width space and joiners, left-to-right and right-to-left marks
    (0x202A, 0x202E),  # bidirectional embeddings and overrides
    (0x2060, 0x206F),  # word joiner, invisible operators, bidirectional isolates, deprecated format characters
    (0xFEFF, 0xFEFF),  # byte order mark (zero-width no-break space)
    (0xFFF9, 0xFFFB),  # interlinear annotation
    (0xE0000, 0xE007F),  # tag characters
    (0xD800, 0xDFFF),  # unpaired surrogates, which a UTF-8 stream cannot encode (a JSON escape in provider text makes one)
)


def _characters(ranges):
    return re.compile("[" + "".join(f"{chr(low)}-{chr(high)}" for low, high in ranges) + "]")


_REMOVED = _characters(_REMOVED_RANGES)
# In a URL the same characters stay (replay and a PoC must send the request that the scan sent) as percent-encoding.
_ENCODED = _characters(_REMOVED_RANGES + ((0x09, 0x0A), (0x2028, 0x2029)))


def printable(value, *, multiline=False):
    """Make text that a scanned host or a data provider controls safe to print, store and export (a Location header,
    a crawled link, a banner, an NVD description): ESC, a C1 code or a bidirectional override would drive the
    operator's terminal or reorder what it shows, and a line break would start a line of its own, which can forge a
    result line. The default is single-line text; `multiline=True` keeps only "\\n" for the rare field that is
    several lines by nature (NSE script output). Anything that is not a string is returned unchanged."""
    if not isinstance(value, str):
        return value
    return _REMOVED.sub("", value.translate(_MULTILINE if multiline else _SINGLE_LINE))


def wire_url(value):
    """A URL that a host controls, with every character that `printable` would remove or turn into a space
    percent-encoded the way the HTTP client sends it. Removing them would change the request that a replay or a PoC
    sends; encoded, the stored URL names the same request and is plain text. A value that is not a string is
    returned unchanged."""
    if not isinstance(value, str):
        return value
    return _ENCODED.sub(lambda match: quote(match[0], safe="", errors="surrogatepass"), value)
