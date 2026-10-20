# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The dashboard dictionary has the same keys in both languages, and every key the pages use exists in it."""

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static"
PAIR = re.compile(r"'([\w.]+)':\s*'((?:[^'\\]|\\.)*)'")


def _dictionary():
    source = (STATIC / "i18n.js").read_text(encoding="utf-8")
    start_en, start_tr = source.index("    en: {"), source.index("    tr: {")
    end_tr = source.index("    },\n  };", start_tr)
    return dict(PAIR.findall(source[start_en:start_tr])), dict(PAIR.findall(source[start_tr:end_tr]))


def test_both_languages_have_the_same_keys_and_no_empty_text():
    english, turkish = _dictionary()
    assert english and set(english) == set(turkish), sorted(set(english) ^ set(turkish))
    assert all(english.values()) and all(turkish.values())


def test_placeholders_match_between_languages():
    english, turkish = _dictionary()
    brace = re.compile(r"\{(\w+)\}")
    assert {key: (brace.findall(english[key]), brace.findall(turkish[key])) for key in english
            if set(brace.findall(english[key])) != set(brace.findall(turkish[key]))} == {}


def test_every_key_the_pages_use_is_in_the_dictionary():
    english, _turkish = _dictionary()
    used = set()
    for name in ("app.js", "web_security.js", "auth.js"):
        used |= set(re.findall(r"\bt\('([\w.]+)'[,)]", (STATIC / name).read_text(encoding="utf-8")))
    for name in ("index.html", "login.html"):
        used |= set(re.findall(r'data-i18n(?:-[a-z-]+)?="([\w.]+)"', (STATIC / name).read_text(encoding="utf-8")))
    missing = sorted(key for key in used if key not in english)
    assert not missing, missing
