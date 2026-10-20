# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Resolve and install the active interface language (gettext)."""

import gettext
import os
from pathlib import Path

from autopwn_suite.paths import data_dir

DOMAIN = "autopwn"
LOCALE_DIR = Path(__file__).resolve().parent / "locales"
SUPPORTED_LANGUAGES = ("en", "tr")
DEFAULT_LANGUAGE = "en"
LANGUAGE_FILE_NAME = "language.txt"


def _language_file():
    return data_dir() / LANGUAGE_FILE_NAME


def _load_saved_language():
    try:
        value = _language_file().read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    return value if value in SUPPORTED_LANGUAGES else None


def _save_language(lang):
    try:
        path = _language_file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(lang, encoding="utf-8")
    except OSError:
        pass


def _detect_system_language():
    # Deliberately only consults these env vars, not locale.getlocale(): that
    # reflects the process's locale state as captured at interpreter startup
    # and does not track later changes to os.environ (breaking test isolation
    # and giving stale results after a real env change within the process).
    lang_code = os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG")
    if not lang_code:
        return None
    primary = lang_code.split("_")[0].split(".")[0].lower()
    return primary if primary in SUPPORTED_LANGUAGES else None


def resolve_language(explicit=None):
    """Resolve the effective language: an explicit CLI choice wins and is
    remembered; otherwise fall back to AUTOPWN_LANG, then the last remembered
    choice, then the system locale, then "en"."""
    if explicit is not None:
        if explicit not in SUPPORTED_LANGUAGES:
            return DEFAULT_LANGUAGE
        _save_language(explicit)
        return explicit
    env_lang = os.environ.get("AUTOPWN_LANG")
    if env_lang in SUPPORTED_LANGUAGES:
        return env_lang
    return _load_saved_language() or _detect_system_language() or DEFAULT_LANGUAGE


def peek_lang_flag(argv):
    """Find a --lang/--language value in argv without a full argparse pass,
    so the language is known before cli() builds (and localizes) the parser."""
    for index, token in enumerate(argv):
        for prefix in ("--lang=", "--language="):
            if token.startswith(prefix):
                return token[len(prefix):]
        if token in ("--lang", "--language") and index + 1 < len(argv):
            return argv[index + 1]
    return None


def install(explicit=None):
    """Resolve the active language and install `_`/`ngettext` into builtins."""
    lang = resolve_language(explicit)
    translation = gettext.translation(
        DOMAIN, localedir=str(LOCALE_DIR), languages=[lang], fallback=True
    )
    translation.install(names=("ngettext",))
    return lang


# Zero-config default so `_()` always resolves to something, even for code
# paths that import modules without ever calling install() (tests, api.py
# used as a library).
gettext.NullTranslations().install(names=("ngettext",))
