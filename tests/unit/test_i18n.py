# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Language resolution and gettext bootstrap, without touching real locale files."""
import builtins
import subprocess
import sys

from autopwn_suite import i18n


def test_peek_lang_flag_finds_space_separated_value():
    assert i18n.peek_lang_flag(["--target", "1.2.3.4", "--lang", "tr"]) == "tr"


def test_peek_lang_flag_finds_equals_form():
    assert i18n.peek_lang_flag(["--language=tr", "-v"]) == "tr"


def test_peek_lang_flag_returns_none_when_absent():
    assert i18n.peek_lang_flag(["--target", "1.2.3.4"]) is None


def test_peek_lang_flag_ignores_a_dangling_flag_with_no_value():
    assert i18n.peek_lang_flag(["--lang"]) is None


def test_resolve_language_defaults_to_english_when_nothing_set(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_MESSAGES", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    assert i18n.resolve_language(None) == "en"


def test_resolve_language_remembers_an_explicit_choice(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    assert i18n.resolve_language("tr") == "tr"
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_MESSAGES", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    assert i18n.resolve_language(None) == "tr"


def test_resolve_language_creates_a_missing_data_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path / "not" / "yet" / "created"))
    assert i18n.resolve_language("tr") == "tr"
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_MESSAGES", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    assert i18n.resolve_language(None) == "tr"


def test_resolve_language_explicit_choice_overrides_a_saved_one(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    i18n.resolve_language("tr")
    assert i18n.resolve_language("en") == "en"
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    assert i18n.resolve_language(None) == "en"


def test_resolve_language_rejects_unsupported_explicit_choice(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    assert i18n.resolve_language("de") == "en"


def test_an_unsupported_explicit_choice_does_not_overwrite_the_remembered_language(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    i18n.resolve_language("tr")
    assert i18n.resolve_language("de") == "en"
    assert (tmp_path / i18n.LANGUAGE_FILE_NAME).read_text(encoding="utf-8") == "tr"


def test_an_unreadable_language_file_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    for name in ("AUTOPWN_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / i18n.LANGUAGE_FILE_NAME).write_bytes(b"\xff\xfe\x00tr")
    assert i18n.resolve_language(None) == "en"


def test_resolve_language_env_var_takes_precedence_over_saved_choice(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    i18n.resolve_language("tr")
    monkeypatch.setenv("AUTOPWN_LANG", "en")
    assert i18n.resolve_language(None) == "en"


def test_resolve_language_detects_system_locale(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    monkeypatch.setenv("LANG", "tr_TR.UTF-8")
    assert i18n.resolve_language(None) == "tr"


def test_install_falls_back_to_identity_when_mo_is_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    lang = i18n.install("en")
    assert lang == "en"
    assert builtins._("hello") == "hello"


def test_the_default_translator_exists_for_a_module_imported_on_its_own():
    code = (
        "import builtins\n"
        "from autopwn_suite import update_checker\n"
        "assert hasattr(builtins, '_') and builtins._('x') == 'x'\n"
        "try:\n"
        "    update_checker.check_release('v', 'owner/name', None)\n"
        "except Exception as error:\n"
        "    assert not isinstance(error, NameError), error\n"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_a_remembered_choice_wins_over_the_system_locale(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AUTOPWN_LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_MESSAGES", raising=False)
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    i18n.resolve_language("tr")
    assert i18n.resolve_language(None) == "tr"
