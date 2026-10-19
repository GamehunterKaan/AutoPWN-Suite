# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Guard tests for the web UI static assets.

These exist to prevent XSS regressions from creeping back into app.js after
CodeQL alerts #4 (js/incomplete-html-attribute-sanitization) and
#5 (js/xss-through-dom) were fixed.
"""
import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

STATIC = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static"
APP_JS = STATIC / "app.js"


@pytest.fixture(scope="module")
def app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index_page() -> BeautifulSoup:
    return BeautifulSoup((STATIC / "index.html").read_text(encoding="utf-8"), "html.parser")


@pytest.mark.unit
def test_esc_function_escapes_all_five_chars(app_js: str) -> None:
    """esc() must escape &, <, >, ", and '."""
    match = re.search(r"function esc\([^)]*\)\s*\{[^}]*\}", app_js)
    assert match, "esc() function not found in app.js"
    body = match.group(0)
    for char in ("&", "<", ">", '"', "'"):
        assert char in body, f"esc() is missing an escape for {char!r}"


@pytest.mark.unit
def test_no_inline_handlers_with_template_injection(app_js: str) -> None:
    """Inline event handlers with ${...} injection are HTML-decoded then JS-parsed,
    so HTML-escaping cannot protect them. Use data-action + delegated listener."""
    bad = re.findall(r'on\w+="[^"]*\$\{', app_js)
    assert not bad, f"inline event handlers with template injection: {bad}"


def css_rule(selector: str) -> str:
    """The declarations of the first rule whose selector list is exactly `selector`."""
    css = (STATIC / "styles.css").read_text(encoding="utf-8")
    match = re.search(r"(?:^|\})\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, f"no {selector} rule in styles.css"
    return match.group(1)


@pytest.mark.unit
def test_the_faded_toast_never_intercepts_clicks() -> None:
    """The toast stays in the page (it is a live region) and only fades to opacity 0, so it must not
    receive pointer events or it blocks the corner of the page it sits over."""
    rule = css_rule(".toast")
    assert "pointer-events:none" in rule.replace(" ", "")
    assert re.search(r"opacity:\s*0", rule), "a toast that has not shown anything must start transparent"


@pytest.mark.unit
def test_toast_is_a_polite_live_region_that_exists_before_its_first_message(app_js: str, index_page: BeautifulSoup) -> None:
    """Assistive technology only announces changes to a live region that was already in the page, so the
    toast element ships in index.html with its role and toast() fills it instead of creating one."""
    toast = index_page.select_one("#toast-el")
    assert toast is not None, "index.html has no pre-created #toast-el"
    assert toast.get("role") == "status"
    assert toast.get("aria-live") == "polite"
    assert toast.get("aria-atomic") == "true"
    assert "toast" in toast.get("class", [])
    assert not toast.get_text(strip=True)
    body = re.search(r"function toast\(.*?\n\}", app_js, re.S)
    assert body, "toast() not found in app.js"
    assert "createElement" not in body.group(0), "toast() must not create its own, unannounced element"
