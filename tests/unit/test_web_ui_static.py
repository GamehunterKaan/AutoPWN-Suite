"""
Guard tests for the web UI static assets.

These exist to prevent XSS regressions from creeping back into app.js after
CodeQL alerts #4 (js/incomplete-html-attribute-sanitization) and
#5 (js/xss-through-dom) were fixed.
"""
import re
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parents[2] / "modules" / "web_ui_static" / "app.js"


@pytest.fixture(scope="module")
def app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


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
