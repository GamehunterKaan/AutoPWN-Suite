# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Settings > Dashboard account: the form is styled and spaced like the other Settings sections, and
autofilled fields keep the dark theme on the dashboard and on the sign-in page.

These read the shipped HTML and CSS as text, as the other static dashboard tests do, so they run
without Node or a browser.
"""

import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

STATIC = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static"
pytestmark = pytest.mark.unit

FIELDS = {  # id -> (type, autocomplete, label text)
    "account-username": ("text", "username", "Username"),
    "account-current-password": ("password", "current-password", "Current password"),
    "account-password": ("password", "new-password", "New password"),
    "account-confirm-password": ("password", "new-password", "Confirm new password"),
}
AUTOFILL = ":is(input,select,textarea):is(:-webkit-autofill,:autofill)"
LOGIN_AUTOFILL = "input:is(:-webkit-autofill,:autofill)"


def page(name: str) -> BeautifulSoup:
    return BeautifulSoup((STATIC / name).read_text(encoding="utf-8"), "html.parser")


def parse_rules(css: str) -> dict[str, dict[str, str]]:
    """Selector list (whitespace removed) -> declarations of every rule, comments dropped and the rules
    inside an at-rule included."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = {}
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        body = re.sub(r"\s*([:;])\s*", r"\1", body.strip())
        declarations = dict(item.split(":", 1) for item in body.split(";") if item)
        rules.setdefault("".join(selector.split()), {}).update(declarations)
    return rules


def stylesheet(name: str) -> dict[str, dict[str, str]]:
    return parse_rules((STATIC / name).read_text(encoding="utf-8"))


def narrow_rules() -> dict[str, dict[str, str]]:
    css = (STATIC / "styles.css").read_text(encoding="utf-8")
    opening = "@media(max-width:760px){"
    start = css.index(opening) + len(opening)
    depth = 1
    for position in range(start, len(css)):
        depth += {"{": 1, "}": -1}.get(css[position], 0)
        if not depth:
            return parse_rules(css[start:position])
    raise AssertionError("unterminated narrow-viewport block")


def test_every_text_like_control_matches_the_shared_input_rule() -> None:
    """The dashboard styles `input[type=text]` and its siblings, so an input with no type attribute
    falls back to the browser's white box. The account username was one."""
    shared = next(selector for selector in stylesheet("styles.css") if "input[type=text]" in selector)
    styled = set(re.findall(r"input\[type=(\w+)\]", shared))
    assert {"text", "number", "email", "password"} <= styled
    sources = [(STATIC / name).read_text(encoding="utf-8") for name in ("index.html", "web_security.js", "app.js")]
    inputs = [tag for source in sources for tag in BeautifulSoup(source, "html.parser").find_all("input")]
    assert len(inputs) > 30
    for control in inputs:
        kind = control.get("type")
        if kind in ("checkbox", "hidden"):
            continue
        assert kind in styled, f"<input id={control.get('id')!r}> has type {kind!r}, so the shared input rule skips it"


def test_account_fields_are_labelled_grouped_and_use_the_right_autocomplete() -> None:
    form = page("index.html").select_one("form#account-form")
    assert form is not None
    assert "s-form" in form.get("class", [])
    for identifier, (kind, autocomplete, caption) in FIELDS.items():
        field = form.select_one("#" + identifier)
        assert field is not None, identifier
        assert (field.get("type"), field.get("autocomplete")) == (kind, autocomplete), identifier
        label = form.select_one(f"label[for={identifier}]")
        assert label is not None and label.get_text(strip=True) == caption, identifier
        group = field.parent
        assert group is not form and group.name == "div", f"{identifier} sits directly in the form's flex column"
        assert label in group.select(".fl label"), f"{identifier} is not grouped with its caption"
    # Each caption and its field are one flex item, so the form's gap separates fields, not captions.
    assert [child.name for child in form.find_all(recursive=False)] == ["div"] * 4
    assert form.find_all(recursive=False)[-1].get("class") == ["s-actions"]


def test_account_form_uses_the_vertical_rhythm_of_the_settings_sections() -> None:
    rules = stylesheet("styles.css")
    shared = rules[".s-section,.s-form"]
    assert shared["display"] == "flex" and shared["flex-direction"] == "column"
    assert re.fullmatch(r"\d+px", shared["gap"]), "the form needs a gap of its own: only the section has one"
    form = page("index.html").select_one("form#account-form")
    actions = form.select_one(".s-actions")
    assert actions is not None
    assert [child.name for child in actions.find_all(recursive=False)] == ["button", "p"]
    button, message = actions.find_all(recursive=False)
    assert button.get("id") == "account-save" and button.get("type") == "submit"
    assert button.get_text(strip=True) == "Update account"
    # The status line stays a live region that exists before its first message, and sits beside the button:
    # an empty line of its own would add a second gap above the button.
    assert (message.get("id"), message.get("role"), message.get("aria-live")) == ("account-message", "status", "polite")
    assert rules[".s-actions[role=status]"]["align-self"] == "center"


def test_account_new_password_pair_stacks_on_a_narrow_viewport_with_the_same_gap() -> None:
    """Side by side below 760 px the new-password placeholder is cut to "Leave blank to keep"."""
    stacked = narrow_rules()[".s-form.row2"]
    assert stacked["grid-template-columns"] == "1fr"
    assert stacked["row-gap"] == "inherit", "reuse the form's gap instead of repeating the number"


def test_autofilled_dashboard_fields_keep_the_dark_input_colours() -> None:
    rules = stylesheet("styles.css")
    shared = next(declarations for selector, declarations in rules.items() if "input[type=text]" in selector)
    assert AUTOFILL in rules, "no autofill rule for the dashboard's inputs, selects and text areas"
    autofill = rules[AUTOFILL]
    assert autofill["background-color"] == shared["background"] == "var(--bg3)"
    assert autofill["-webkit-text-fill-color"] == autofill["caret-color"] == shared["color"] == "var(--text)"
    assert autofill["box-shadow"] == "inset 0 0 0 100vmax " + shared["background"]
    assert autofill["filter"] == "none"
    # A selector list holding a name the browser does not know is dropped whole, so each name stays inside :is().
    assert [selector for selector in rules if "autofill" in selector] == [AUTOFILL]


def test_autofilled_sign_in_fields_keep_the_dark_input_colours() -> None:
    rules = stylesheet("login.css")
    field = rules["input"]
    assert LOGIN_AUTOFILL in rules, "no autofill rule on the sign-in page"
    autofill = rules[LOGIN_AUTOFILL]
    assert autofill["background-color"] == field["background"]
    assert autofill["-webkit-text-fill-color"] == autofill["caret-color"] == field["color"]
    assert autofill["box-shadow"] == "inset 0 0 0 100vmax " + field["background"]
    assert autofill["filter"] == "none"
    assert [selector for selector in rules if "autofill" in selector] == [LOGIN_AUTOFILL]
    login = page("login.html")
    assert login.select_one("#login-username")["autocomplete"] == "username"
    assert login.select_one("#login-password")["autocomplete"] == "current-password"
