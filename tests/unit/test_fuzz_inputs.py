# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Seeded mutation fuzzing of every parser and validator that handles untrusted input.

These run in the normal suite (and therefore in CI on every change). A failure means an
untrusted input reached an exception the code does not document, or a validator accepted
something it must reject. Seeds are fixed so a failure is reproducible.
"""

import importlib
import json
import random
import re
import sqlite3
import string
import sys
import zlib
from contextlib import closing
from types import SimpleNamespace

import pytest
from rich.text import Text

from autopwn_suite.logger import markup_safe
from autopwn_suite.nmap_backend import parse_nmap_xml
from autopwn_suite.vulnerability_db import SCHEMA_VERSION, DatabaseUnavailable, OfflineDatabase
from autopwn_suite.web.options import normalize_options
from autopwn_suite.web_auth import ACCOUNT_FILE, password_matches, validate_account

SEED = 20261016
VALID_XML = (
    '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 192.0.2.10"><host>'
    '<status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>'
    '<hostnames><hostname name="example.test" type="user"/></hostnames><ports>'
    '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
    '<service name="http" product="nginx" version="1.24.0"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service></port>'
    '</ports></host><runstats><finished time="2" elapsed="1.2" exit="success"/>'
    '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
)
JUNK = ["", "<", ">", "&", "&#0;", "&#x110000;", "<!DOCTYPE x [<!ENTITY a 'b'>]>", "\x00", "\ud800", "9" * 40, "-1", "]]>", "<![CDATA["]


def mutate(text, rng):
    chars = list(text)
    for _ in range(rng.randint(1, 6)):
        action = rng.choice(["delete", "insert", "truncate", "duplicate", "swap"])
        position = rng.randrange(len(chars) + 1) if chars else 0
        if action == "delete" and chars:
            del chars[rng.randrange(len(chars))]
        elif action == "insert":
            chars[position:position] = list(rng.choice(JUNK))
        elif action == "truncate" and chars:
            del chars[rng.randrange(len(chars)):]
        elif action == "duplicate" and chars:
            start = rng.randrange(len(chars))
            chars[position:position] = chars[start:start + rng.randint(1, 40)]
        elif action == "swap" and len(chars) > 1:
            first, second = rng.randrange(len(chars)), rng.randrange(len(chars))
            chars[first], chars[second] = chars[second], chars[first]
    return "".join(chars)


def random_value(rng, depth=0):
    kinds = ["int", "str", "bool", "none", "float", "list", "dict"] if depth < 2 else ["int", "str", "bool", "none"]
    kind = rng.choice(kinds)
    if kind == "int":
        return rng.choice([0, 1, -1, 2**63, -(2**63), rng.randint(-10**6, 10**6)])
    if kind == "str":
        return "".join(rng.choice(string.printable + "é€\u0000") for _ in range(rng.randint(0, 30)))
    if kind == "bool":
        return rng.random() < .5
    if kind == "none":
        return None
    if kind == "float":
        return rng.choice([0.5, float("inf"), float("nan"), -1e308])
    if kind == "list":
        return [random_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {str(random_value(rng, 2)) if rng.random() < .3 else rng.choice(["checks", "speed", "timeout", "verify_tls", "x"]): random_value(rng, depth + 1)
            for _ in range(rng.randint(0, 4))}


def test_baseline_xml_is_valid():
    assert parse_nmap_xml(VALID_XML)


def test_banner_and_cve_text_survives_rich_markup_parsing_unchanged():
    rng = random.Random(SEED)
    pieces = list("[]/#@ab-=_ ") + ["[/", "[b]", "[/b]", "[red]", "[/red]", "[/]", "[@click=x]", "[#ff0000]"]
    for _ in range(2000):
        value = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
        assert Text.from_markup(markup_safe(value), emoji=False).plain == value, value
        assert Text.from_markup(f"[red]{markup_safe(value)}[/red]", emoji=False).plain == value, value
        assert Text.from_markup(f"[yellow]{markup_safe(f'[ {value} ]')}[/yellow]", emoji=False).plain == f"[ {value} ]", value
    # Rich drops one backslash before a bracket that is not a tag, so only require that
    # backslashes never turn escaped text back into markup that raises.
    pieces += ["\\", "\\[", "\\\\", "\\[/b]"]
    for _ in range(2000):
        value = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
        Text.from_markup(markup_safe(value), emoji=False)
        Text.from_markup(f"[red]{markup_safe(value)}[/red]", emoji=False)
        Text.from_markup(f"[yellow]{markup_safe(f'[ {value} ]')}[/yellow]", emoji=False)


def test_nmap_xml_parser_only_raises_its_documented_error():
    rng = random.Random(SEED)
    rejected = accepted = 0
    for _ in range(1500):
        document = mutate(VALID_XML, rng)
        try:
            parse_nmap_xml(document)
            accepted += 1
        except RuntimeError:
            rejected += 1
    assert rejected and accepted  # the corpus exercises both outcomes


def test_web_option_schema_only_raises_value_error():
    rng = random.Random(SEED + 1)
    for _ in range(1500):
        candidate = random_value(rng)
        existing = random_value(rng) if rng.random() < .3 else None
        try:
            result = normalize_options(candidate, existing)
        except ValueError:
            continue
        assert isinstance(result["verify_tls"], bool)
        assert all(isinstance(result[name], int) and not isinstance(result[name], bool) for name in result if name not in ("checks", "verify_tls"))


def test_copied_mirror_records_only_raise_database_unavailable(tmp_path):
    """A mirror is copied between machines, so its stored records are untrusted input to the lookup."""
    path = tmp_path / "vulnerabilities.sqlite3"
    description = "OpenSSH 8.2p1 has a possible vulnerability"
    base = {"cve": {"id": "CVE-2025-1234", "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                        "baseScore": 7.5, "baseSeverity": "HIGH"}, "exploitabilityScore": 3.9}]},
                    "configurations": [{"nodes": []}], "references": [{"url": "https://example.com/advisory"}]}}
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(f"""
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE cves (id TEXT PRIMARY KEY, year INTEGER NOT NULL, description TEXT NOT NULL, record BLOB NOT NULL);
            INSERT INTO metadata VALUES ('ready', 'true'), ('count', '1'), ('updated_at', '2026-01-01');
            PRAGMA user_version = {SCHEMA_VERSION};
        """)
        connection.execute("INSERT INTO cves VALUES ('CVE-2025-1234', 2025, ?, x'00')", (description.casefold(),))
        connection.commit()
    rng = random.Random(SEED + 50)
    junk = [None, True, 0, -1, 2**70, 1.5, float("nan"), "", "x", [], ["x"], {}, {"a": 1}, [[[]]],
            {"lang": "en", "value": 5}, {"cvssData": []}]

    def corrupt(node):
        if rng.random() < .15:
            return rng.choice(junk)
        if isinstance(node, dict):
            return {key: corrupt(value) for key, value in node.items()}
        if isinstance(node, list):
            return [corrupt(value) for value in node]
        return node

    accepted = rejected = 0
    for _ in range(400):
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("UPDATE cves SET record = ?", (zlib.compress(json.dumps(corrupt(base)).encode()),))
            connection.commit()
        with closing(OfflineDatabase(path)) as local:
            try:
                findings = local.search("OpenSSH 8.2p1")
            except DatabaseUnavailable:
                rejected += 1
                continue
        accepted += 1
        assert all(isinstance(value, str) for finding in findings
                   for value in (finding.CVEID, finding.description, finding.severity))
    assert accepted and rejected  # the corpus exercises both outcomes


@pytest.fixture
def web_ui(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    sys.modules.pop("autopwn_suite.web_ui", None)
    module = importlib.import_module("autopwn_suite.web_ui")
    module._load_settings()
    app = module._build_app(module._STATIC_DIR)
    app.config["TESTING"] = True
    password = re.search(r"  Password: (\S+)", capsys.readouterr().out)[1]
    return SimpleNamespace(module=module, app=app, password=password, path=tmp_path / ACCOUNT_FILE)


def test_target_and_flag_allowlists_never_raise_and_reject_shell_syntax(web_ui):
    rng = random.Random(SEED + 2)
    alphabet = string.printable + "éß \u0000;|&`$(){}"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        for check in (web_ui.module._validate_target, web_ui.module._validate_nmap_flags):
            verdict = check(text)
            assert verdict is None or isinstance(verdict, str)
            if verdict is None:
                assert not set(text) & web_ui.module._SHELL_DANGEROUS
    for value in (None, 1, 1.5, [], {}, b"x", True):
        assert isinstance(web_ui.module._validate_target(value), str)
        assert isinstance(web_ui.module._validate_nmap_flags(value), (str, type(None)))


def test_event_stream_resume_point_is_the_first_short_ascii_number_and_never_raises(web_ui):
    rng = random.Random(SEED + 5)
    accepted = rejected = 0
    for _ in range(3000):
        candidates = []
        for _ in range(rng.randint(0, 3)):
            kind = rng.random()
            if kind < .3:
                candidates.append(random_value(rng))
            elif kind < .6:
                candidates.append(str(rng.choice([0, 1, 10**17, 10**18 - 1, 10**18, rng.randint(0, 10**20)])))
            else:
                candidates.append(mutate(str(rng.randint(0, 10**9)), rng))
        result = web_ui.module._resume_point(*candidates)
        expected = next((int(value) for value in candidates if isinstance(value, str) and re.fullmatch(r"[0-9]{1,18}", value)), None)
        assert result == expected, candidates
        accepted += result is not None
        rejected += result is None
    assert accepted and rejected  # the corpus exercises both outcomes


def test_flag_allowlist_rejects_every_file_option_spelling_among_random_flags(web_ui):
    rng = random.Random(SEED + 40)
    file_options = ["-oN", "-oXout", "--oX", "--oA", "-6o", "-Rno", "-ox", "-iL", "--iL", "-6i", "--resu", "--appe",
                    "--datad", "--stylesheet", "--excludef", "--servicedb", "--versiondb"]
    ordinary = ["-sV", "-sS", "-Pn", "-n", "-T4", "-p", "80,443", "--open", "--exclude", "192.0.2.9", "--version-intensity",
                "5", "--script=default", "--data-length", "10", "-vv", "-6", "out.txt", "-O"]
    check = web_ui.module._validate_nmap_flags
    for _ in range(2000):
        tokens = [rng.choice(ordinary) for _ in range(rng.randint(0, 5))]
        assert check(" ".join(tokens)) is None
        tokens.insert(rng.randint(0, len(tokens)), rng.choice(file_options) + rng.choice(["", "=out.txt", " out.txt", "\t."]))
        assert check(" ".join(tokens)) == "nmap_flags cannot read or write files"


def test_account_validation_and_hash_check_only_raise_value_error():
    rng = random.Random(SEED + 3)
    for _ in range(1000):
        username, password = random_value(rng), random_value(rng)
        try:
            validate_account(username, password)
        except ValueError:
            pass
    stored = "scrypt$32768$8$3$" + "ab" * 16 + "$" + "cd" * 64
    for _ in range(100):
        guess = random_value(rng)
        assert password_matches(guess, stored) is False


def test_login_and_account_endpoints_never_return_server_errors(web_ui):
    rng = random.Random(SEED + 4)
    client = web_ui.app.test_client()
    challenge = client.get("/api/auth/login").json["csrf_token"]
    headers = {"X-CSRF-Token": challenge}
    allowed = {400, 401, 403, 413, 415, 429}
    for _ in range(300):
        body = random_value(rng)
        kind = rng.choice(["json", "raw", "form"])
        if kind == "json":
            response = client.post("/api/auth/login", json=body, headers=headers)
        elif kind == "raw":
            response = client.post("/api/auth/login", data=mutate('{"username":"admin","password":"x"}', rng).encode("utf-8", "surrogatepass"),
                                   content_type="application/json", headers=headers)
        else:
            response = client.post("/api/auth/login", data={"username": str(body).encode("utf-8", "surrogatepass"),
                                                        "password": str(body).encode("utf-8", "surrogatepass")}, headers=headers)
        assert response.status_code in allowed, (kind, body, response.status_code)
        # Never reveal the stored hash, the account file path or a traceback.
        text = response.get_data(as_text=True)
        assert "scrypt$" not in text and "Traceback" not in text and ACCOUNT_FILE not in text
    # Unauthenticated administrative calls stay closed for arbitrary bodies and methods.
    for path in ("/api/auth/account", "/api/scans", "/api/settings", "/api/web/findings"):
        for method in ("get", "put", "post", "delete"):
            response = getattr(client, method)(path, json=random_value(rng))
            assert response.status_code in {401, 403, 404, 405, 429}
