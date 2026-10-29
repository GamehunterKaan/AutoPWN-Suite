# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Seeded mutation fuzzing of every parser and validator that handles untrusted input.

These run in the normal suite (and therefore in CI on every change). A failure means an
untrusted input reached an exception the code does not document, or a validator accepted
something it must reject. Seeds are fixed so a failure is reproducible.
"""

import importlib
import itertools
import json
import posixpath
import random
import re
import shlex
import sqlite3
import string
import subprocess
import sys
import zlib
from argparse import ArgumentTypeError
from contextlib import closing
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest
from rich.text import Text

from autopwn_suite import i18n, update_checker
from autopwn_suite.cpe_match import affects, find_affected
from autopwn_suite.logger import markup_safe
from autopwn_suite.nist_search import Vulnerability
from autopwn_suite.nmap_backend import parse_nmap_xml
from autopwn_suite.searchvuln import FindVulnerabilities, GenerateKeyword
from autopwn_suite.utils import _port, _report_name
from autopwn_suite.vulnerability_categories import CATEGORIES, categorize, find_weaknesses
from autopwn_suite.vulnerability_db import SCHEMA_VERSION, DatabaseUnavailable, OfflineDatabase
from autopwn_suite.web.options import normalize_options
from autopwn_suite.web_auth import ACCOUNT_FILE, password_matches, validate_account
from tests.auth_helpers import authenticated_app

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


def test_web_port_validator_only_raises_its_documented_error():
    rng = random.Random(SEED + 41)
    alphabet = string.digits * 3 + string.printable + "\u0663\u00e9\u0000"
    accepted = rejected = 0
    for _ in range(3000):
        text = str(rng.randint(-5, 70000)) if rng.random() < .5 else "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        try:
            port = _port(text)
        except ArgumentTypeError:
            rejected += 1
            continue
        assert isinstance(port, int) and 1 <= port <= 65535
        accepted += 1
    assert accepted and rejected  # the corpus exercises both outcomes


def test_report_name_only_contains_filesystem_safe_characters():
    rng = random.Random(SEED + 42)
    alphabet = string.printable + "\u00e9\u20ac\u0000:*?<>|\\/\ud800"
    for _ in range(3000):
        name = _report_name("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 150))))
        assert len(name) <= 100
        assert re.fullmatch(r"[A-Za-z0-9._-]*", name)
    assert _report_name(["192.0.2.1", "198.51.100.1"]) == "multihost"


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


def test_target_allowlist_never_raises_and_rejects_shell_syntax_and_option_looking_targets(web_ui):
    rng = random.Random(SEED + 2)
    alphabet = string.printable + "\xe9\xdf \x00;|&`$(){}-,-"
    accepted = 0
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        verdict = web_ui.module._validate_target(text)
        assert verdict is None or isinstance(verdict, str)
        if verdict is None:
            accepted += 1
            assert not set(text) & web_ui.module._SHELL_DANGEROUS
            assert not any(token.startswith("-") for token in re.split(r"[\s,]+", text)), text  # never an Nmap option
    assert accepted
    for value in (None, 1, 1.5, [], {}, b"x", True):
        assert isinstance(web_ui.module._validate_target(value), str)


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


def test_dashboard_refuses_every_nmap_flags_text_whatever_the_option(web_ui):
    """File options, NSE options, ordinary options and noise alike: a request (or a stored profile) with any
    non-blank nmap_flags is refused with the one fixed message, and a blank one is stored as empty."""
    rng = random.Random(SEED + 40)
    wu = web_ui.module
    file_options = ["-oN", "-oXout", "--oX", "--oA", "-6o", "-Rno", "-ox", "-iL", "--iL", "-6i", "--resu", "--appe",
                    "--datad", "--stylesheet", "--excludef", "--servicedb", "--versiondb", "-m", "-6m", "-nm"]
    nse = ["--script", "--script=default", "--script-args", "--script-args-file=x", "--script-updatedb", "http-fetch.destination=/tmp"]
    ordinary = ["-sV", "-sS", "-Pn", "-n", "-T4", "-p", "80,443", "--open", "--exclude", "192.0.2.9", "--version-intensity",
                "5", "--data-length", "10", "-vv", "-6", "out.txt", "-O", "--max-retries", "--mtu", "-M", "-A", "-"]
    refused = blank = 0
    for _ in range(3000):
        kind = rng.random()
        if kind < .4:
            text = " ".join(rng.choice(ordinary + nse + file_options) for _ in range(rng.randint(1, 6)))
        elif kind < .7:
            text = mutate(" ".join(rng.choice(ordinary + nse + file_options) for _ in range(rng.randint(0, 4))), rng)
        else:
            text = "".join(rng.choice(string.printable + "\xe9\u4e2d\u202e\x00") for _ in range(rng.randint(0, 30)))
        for source in ({"nmap_flags": text}, {"mode": "normal", "nmap_flags": text, "scan_technique": "-sS", "ports": "80"}):
            if text.strip():
                refused += 1
                with pytest.raises(wu._OptionsRefused) as error:
                    wu._profile_config(source)
                assert str(error.value) == wu._NMAP_OPTIONS_REFUSED
                with pytest.raises(wu._OptionsRefused):
                    wu._profile_config({}, source)
            else:
                blank += 1
                assert wu._profile_config(source)["nmap_flags"] == ""
    assert refused > 2000 and blank


def test_structured_scan_fields_can_only_produce_the_fixed_nmap_arguments(web_ui):
    """Whatever the structured fields hold, an accepted configuration yields exactly: an offered technique, "-p" and
    a port specification, "--version-intensity" and one digit, "-O"; nothing else, nothing with whitespace, and the
    arguments Nmap is started with carry no other option than the scanner's own."""
    rng = random.Random(SEED + 41)
    wu = web_ui.module
    techniques = [t for t in wu._SCAN_TECHNIQUES if t]
    injections = ["-oN /etc/cron.d/x", "--script=http-fetch", "-iL hosts", "--excludefile x", "-sS -sV", "-p 1-65535", "-A", "-O",
                  "--version-intensity 9", "-T5", "22 -oN x", "22,--script=x", "80\n-oN", ";id", "$(id)", "`id`", "../../etc",
                  "22\n80", "T:80", "-", "--", "1-", "-1", " ", "\t", "0", "65536", "1e3", "+80", "0x50", "1_000", "\x00", "\xe9"]
    port_pieces = list("0123456789") * 4 + ["-", ",", " ", ":", "T", "U", "\n"] + injections

    def structured(valid):
        pick = rng.random()
        if pick < .45:
            return rng.choice(valid)
        if pick < .7:
            return mutate(str(rng.choice(valid)), rng)
        if pick < .85:
            return rng.choice(injections)
        return random_value(rng)

    valid = {"scan_technique": techniques + [""], "ports": ["80", "22,80,443", "1-1000", "1-65535", "22,80,1-1000", "65535", "", "53,161,1000-2000"],
             "version_intensity": [0, 1, 5, 9, None, "", "7"], "os_detection": [True, False], "speed": [0, 1, 3, 5, "2"],
             "host_timeout": [1, 30, 240, "60"], "mode": ["normal", "evade", "noise"], "scan_type": [None, "arp", "ping", ""]}
    accepted = rejected = 0
    for _ in range(4000):
        body = {name: rng.choice(choices) for name, choices in valid.items()}
        for name in rng.sample(sorted(valid), rng.choice([0, 1, 1, 2])):  # most requests are wrong in one or two fields
            body[name] = structured(valid[name])
        if rng.random() < .3:
            body["ports"] = "".join(rng.choice(port_pieces) for _ in range(rng.randint(0, 12)))
        try:
            config = wu._profile_config(body)
        except ValueError:
            rejected += 1
            continue
        accepted += 1
        flags = wu._build_nmap_flags(config)
        tokens = shlex.split(flags)
        assert " ".join(tokens) == flags
        assert not any(re.search(r"\s", token) or "\x00" in token for token in tokens), flags
        technique, ports = config["scan_technique"], config["ports"]
        assert technique in wu._SCAN_TECHNIQUES and not re.search(r"\s", technique)
        assert ports == "" or (re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", ports) and len(ports) <= 2048)
        for number in re.findall(r"[0-9]+", ports):
            assert 1 <= int(number) <= 65535 and not number.startswith("0")
        expected = [technique] if technique else []
        expected += ["-p", ports] if ports else []
        if config["version_intensity"] is not None:
            assert isinstance(config["version_intensity"], int) and 0 <= config["version_intensity"] <= 9
            expected += ["--version-intensity", str(config["version_intensity"])]
        expected += ["-O"] if config["os_detection"] else []
        assert tokens == expected, (body, flags)
        # The only tokens that start with a dash are the fixed option names and the offered technique.
        assert {token for token in tokens if token.startswith("-")} <= set(techniques) | {"-p", "--version-intensity", "-O"}
        if accepted % 40 == 0:  # through the real argument builder of the scanner, with Nmap itself stubbed out
            for root in (True, False):
                with patch("autopwn_suite.scanner.PortScanner") as scanner, patch("autopwn_suite.scanner.is_root", return_value=root):
                    from autopwn_suite.scanner import PortScan
                    PortScan("192.0.2.1", MagicMock(), config["speed"], config["host_timeout"], customflags=flags)
                    arguments = shlex.split(scanner.return_value.scan.call_args.kwargs["arguments"])
                owned = set(techniques) | {"-p", "--version-intensity", "-O", "-sV", "--host-timeout", "-Pn", "-T"}
                assert {token for token in arguments if token.startswith("-")} <= owned, arguments
                assert "192.0.2.1" not in arguments  # the target is not among the arguments
    assert accepted > 300 and rejected > 300


def test_profile_validation_never_raises_anything_but_value_error_for_hand_edited_records(web_ui):
    rng = random.Random(SEED + 43)
    wu = web_ui.module
    for _ in range(3000):
        record = {key: random_value(rng) for key in rng.sample(
            ["scan_technique", "ports", "nmap_flags", "version_intensity", "os_detection", "speed", "host_timeout", "mode",
             "scan_type", "scan_ports", "scan_vulns", "vulnerability_source", "web_options"], rng.randint(0, 8))}
        for call in (lambda: wu._profile_config(record), lambda: wu._profile_config({}, record), lambda: wu._profile_config(record, record)):
            try:
                call()
            except ValueError:
                pass
        assert isinstance(wu._holds_options(record), bool)
    for stored in (1, "x", [], [1], True):  # a stored configuration that is not an object
        with pytest.raises(ValueError):
            wu._profile_config({}, stored)


TIMESTAMPS = ["2026-10-19T02:00:00Z", "2026-10-19T02:00:00", "2026-10-19T02:00:00+05:30", "2026-10-19"]
RANGE_LIMITS = ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "9999-12-31T23:59:59Z", "0001-01-01T00:00:00"]


def timestamp_like(rng):
    """What a hand-edited schedules file may hold in a time field: junk, near-valid text and the range limits."""
    pick = rng.random()
    if pick < .25:
        return random_value(rng)
    if pick < .45:
        return rng.choice(RANGE_LIMITS)
    return mutate(rng.choice(TIMESTAMPS), rng)


def test_schedule_time_fields_never_raise_in_the_scheduler_check(web_ui):
    rng = random.Random(SEED + 5)
    wu = web_ui.module
    for _ in range(3000):
        parsed = wu._parse_utc(timestamp_like(rng))
        assert parsed is None or parsed.utcoffset() == timedelta(0)
    clocks = [None, datetime(2026, 10, 18, 2, 0, tzinfo=timezone.utc), datetime(2026, 10, 18, 2, 0), "yesterday", 5]
    for _ in range(3000):
        schedule = {"id": rng.choice(["s1", "s1", "s1", "", None, 5]), "enabled": rng.choice([True, True, False, 1, None]),
                    "type": rng.choice(["interval", "daily", "weekly", "custom", None, 7]),
                    "time_utc": rng.choice(["02:00", "25:99", "2:5", "", "٣:٠٠", "9" * 30 + ":00", random_value(rng)]),
                    "weekday": rng.choice([0, 6, 7, -1, "1", True, random_value(rng)]),
                    "interval_unit": rng.choice(["minutes", "hours", "days", "weeks", None]),
                    "interval_value": rng.choice([1, 0, -1, 2**63, "5", True, random_value(rng)]),
                    "created_at": timestamp_like(rng), "armed_at": timestamp_like(rng), "last_run": timestamp_like(rng)}
        wu._schedule_last_run.clear()
        last = rng.choice(clocks)
        if last is not None:
            wu._schedule_last_run["s1"] = last
        assert isinstance(wu._should_fire(schedule if rng.random() < .95 else random_value(rng)), bool)


def test_profiles_and_schedules_files_never_stop_the_dashboard_from_loading_what_is_valid(web_ui):
    """One bad entry or field costs that entry, never the others or the start of the dashboard."""
    rng = random.Random(SEED + 6)
    wu = web_ui.module
    stores = ((wu._PROFILES_FILE, wu._load_profiles, "_profiles"), (wu._SCHEDULES_FILE, wu._load_schedules, "_schedules"))
    for _ in range(300):
        for path, load, name in stores:
            records = {f"id{index}": rng.choice([random_value(rng), {"id": f"id{index}", "enabled": True, "type": "daily",
                                                                       "last_run": timestamp_like(rng), "created_at": timestamp_like(rng)}])
                       for index in range(rng.randint(0, 5))}
            document = json.dumps(records if rng.random() < .9 else random_value(rng))
            if rng.random() < .3:
                document = mutate(document, rng)
            path.write_bytes(document.encode("utf-8", "surrogatepass"))
            load()
            try:
                parsed = json.loads(document)
            except (ValueError, RecursionError):
                parsed = None
            expected = {key for key, value in parsed.items() if isinstance(value, dict)} if isinstance(parsed, dict) else set()
            state = getattr(wu, name)
            assert set(state) == expected, document
            assert all(isinstance(value, dict) for value in state.values())
            for schedule in wu._schedules.values() if name == "_schedules" else ():
                assert isinstance(wu._should_fire(schedule), bool)
        assert all(value.utcoffset() == timedelta(0) for value in wu._schedule_last_run.values())


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


def test_sign_in_challenge_check_never_raises_and_only_accepts_the_issued_cookie_and_token(web_ui):
    auth = web_ui.app.extensions["dashboard_auth"]
    revision = auth.store.load()["revision"]
    cookie, csrf = auth.new_challenge(revision)
    assert auth.challenge_valid(cookie, csrf, revision) is True
    rng = random.Random(SEED + 9)
    for _ in range(3000):
        changed_cookie, changed_csrf = mutate(cookie, rng), mutate(csrf, rng)
        assert auth.challenge_valid(changed_cookie, csrf, revision) is (changed_cookie == cookie)
        assert auth.challenge_valid(cookie, changed_csrf, revision) is (changed_csrf == csrf)
        for value in (random_value(rng), random_value(rng)):
            assert auth.challenge_valid(value, csrf, revision) is False
            assert auth.challenge_valid(cookie, value, revision) is False


def test_text_a_target_controls_is_cleaned_and_compared_without_raising(monkeypatch):
    from difflib import SequenceMatcher

    from autopwn_suite.web import poc_runtime
    from autopwn_suite.web import similarity as similarity_module
    from autopwn_suite.web.findings import printable
    from autopwn_suite.web.runtime import redact_text
    rng = random.Random(SEED + 2)
    monkeypatch.setattr(similarity_module, "monotonic", lambda: 0.0)  # no deadline: small texts are compared as difflib does
    monkeypatch.setattr(poc_runtime, "monotonic", lambda: 0.0)
    control = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
    pieces = ["http://", "https://a.test/", "?token=1&", "&session=", "x", "/", ".", ")", " ", "\x1b[2J", "\x1b]0;t\x07", "\r", "\n", "\t", "\x85", "\x7f", "\ud800", "é", "[", "]", "\"", "<", "@", ":", "%zz"]
    for _ in range(2000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
        assert not control.search(printable(text)) and printable(printable(text)) == printable(text)
        assert not control.search(redact_text(text))
    # Control characters inside a URL (even inside its scheme or the parameter name) must not hide a secret from redaction.
    for _ in range(1000):
        secret = "S3cr" + "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(1, 12)))
        text = list(f"see http://app.test/p?id=1&token={secret}, then")
        for _ in range(rng.randint(0, 4)):
            text.insert(rng.randrange(len(text) + 1), rng.choice(["\x00", "\x07", "\x1b", "\r", "\x7f", "\x85", "\x9b"]))
        assert secret not in redact_text("".join(text))
    alphabets = ["ab", "abc d", string.ascii_letters + string.digits + " <>/=\"'", "".join(chr(0x4E00 + index) for index in range(150))]
    for _ in range(300):
        alphabet = rng.choice(alphabets)
        left = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        right = mutate(left, rng) if rng.random() < .7 else "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        ratio = SequenceMatcher(None, left, right).ratio()
        assert 0 <= ratio <= 1
        # The package function and the copy that downloaded PoCs carry agree with each other and with difflib.
        assert similarity_module.similarity(left, right) == poc_runtime._similarity(left, right) == ratio
        assert similarity_module.similarity(left, left) == poc_runtime._similarity(left, left) == 1.0


def test_redact_text_never_raises_and_leaves_no_value_of_a_diagnostic_target():
    from autopwn_suite.web import poc_runtime
    from autopwn_suite.web.runtime import SENSITIVE_PARAMETER, redact_target, redact_text, redact_url
    rng = random.Random(SEED + 3)
    schemes = ["http://", "https://", "HTTP://", "HtTpS://", "ftp://", "a+b.c-d://", "://", "//", ""]
    userinfos = ["", "", "user@", "user:{s}@", "{s}@", ":{s}@", "@"]
    hosts = ["a.test", "a.test:8080", "[::1]", "[::1]:80", "192.0.2.7:81", "x"]
    credential_names = ["token", "api_key", "PASSWORD", "session", "sid", "otp", "key", "access_key", "x-amz-sig", "jwt", "%74oken", "pwd", "csrf_token",
                        "code", "pw", "ticket", "nonce", "SAMLResponse", "RelayState", "code_verifier"]
    plain_names = ["id", "q", "page", "nick", "x", "n%61me", "a.b", "", "sort_key", "country_code"]
    # Characters that can sit inside a value or a userinfo and that a tokenizer cuts a URL at. A message ends a URL at the
    # next ASCII whitespace only; a target typed as one string (`redact_target`) has no such limit.
    breakers = ["'", '"', "<", ">", "\u00a0", "\u2028", "\u3000"]

    serial = itertools.count()

    def chunk():
        # A fixed-width serial number first: no chunk is the start of another one, so finding one in a text is a real leak.
        return f"ZQ{next(serial):07d}" + "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(4, 14)))

    def secret(breaking):
        """A value of one to three chunks with a breaker between them: the check is that no chunk is left, not only the whole value."""
        parts = [chunk() for _ in range(rng.randint(1, 3))]
        value = parts[0]
        for part in parts[1:]:
            value += rng.choice(breaking) + part
        return value, parts

    def build(breaking):
        everything, guarded, always, bare = [], [], [], []  # chunks in the text; the ones a credential name guards; the ones that never stay; the bare query parts
        scheme, userinfo = rng.choice(schemes), rng.choice(userinfos)
        if "{s}" in userinfo:
            value, parts = secret(breaking)
            everything += parts
            always += parts
            userinfo = userinfo.replace("{s}", value)
        query = ""
        if rng.random() < .85:
            pairs = []
            for _ in range(rng.randint(1, 5)):
                if rng.random() < .1:
                    value, parts = secret(breaking)
                    bare += parts
                    pairs.append(value)  # no "=": a bare token
                    continue
                name = rng.choice(credential_names if rng.random() < .4 else plain_names)
                value, parts = secret(breaking)
                everything += parts
                if SENSITIVE_PARAMETER.search(name.replace("%74", "t").replace("%61", "a")):
                    guarded += parts
                pairs.append(f"{name}={value}")
            query = "?" + rng.choice(["&", "&", "&", ";"]).join(pairs)
        fragment = ""
        if rng.random() < .3:
            value, parts = secret(breaking)
            everything += parts
            always += parts
            fragment = rng.choice(["#", "#/route?token=", "#access_token="]) + value
        path = "".join("/" + rng.choice(["a", "app", "x.php", "", "%2e"]) for _ in range(rng.randint(0, 3)))
        # A target typed without a scheme is parsed only when it shows a query, userinfo or fragment.
        if "://" in scheme or query or userinfo or fragment:
            path = path or "/"
            for _ in range(rng.randint(0, 2)):
                value, parts = secret(breaking)
                everything += parts
                name = rng.choice(["jsessionid", "v"])
                if name == "jsessionid":
                    guarded += parts
                path += f";{name}={value}"
        return scheme, scheme + userinfo + rng.choice(hosts) + path + query + fragment, everything, guarded, always, bare

    def left(chunks, shown):
        return [value for value in chunks if value in shown]

    for _ in range(3000):
        scheme, url, everything, guarded, always, bare = build(breakers)
        # A `//` after a prefix (`target=//user@host`) is not read as a network-path reference.
        text = rng.choice(["", "see ", "(", "'", "<", '"'] if scheme == "//" else ["", "see ", "target=", "(", "'", "<", '"']) + url + rng.choice(
            ["", ".", ",", ")", ".)", ":", "'", '"', ">", " and more", "\u3000and more", "\n" + url])
        shown = redact_text(text)
        assert isinstance(shown, str) and redact_text(shown) == shown
        # A diagnostic leaves no value, whatever the parameter is called, and neither the userinfo nor the fragment, whatever
        # a value holds: a quote, an angle bracket and any Unicode space stay inside the URL. A bare query part goes in a URL.
        assert not left(everything + (bare if "://" in scheme else []), shown), (text, shown)
        # A finding keeps the values that no credential name guards, but not the userinfo, the fragment or a guarded value.
        assert not left(always + guarded, redact_text(text, names_only=True)), (text, shown)
        # A target echoed as one string: the same, whatever it holds, ASCII whitespace included.
        scheme, url, everything, guarded, always, bare = build(breakers + [" ", "\t"])
        shown = redact_target(url)
        assert isinstance(shown, str) and redact_target(shown) == shown
        assert not left(everything + bare, shown), (url, shown)
    # A breaker anywhere in front of a credential value is no way around it, in a message and in a target.
    junk_alphabet = string.ascii_letters + string.digits + "'\"<>\u00a0\u2028\u3000%+,./:=?@[]()!$*-_~|{}\\^`#"
    for _ in range(3000):
        junk = "".join(rng.choice(junk_alphabet) for _ in range(rng.randint(0, 20)))
        marker = chunk()
        url = rng.choice(["http://h/?", "HTTPS://u:p@h:81/a;b=c/?", "h:80?", "[::1]:80/x?", "u@h/p?a=1&"]) + "q=" + junk + "&token=" + marker
        assert marker not in redact_target(url), url
        assert marker not in redact_text("see " + url + "."), url
    # Arbitrary text: never an exception, always a string, and the same answer from the scanner and from a downloaded PoC.
    alphabet = string.ascii_letters + string.digits + "?&=;#@:/\\.%[]()<>\"' \t\n\x1b\x00\x85\ud800é-_+~\u00a0\u2028\u3000"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        assert isinstance(redact_text(text), str) and isinstance(redact_text(text, names_only=True), str) and isinstance(redact_target(text), str)
        assert redact_url(text) == poc_runtime._public_url(text)


def test_random_unicode_never_leaves_a_line_break_a_control_or_a_layout_character():
    """Whatever code points a host or a data provider sends, the text that is printed, stored or exported keeps none of
    the characters listed in test_hostile_text, and cleaning it a second time changes nothing."""
    from autopwn_suite.logger import console_safe
    from autopwn_suite.nist_search import Vulnerability
    from autopwn_suite.text import wire_url
    from autopwn_suite.web.findings import finding, printable
    from autopwn_suite.web.runtime import redact_text, redact_url
    from tests.unit.test_hostile_text import FORBIDDEN, FORBIDDEN_EXCEPT_NEWLINE, FORBIDDEN_TEXT
    rng = random.Random(SEED + 7)
    pieces = [*FORBIDDEN_TEXT, "\r\n", "\x1b[2J", "\x1b]0;t\x07", "[/red]", "[bold]", "http://a.test/?token=1", " ", "a", "é", "日本"]

    def random_text():
        chars = []
        for _ in range(rng.randint(0, 24)):
            kind = rng.random()
            if kind < .5:
                chars.append(rng.choice(pieces))
            elif kind < .75:
                chars.append(chr(rng.randrange(0x10000)))
            else:
                chars.append(chr(rng.randrange(0x10000, 0x110000)))
        return "".join(chars)

    def xml_reference(text):
        """The characters XML can hold, as character references, which keep line breaks inside an attribute."""
        return "".join(f"&#{ord(char)};" for char in text if ord(char) in (9, 10, 13) or 0x20 <= ord(char) <= 0xD7FF
                       or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char))

    for _ in range(3000):
        text = random_text()
        single, multi = printable(text), printable(text, multiline=True)
        assert not FORBIDDEN.search(single) and not FORBIDDEN_EXCEPT_NEWLINE.search(multi)
        assert printable(single) == single and printable(multi, multiline=True) == multi
        assert single == multi.replace("\n", " ") and len(single.splitlines()) <= 1
        assert Text.from_markup(console_safe(text), emoji=False).plain == single
        assert not FORBIDDEN.search(redact_text(text))
        # A URL keeps the characters as percent-encoding, which is plain, stable and what a replay sends.
        encoded = wire_url("http://a.test/" + text)
        assert not FORBIDDEN.search(encoded) and wire_url(encoded) == encoded and not FORBIDDEN.search(redact_url("http://a.test/" + text))
        result = finding("X", "http://a.test/" + text, text, parameter=text)
        assert not any(FORBIDDEN.search(result[key]) for key in ("url", "parameter", "evidence"))
        vulnerability = Vulnerability(text, text, text, text, 1.0, text, 1.0)
        assert not any(FORBIDDEN.search(getattr(vulnerability, name)) for name in ("CVEID", "description", "severity", "details_url"))
        valid = xml_reference(text)
        xml = VALID_XML.replace('name="http"', f'name="{valid}"').replace("</service>", f'</service><script id="s" output="{valid}"/>')
        port = parse_nmap_xml(xml)["scan"]["192.0.2.10"]["tcp"][80]
        assert not FORBIDDEN.search(port["name"]) and not FORBIDDEN_EXCEPT_NEWLINE.search(port["script"]["s"])


UPDATE_NAMES = ["main", "v2.7.0", "release/1.0", "x/y", "GamehunterKaan/AutoPWN-Suite", "--abort", "a..b", "a//b", "a.lock", "a/.b"]
UPDATE_PIECES = ["feature", "v1", "2", "a-b", "c_d", "x.y", "1+b", ".lock", "x.lock", ".", "..", ""]


def update_name(rng):
    roll = rng.random()
    if roll < .35:
        return mutate(rng.choice(UPDATE_NAMES), rng)
    if roll < .7:
        return "".join(rng.choice(UPDATE_PIECES) + rng.choice(["/", "/", ".", "-", ""]) for _ in range(rng.randint(1, 4)))
    if roll < .92:
        alphabet = string.ascii_letters + string.digits + "./-_+:~^?*[\\@{} \n\t\x00\u00e9\u0663\u2028"
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
    return rng.choice([None, 0, 5, b"x/y", ["x/y"], {}, 2.5, True])


def test_update_repository_and_ref_validators_only_raise_their_documented_error():
    rng = random.Random(SEED + 60)
    accepted_repos, accepted_refs, rejected, to_check_with_git = 0, 0, 0, []
    for _ in range(6000):
        text = update_name(rng)
        try:
            repo = update_checker._checked_repo(text)
        except update_checker.UpdateCheckError:
            rejected += 1
        else:
            accepted_repos += 1
            owner, name = repo.split("/")
            assert owner not in (".", "..") and name not in (".", "..")
            assert repo.isascii() and repo.isprintable() and " " not in repo
            # The repository can only extend the path of the two fixed GitHub URLs.
            for url, host in ((f"https://github.com/{repo}.git", "github.com"),
                              (update_checker.API_ROOT.format(repo=repo) + "/releases/latest", "api.github.com")):
                parts = urlsplit(url)
                assert parts.netloc == host and not parts.query and not parts.fragment
                assert posixpath.normpath(parts.path) == parts.path
        try:
            ref = update_checker._checked_ref(text, "branch")
        except update_checker.UpdateCheckError:
            rejected += 1
        else:
            accepted_refs += 1
            assert 1 <= len(ref) <= 255 and not ref.startswith("-")
            assert ".." not in ref and "//" not in ref and ref.isascii() and ref.isprintable()
            assert not set(ref) & set(" ~^:?*[\\@{}")
            if len(to_check_with_git) < 100:
                to_check_with_git.append(ref)
    assert accepted_repos > 50 and accepted_refs > 50 and rejected > 1000  # the corpus exercises both outcomes
    # Everything the allowlist accepts is also a name git accepts, so a refused name is the only way to a git error.
    for ref in to_check_with_git:
        assert subprocess.run(["git", "check-ref-format", f"refs/heads/{ref}"], capture_output=True).returncode == 0, ref


UPDATE_FIELDS = ["v9.9.9", "", "9" * 5000, "v" + "9" * 5000, "-", "\x1b[2J", "a" * 40, "[bold]", 7, None, ["x"], {"a": 1}, True, 1.5]


def test_github_responses_only_produce_a_status_or_the_documented_error(monkeypatch):
    rng = random.Random(SEED + 61)
    monkeypatch.setattr(update_checker, "_local_commit", lambda: "a" * 40)
    statuses = errors = 0
    for _ in range(3000):
        if rng.random() < .6:
            body = {key: rng.choice(UPDATE_FIELDS) if rng.random() < .8 else random_value(rng)
                    for key in ("tag_name", "html_url", "sha") if rng.random() < .85}
        else:
            body = random_value(rng)
        reply = MagicMock(status_code=rng.choice([200, 200, 200, 403, 404, 500]))
        reply.ok = reply.status_code < 400
        reply.json.return_value = body
        monkeypatch.setattr(update_checker.requests, "get", lambda *a, _reply=reply, **k: _reply)
        for check in (lambda: update_checker.check_release("2.7.0", repo="x/y"), lambda: update_checker.check_commit(repo="x/y")):
            try:
                status = check()
            except update_checker.UpdateCheckError:
                errors += 1
                continue
            statuses += 1
            assert all(isinstance(getattr(status, name), str) for name in ("mode", "repo", "current", "latest", "url"))
            assert isinstance(status.update_available, bool)
            assert isinstance(update_checker.format_status(status), str)
    assert statuses and errors


def test_a_commit_id_from_github_reaches_git_only_as_a_full_hex_object_name(monkeypatch):
    rng = random.Random(SEED + 63)
    calls = []

    def run_git(args, check=True):
        calls.append(list(args))
        return SimpleNamespace(returncode=rng.choice([0, 1, 128]), stdout="", stderr="")

    monkeypatch.setattr(update_checker, "_run_git", run_git)
    monkeypatch.setattr(update_checker, "_local_commit", lambda: "a" * 40)
    pieces = ["b" * 40, "c" * 64, "B" * 40, "b" * 39, "b" * 41, "-", "--all", "HEAD", "\n", " ", "g", "^", "~1", ":"]
    asked = 0
    for _ in range(3000):
        sha = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 3))) if rng.random() < .8 else random_value(rng)
        reply = MagicMock(status_code=200, ok=True)
        reply.json.return_value = {"sha": sha}
        monkeypatch.setattr(update_checker.requests, "get", lambda *a, _reply=reply, **k: _reply)
        calls.clear()
        status = update_checker.check_commit(repo="x/y")
        assert isinstance(status.update_available, bool)
        for args in calls:
            asked += 1
            assert args == ["merge-base", "--is-ancestor", sha, "a" * 40]
            assert re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha)
    assert asked


def test_update_routes_only_pass_a_known_channel_and_the_fixed_branch(web_ui, monkeypatch):
    rng = random.Random(SEED + 64)
    seen = []
    status = update_checker.UpdateStatus("release", "x/y", "1", "2", "https://github.com/x/y", True)
    result = update_checker.UpdateResult("release", "x/y", "a", "a", "v2")
    monkeypatch.setattr(web_ui.module, "__version__", "2.8.0", raising=False)
    monkeypatch.setattr(update_checker, "current_commit", lambda: None)
    monkeypatch.setattr(update_checker, "check_for_updates", lambda *a, **k: seen.append(k) or status)
    monkeypatch.setattr(update_checker, "apply_update", lambda *a, **k: seen.append(k) or result)
    client = authenticated_app(web_ui.module).test_client()
    channels = ["release", "commit", "Release", "nightly", "", " release", "commit\n", None, 1, True, [], {}]
    for _ in range(400):
        body = {"channel": rng.choice(channels)} if rng.random() < .7 else random_value(rng)
        if isinstance(body, dict) and rng.random() < .3:
            body.update(repo=random_value(rng), branch=update_name(rng))
        if isinstance(body, dict) and rng.random() < .4:
            body["automatic"] = rng.choice([True, False, "true", 1, 0, None, []])
        route = rng.choice(["/api/update/check", "/api/update/apply"])
        seen.clear()
        response = client.post(route, json=body)
        assert response.status_code in {200, 400, 409}, (body, response.status_code)
        if response.status_code == 409:  # an automatic check before the last one is 6 hours old
            assert not seen and response.json["code"] == "update_not_due" and body.get("automatic") is True
        elif response.status_code == 400:
            assert not seen and response.json["code"] in {"invalid_update_channel", "invalid_json_body"}
        else:
            assert seen == [{"channel": seen[0]["channel"], "branch": "main"}]
            assert seen[0]["channel"] in ("release", "commit")
            automatic = body.get("automatic", False) if isinstance(body, dict) else False
            assert automatic is False or (automatic is True and route == "/api/update/check")


def test_a_release_tag_reaches_git_only_as_a_plain_name_in_the_expected_arguments(monkeypatch):
    rng = random.Random(SEED + 62)
    calls = []

    def run_git(args, check=True):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    on_branch = []
    monkeypatch.setattr(update_checker, "_run_git", run_git)
    monkeypatch.setattr(update_checker, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(update_checker, "_ensure_clean_worktree", lambda: None)
    monkeypatch.setattr(update_checker, "_current_branch", lambda: "main" if on_branch[-1] else None)
    reached = refused = 0
    for _ in range(2500):
        tag = update_name(rng)
        on_branch.append(rng.random() < .5)
        calls.clear()
        reply = MagicMock(status_code=200, ok=True)
        reply.json.return_value = {"tag_name": tag}
        monkeypatch.setattr(update_checker.requests, "get", lambda *a, _reply=reply, **k: _reply)
        try:
            update_checker.apply_update(channel="release", repo="x/y")
        except update_checker.UpdateCheckError:
            refused += 1
            assert not calls  # nothing ran before the refusal
            continue
        reached += 1
        assert not tag.startswith("-") and ".." not in tag and not set(tag) & set(" ~^:?*[\\@{}\n")
        fetch, last = calls[0], calls[-1]
        assert fetch[0] == "fetch" and fetch[2] == f"refs/tags/{tag}:refs/tags/{tag}"
        assert last == (["merge", "--ff-only", tag] if on_branch[-1] else ["checkout", "--detach", f"refs/tags/{tag}"])
        assert all(not arg.startswith("-") for args in calls for arg in args[2:] if tag in arg)
    assert reached and refused


def test_language_selection_only_yields_a_supported_language_and_leaves_the_saved_one_alone_for_junk(tmp_path, monkeypatch):
    rng = random.Random(SEED + 70)
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    language_file = tmp_path / i18n.LANGUAGE_FILE_NAME
    words = ["--lang", "--language", "--lang=tr", "--language=", "--language=en", "--lang=\x1b[2J", "-t", "192.0.2.1", "tr", "en", "de", "", "\x00", "\u0130", "-" * 30]
    saved_values = [b"tr", b"en\n", b"TR", b"de", b" tr "]
    for _ in range(1500):
        argv = [rng.choice(words) for _ in range(rng.randint(0, 6))]
        found = i18n.peek_lang_flag(argv)
        assert found is None or (isinstance(found, str) and any(found in token for token in argv))
        for name in ("AUTOPWN_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
            monkeypatch.setenv(name, rng.choice(["tr", "tr_TR.UTF-8", "en_US", "", "\u0130stanbul", "de_DE", "x" * 300]))
        if rng.random() < .3:
            language_file.unlink(missing_ok=True)
        elif rng.random() < .5:
            language_file.write_bytes(bytes(rng.randrange(256) for _ in range(rng.randint(0, 6))))
        else:
            language_file.write_bytes(rng.choice(saved_values))
        before = language_file.read_bytes() if language_file.exists() else None
        assert i18n.resolve_language(found) in i18n.SUPPORTED_LANGUAGES
        if found in i18n.SUPPORTED_LANGUAGES:
            assert language_file.read_text(encoding="utf-8") == found
        else:
            assert (language_file.read_bytes() if language_file.exists() else None) == before
        assert i18n.resolve_language(None) in i18n.SUPPORTED_LANGUAGES


def test_vulnerability_categories_only_return_the_fixed_ids_for_any_record_or_description():
    rng = random.Random(SEED + 61)
    descriptions = ["Allows remote attackers to execute arbitrary code or cause a denial of service (crash).",
                    "Cross-site scripting (XSS) via the name parameter", "Heap-based buffer overflow", ""]
    cwes = ["CWE-79", "CWE-787", "CWE-20", "NVD-CWE-Other", "CWE-1", "CWE-99999"]
    for _ in range(4000):
        entry = rng.choice([random_value(rng), {"value": random_value(rng)}, {"value": mutate(rng.choice(cwes), rng)},
                            {"value": rng.choice(cwes)}])
        weaknesses = rng.choice([random_value(rng), [random_value(rng)], [{"description": [entry, entry]}],
                                 [{"description": [{"value": rng.choice(cwes)} for _ in range(rng.randint(0, 80))]}]])
        record = rng.choice([{"cve": {"weaknesses": weaknesses}}, {"cve": random_value(rng)}, random_value(rng)])
        found = find_weaknesses(record)
        assert type(found) is tuple and len(found) <= 32 and len(set(found)) == len(found)
        assert all(re.fullmatch(r"CWE-[0-9]{1,5}", value) for value in found)
        description = rng.choice([random_value(rng), mutate(rng.choice(descriptions), rng), rng.choice(descriptions)])
        result = categorize(found, description)
        assert result and set(result) <= set(CATEGORIES)
        assert list(result) == sorted(set(result), key=CATEGORIES.index)
        assert "other" not in result or result == ("other",)



def test_service_keywords_and_cpe_applicability_never_raise_for_banner_or_record_text():
    """Nmap's product and version come from a target's banner, and the CPE matches from NVD or a copied mirror."""
    rng = random.Random(SEED + 71)
    products = ["Apache httpd", "OpenSSH", "MySQL", "ISC BIND", "Samba smbd", "Jetty", "UnrealIRCd", "Unknown"]
    versions = ["2.4.41", "8.2p1 Ubuntu 4ubuntu0.5", "5.5.5-10.3.23-MariaDB-0+deb10u1", "9.11.5-P4-5.1+deb10u5",
                "3.X - 4.X", "9.4.18.v20190429", "8.14.4/8.14.4", "10.50.1600.00; RTM", "Unknown", "", "9" * 5000]
    base = {"cve": {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:p2:*:*:*:*:*:*", "versionEndIncluding": "7.2"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:isc:bind:9.11.5:p4:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.52"}]}]}]}}
    junk = [None, True, 0, 2**70, 1.5, "", "x", "9" * 5000, [], ["x"], {}, {"a": 1}, "cpe:2.3:a:x", "cpe:2.3:a:x:y:*:*"]

    def corrupt(node):
        if rng.random() < .1:
            return rng.choice(junk)
        if isinstance(node, dict):
            return {key: corrupt(value) for key, value in node.items()}
        if isinstance(node, list):
            return [corrupt(value) for value in node]
        return mutate(node, rng) if isinstance(node, str) and rng.random() < .2 else node

    for _ in range(3000):
        product = str(rng.choice([random_value(rng), mutate(rng.choice(products), rng), rng.choice(products)]))
        version = str(rng.choice([random_value(rng), mutate(rng.choice(versions), rng), rng.choice(versions)]))
        keyword = GenerateKeyword(product, version)
        release = keyword.rpartition(" ")[2]
        assert not keyword or product.lower() == "unrealircd" or re.fullmatch(
            r"[0-9]+(?:\.[0-9]+)*(?:[a-z]+[0-9]*)?", release, re.IGNORECASE)
        found = find_affected(rng.choice([corrupt(base), random_value(rng)]))
        assert type(found) is tuple and all(
            len(entry) == 8 and all(part is None or isinstance(part, str) for part in entry) for entry in found)
        assert affects(found, product, release or version) in (True, False, None)
        candidate = Vulnerability("term", "CVE-2026-0001", mutate(product + " " + version, rng), "HIGH", 7.5,
                                  "https://nvd.test/", 3.9, affected=found)
        assert FindVulnerabilities(keyword or product, lambda term: [candidate]) in ([], [candidate])
