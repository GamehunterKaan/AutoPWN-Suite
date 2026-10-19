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
import shlex
import sqlite3
import string
import sys
import zlib
from argparse import ArgumentTypeError
from contextlib import closing
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.text import Text

from autopwn_suite.logger import markup_safe
from autopwn_suite.nmap_backend import parse_nmap_xml
from autopwn_suite.utils import _port, _report_name
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
    from autopwn_suite.web.runtime import SENSITIVE_PARAMETER, redact_text, redact_url
    rng = random.Random(SEED + 3)
    schemes = ["http://", "https://", "HTTP://", "HtTpS://", "ftp://", "a+b.c-d://", "://", "//", ""]
    userinfos = ["", "", "user@", "user:{s}@", "{s}@", ":{s}@", "@"]
    hosts = ["a.test", "a.test:8080", "[::1]", "[::1]:80", "192.0.2.7:81", "x"]
    credential_names = ["token", "api_key", "PASSWORD", "session", "sid", "otp", "key", "access_key", "x-amz-sig", "jwt", "%74oken", "pwd", "csrf_token"]
    plain_names = ["id", "q", "page", "nick", "code", "x", "n%61me", "a.b", "", "sort_key"]

    def secret():
        return "ZQ" + "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(4, 14)))

    for _ in range(3000):
        everything, guarded, always = [], [], []  # values in the text; the ones a credential name guards; the ones that never stay
        scheme, userinfo = rng.choice(schemes), rng.choice(userinfos)
        if "{s}" in userinfo:
            value = secret()
            everything.append(value)
            always.append(value)
            userinfo = userinfo.replace("{s}", value)
        query = ""
        if rng.random() < .85:
            pairs = []
            for _ in range(rng.randint(1, 5)):
                name = rng.choice(credential_names if rng.random() < .4 else plain_names)
                if rng.random() < .1:
                    pairs.append(name)  # no "=": the part is replaced whole
                    continue
                value = secret()
                everything.append(value)
                if SENSITIVE_PARAMETER.search(name.replace("%74", "t").replace("%61", "a")):
                    guarded.append(value)
                pairs.append(f"{name}={value}")
            query = "?" + rng.choice(["&", "&", "&", ";"]).join(pairs)
        fragment = ""
        if rng.random() < .3:
            value = secret()
            everything.append(value)
            always.append(value)
            fragment = rng.choice(["#", "#/route?token=", "#access_token="]) + value
        path = "".join("/" + rng.choice(["a", "app", "x.php", "", "%2e"]) for _ in range(rng.randint(0, 3)))
        # A target typed without a scheme is parsed only when it shows a query, userinfo or fragment.
        if "://" in scheme or query or userinfo or fragment:
            path = path or "/"
            for _ in range(rng.randint(0, 2)):
                value = secret()
                everything.append(value)
                name = rng.choice(["jsessionid", "v"])
                if name == "jsessionid":
                    guarded.append(value)
                path += f";{name}={value}"
        url = scheme + userinfo + rng.choice(hosts) + path + query + fragment
        # A `//` after a prefix (`target=//user@host`) is not read as a network-path reference.
        text = rng.choice(["", "see ", "(", "'", "<"] if scheme == "//" else ["", "see ", "target=", "(", "'", "<"]) + url + rng.choice(["", ".", ",", ")", ".)", ":", " and more", "\n" + url])
        shown = redact_text(text)
        assert isinstance(shown, str) and redact_text(shown) == shown
        # A diagnostic leaves no value, whatever the parameter is called, and neither the userinfo nor the fragment.
        assert not [value for value in everything if value in shown], (text, shown)
        # A finding keeps the values that no credential name guards, but not the userinfo, the fragment or a guarded value.
        kept = redact_text(text, names_only=True)
        assert not [value for value in always + guarded if value in kept], (text, kept)
    # Arbitrary text: never an exception, always a string, and the same answer from the scanner and from a downloaded PoC.
    alphabet = string.ascii_letters + string.digits + "?&=;#@:/\\.%[]()<>\"' \t\n\x1b\x00\x85\ud800é-_+~"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        assert isinstance(redact_text(text), str) and isinstance(redact_text(text, names_only=True), str)
        assert redact_url(text) == poc_runtime._public_url(text)
