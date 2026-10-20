# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Authentication boundary, browser forgery defenses and local account recovery."""

import importlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from autopwn_suite.web_auth import (
    ACCOUNT_FILE,
    COOKIE,
    LOGIN_COOKIE,
    AccountStore,
    AccountUnavailable,
    DashboardAuth,
    password_matches,
)


@pytest.fixture
def dashboard_login(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    sys.modules.pop("autopwn_suite.web_ui", None)
    wu = importlib.import_module("autopwn_suite.web_ui")
    wu._load_settings()
    app = wu._build_app(wu._STATIC_DIR)
    app.config["TESTING"] = True
    output = capsys.readouterr().out
    password = re.search(r"  Password: (\S+)", output)[1]
    return SimpleNamespace(wu=wu, app=app, password=password, output=output,
                           path=tmp_path / ACCOUNT_FILE, auth=app.extensions["dashboard_auth"])


def sign_in(client, password, username="admin", **kwargs):
    challenge = client.get("/api/auth/login").json["csrf_token"]
    return client.post("/api/auth/login", json={"username": username, "password": password},
                       headers={"X-CSRF-Token": challenge}, **kwargs)


def logged_in(dashboard):
    client = dashboard.app.test_client()
    response = sign_in(client, dashboard.password)
    assert response.status_code == 200
    return client, response.json["csrf_token"]


def test_first_launch_prints_unique_password_once_and_only_persists_hash(dashboard_login, capsys):
    d = dashboard_login
    data = json.loads(d.path.read_text())
    assert data["username"] == "admin" and len(d.password) == 32
    assert d.password not in d.path.read_text()
    assert data["password_hash"].startswith("scrypt$32768$8$3$")
    assert password_matches(d.password, data["password_hash"])
    assert not password_matches(d.password + "x", data["password_hash"])
    d.wu._build_app(d.wu._STATIC_DIR)
    assert capsys.readouterr().out == ""
    assert json.loads(d.path.read_text()) == data
    if os.name != "nt":
        assert d.path.stat().st_mode & 0o777 == 0o600


def test_every_existing_route_requires_login_including_static_sse_and_downloads(dashboard_login):
    client = dashboard_login.app.test_client()
    public = {"/login", "/api/auth/login", "/favicon.ico"}
    checked = 0
    for rule in dashboard_login.app.url_map.iter_rules():
        if rule.rule in public:
            continue
        url = re.sub(r"<[^>]+>", "index.html" if rule.endpoint == "static" else "example", rule.rule)
        for method in rule.methods - {"OPTIONS"}:
            response = client.open(url, method=method)
            expected = 401 if url.startswith("/api/") or method not in ("GET", "HEAD") else 302
            assert response.status_code == expected, (method, url, response.status_code)
            assert response.headers["Cache-Control"] == "no-store"
            checked += 1
    assert checked > 50
    for asset in ("/login", "/login.js", "/login.css", "/favicon.ico"):
        assert client.get(asset).status_code == 200


def test_login_requires_bound_challenge_and_cannot_reuse_it(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    credentials = {"username": "admin", "password": d.password}
    assert client.post("/api/auth/login", json=credentials).status_code == 403
    challenge = client.get("/api/auth/login").json["csrf_token"]
    foreign = d.app.test_client()
    assert foreign.post("/api/auth/login", json=credentials, headers={"X-CSRF-Token": challenge}).status_code == 403
    response = client.post("/api/auth/login", json=credentials, headers={"X-CSRF-Token": challenge})
    assert response.status_code == 200
    assert client.get_cookie(LOGIN_COOKIE) is None
    assert client.post("/api/auth/login", json=credentials, headers={"X-CSRF-Token": challenge}).status_code == 403
    assert client.get("/").status_code == 200
    cookie = next(value for value in response.headers.getlist("Set-Cookie") if value.startswith(COOKIE + "="))
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:9999", "http://localhost.evil", "http://localhost/path"])
def test_cross_origin_login_and_admin_requests_are_rejected(dashboard_login, origin):
    d = dashboard_login
    client, csrf = logged_in(d)
    assert client.get("/api/auth/login", headers={"Origin": origin}).status_code == 403
    response = client.put("/api/settings", json={"nist_api_key": "forged"}, headers={"X-CSRF-Token": csrf, "Origin": origin})
    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers
    assert client.get("/api/settings").json.get("nist_api_key") != "forged"


@pytest.mark.parametrize("method,path", [("PUT", "/api/settings"), ("POST", "/api/scan/stop"), ("DELETE", "/api/profiles/missing"), ("POST", "/api/auth/logout")])
def test_all_mutations_require_csrf_even_without_a_body(dashboard_login, method, path):
    client, _ = logged_in(dashboard_login)
    assert client.open(path, method=method).status_code == 403
    assert client.open(path, method=method, headers={"X-CSRF-Token": "é"}).status_code == 403
    assert client.get("/api/auth/session").status_code == 200


def test_same_origin_mutations_and_downloads_keep_working_without_leaking_hashes(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    assert client.put("/api/settings", json={"nist_api_key": "synthetic"}, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"}).status_code == 200
    assert client.get("/api/settings").json["nist_api_key"] == "synthetic"
    for url in ("/api/settings", "/api/auth/session", "/api/auth/login"):
        response = client.get(url)
        assert "password_hash" not in response.get_data(as_text=True)
        assert d.password not in response.get_data(as_text=True)
    assert client.put("/api/settings", json={"account": {"username": "forged"}}, headers={"X-CSRF-Token": csrf}).status_code == 400
    assert json.loads(d.path.read_text())["username"] == "admin"


def test_account_change_requires_current_password_rotates_sessions_and_persists(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    other, _ = logged_in(d)
    old_token = client.get_cookie(COOKIE).value
    original = d.path.read_bytes()
    body = {"username": "new-admin", "current_password": "incorrect", "new_password": "A new strong test password 2026!"}
    assert client.put("/api/auth/account", json=body, headers={"X-CSRF-Token": csrf}).status_code == 403
    assert d.path.read_bytes() == original
    body["current_password"] = d.password
    response = client.put("/api/auth/account", json=body, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json["username"] == "new-admin"
    assert response.json["csrf_token"] != csrf
    assert client.get_cookie(COOKIE).value != old_token
    assert other.get("/api/settings").status_code == 401
    assert client.get("/api/settings").status_code == 200
    assert not password_matches(d.password, json.loads(d.path.read_text())["password_hash"])
    assert body["new_password"] not in d.path.read_text()
    restarted = d.wu._build_app(d.wu._STATIC_DIR).test_client()
    assert sign_in(restarted, d.password).status_code == 401
    assert sign_in(restarted, body["new_password"], "new-admin").status_code == 200


def test_username_only_change_retains_hash_but_revokes_previous_sessions(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    old = json.loads(d.path.read_text())
    response = client.put("/api/auth/account", json={"username": "renamed", "current_password": d.password, "new_password": ""}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    updated = json.loads(d.path.read_text())
    assert updated["password_hash"] == old["password_hash"] and updated["revision"] != old["revision"]
    assert sign_in(d.app.test_client(), d.password, "renamed").status_code == 200


@pytest.mark.parametrize("username,password", [("<script>", "A test password long enough"), ("admin", "short"), ("admin", " " * 15), ("admin", "x" * 129), ("admin", "\ud800" * 15)])
def test_invalid_account_updates_preserve_existing_credentials(dashboard_login, username, password):
    d = dashboard_login
    client, csrf = logged_in(d)
    original = d.path.read_bytes()
    response = client.put("/api/auth/account", json={"username": username, "current_password": d.password, "new_password": password}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 400
    assert d.path.read_bytes() == original


def test_logout_revokes_cookie_copies_and_stops_open_event_stream(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    copied = d.app.test_client()
    copied.set_cookie(COOKIE, client.get_cookie(COOKIE).value)
    stream = client.get("/api/events", buffered=False)
    iterator = iter(stream.response)
    d.wu._broadcast({"msg": "first"})
    d.wu._broadcast({"msg": "must-not-leak-after-logout"})
    received = b""
    while b"first" not in received:  # a heartbeat may come before the first entry
        received += next(iterator)
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    with pytest.raises(StopIteration):
        next(iterator)
    stream.close()
    assert copied.get("/api/log").status_code == 401
    assert not d.wu._sse_subscribers


def test_resuming_the_event_stream_needs_sign_in_and_stops_at_logout_even_during_the_replay(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    for message in ("replay one", "replay two", "replay three"):
        d.wu._broadcast({"msg": message})
    for resume in ({"query_string": {"after": "0"}}, {"headers": {"Last-Event-ID": "0"}}):
        stranger = d.app.test_client().get("/api/events", **resume)
        assert stranger.status_code == 401 and b"replay" not in stranger.data
    stream = client.get("/api/events?after=0", buffered=False)
    iterator = iter(stream.response)
    received = b""
    for _ in range(3):  # a heartbeat can come first; never wait for ever if nothing is replayed
        received += next(iterator)
        if b"replay one" in received:
            break
    assert b"replay one" in received
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    with pytest.raises(StopIteration):
        next(iterator)
    stream.close()
    assert b"replay two" not in received and not d.wu._sse_subscribers


def test_expired_session_and_forged_cookie_fail_closed(dashboard_login):
    d = dashboard_login
    client, _ = logged_in(d)
    for key, entry in list(d.auth.sessions.items()):
        d.auth.sessions[key] = replace(entry, expires=0)
    assert client.get("/api/settings").status_code == 401
    client.set_cookie(COOKIE, "forged-session-token-" * 3)
    assert client.get("/api/settings").status_code == 401


def test_cli_reset_from_another_process_revokes_running_sessions_and_changes_password(dashboard_login):
    d = dashboard_login
    client, _ = logged_in(d)
    result = subprocess.run([sys.executable, str(Path(__file__).parents[2] / "autopwn.py"), "--web-reset-account", "--web"],
                            capture_output=True, text=True, timeout=20, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    password = re.search(r"  Password: (\S+)", result.stdout)[1]
    assert password != d.password
    assert password not in d.path.read_text()
    assert client.get("/api/settings").status_code == 401
    assert sign_in(d.app.test_client(), d.password).status_code == 401
    assert sign_in(d.app.test_client(), password).status_code == 200


def test_cli_reset_does_not_scan_and_initialization_does_not_overwrite_corruption(dashboard_login, monkeypatch, capsys):
    import autopwn_suite.cli as autopwn
    d = dashboard_login
    d.path.write_text("{broken", encoding="utf-8")
    with pytest.raises(AccountUnavailable):
        d.wu._build_app(d.wu._STATIC_DIR)
    assert d.path.read_text() == "{broken"
    scanner, server = Mock(), Mock()
    monkeypatch.setattr(autopwn, "StartScanning", scanner)
    monkeypatch.setattr(autopwn, "start_server", server)
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--web-reset-account"])
    autopwn.main()
    scanner.assert_not_called()
    server.assert_not_called()
    password = re.search(r"  Password: (\S+)", capsys.readouterr().out)[1]
    assert sign_in(d.app.test_client(), password).status_code == 200


@pytest.mark.parametrize("damage", ["missing", "corrupt", "weak-hash"])
def test_runtime_missing_or_invalid_auth_file_never_restores_defaults(dashboard_login, damage):
    d = dashboard_login
    client, _ = logged_in(d)
    if damage == "missing":
        d.path.unlink()
    elif damage == "corrupt":
        d.path.write_text("{}", encoding="utf-8")
    else:
        data = json.loads(d.path.read_text())
        data["password_hash"] = "scrypt$2$8$1$00$00"
        d.path.write_text(json.dumps(data), encoding="utf-8")
    assert client.get("/api/settings").status_code == 503
    assert client.get("/api/auth/login").status_code == 503


def test_failed_account_write_preserves_login_and_original_file(dashboard_login):
    d = dashboard_login
    client, csrf = logged_in(d)
    original = d.path.read_bytes()
    with patch("autopwn_suite.web_auth.os.replace", side_effect=OSError("disk unavailable")):
        response = client.put("/api/auth/account", json={"username": "renamed", "current_password": d.password, "new_password": ""}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 503
    assert d.path.read_bytes() == original
    assert client.get("/api/settings").status_code == 200
    assert not list(d.path.parent.glob(".web_ui_auth.json.*.tmp"))


def test_account_replacement_retries_while_another_process_holds_the_file_open(tmp_path):
    # On Windows os.replace raises PermissionError while the running dashboard has the file open to check a session.
    store = AccountStore(tmp_path / ACCOUNT_FILE)
    real_replace, attempts = os.replace, []

    def contended(source, destination):
        attempts.append(source)
        if len(attempts) < 3:
            raise PermissionError(13, "Access is denied")
        return real_replace(source, destination)

    with patch("autopwn_suite.web_auth.os.replace", side_effect=contended), patch("autopwn_suite.web_auth.time.sleep") as sleep:
        username, password = store.reset()
    assert len(attempts) == 3 and sleep.call_count == 2
    assert username == "admin" and password_matches(password, store.load()["password_hash"])
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="only Windows refuses to replace a file that is open")
def test_reset_succeeds_when_a_reader_releases_the_account_file_shortly_after(tmp_path):
    import threading
    store = AccountStore(tmp_path / ACCOUNT_FILE)
    store.reset()
    reader = store.path.open(encoding="utf-8")
    timer = threading.Timer(.3, reader.close)
    real_replace, attempts = os.replace, []

    def replace_with_the_reader_still_open(source, destination):
        attempts.append(source)
        if len(attempts) == 1:
            timer.start()  # the reader is open for the first attempt, however long the password hash took
        return real_replace(source, destination)

    try:
        with patch("autopwn_suite.web_auth.os.replace", side_effect=replace_with_the_reader_still_open):
            username, password = store.reset()
    finally:
        timer.join()
        reader.close()
    assert len(attempts) > 1
    assert username == "admin" and password_matches(password, store.load()["password_hash"])


def test_account_replacement_gives_up_after_the_retries_and_keeps_the_original(tmp_path):
    store = AccountStore(tmp_path / ACCOUNT_FILE)
    store.reset()
    original = store.path.read_bytes()
    with patch("autopwn_suite.web_auth.os.replace", side_effect=PermissionError(13, "Access is denied")) as replace, \
            patch("autopwn_suite.web_auth.time.sleep"):
        with pytest.raises(PermissionError):
            store.reset()
    assert replace.call_count == 20
    assert store.path.read_bytes() == original and not list(tmp_path.glob(".*.tmp"))


def test_login_throttling_cannot_be_bypassed_by_new_challenges(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    for _ in range(5):
        assert sign_in(client, "incorrect-password").status_code == 401
    with patch("autopwn_suite.web_auth.password_matches") as verify:
        assert sign_in(client, d.password).status_code == 429
        verify.assert_not_called()
    assert sign_in(d.app.test_client(), d.password, environ_overrides={"REMOTE_ADDR": "127.0.0.2"}).status_code == 200


SIGN_IN_EXPIRED = {"error": "Sign-in expired. Refresh the page and retry."}


def present(client, cookie, csrf, password, **where):
    """Submit a sign-in with the given challenge cookie and CSRF token, as a client that holds just those."""
    client.set_cookie(LOGIN_COOKIE, cookie)
    return client.post("/api/auth/login", json={"username": "admin", "password": password},
                       headers={"X-CSRF-Token": csrf}, **where)


def start_sign_in(client, **where):
    csrf = client.get("/api/auth/login", **where).json["csrf_token"]
    return client.get_cookie(LOGIN_COOKIE).value, csrf


@pytest.mark.parametrize("peers", ["one shared address", "a thousand addresses"])
def test_a_flood_of_challenge_requests_never_invalidates_another_clients_pending_sign_in(dashboard_login, peers):
    d = dashboard_login

    def address(number):  # loopback, so the flood passes the HTTPS rule without a proxy
        return "127.0.0.1" if peers == "one shared address" else f"127.0.{number // 250}.{number % 250 + 1}"

    operator = d.app.test_client()
    operator_csrf = start_sign_in(operator)[1]  # the cookie stays in the operator's jar, as in a browser
    oldest_cookie, oldest_csrf = start_sign_in(d.app.test_client(), environ_overrides={"REMOTE_ADDR": address(0)})
    for number in range(1000):
        d.app.test_client().get("/api/auth/login", environ_overrides={"REMOTE_ADDR": address(number)})
    # Nothing was evicted: not the operator's challenge and not even the oldest one the flood overtook.
    response = operator.post("/api/auth/login", json={"username": "admin", "password": d.password},
                             headers={"X-CSRF-Token": operator_csrf})
    assert response.status_code == 200
    assert present(d.app.test_client(), oldest_cookie, oldest_csrf, d.password,
                   environ_overrides={"REMOTE_ADDR": address(0)}).status_code == 200


def test_issuing_challenges_keeps_no_server_side_state(dashboard_login):
    d = dashboard_login

    def sizes():
        # Every collection the object holds, so a new store for challenges could not hide from this check.
        return {name: len(value) for name, value in vars(d.auth).items() if isinstance(value, (dict, list, set, tuple))}

    assert {"sessions", "failures"} <= sizes().keys()
    before = sizes()
    client = d.app.test_client()
    for number in range(1000):
        client.get("/api/auth/login", environ_overrides={"REMOTE_ADDR": f"127.0.{number // 250}.{number % 250 + 1}"})
    assert sizes() == before == {"sessions": 0, "failures": 0}


def test_challenge_is_valid_only_for_the_process_token_and_account_it_was_issued_for(dashboard_login):
    auth = dashboard_login.auth
    revision = auth.store.load()["revision"]
    cookie, csrf = auth.new_challenge(revision)
    assert auth.challenge_valid(cookie, csrf, revision)
    assert not auth.challenge_valid(cookie, csrf, "0" * 32)  # another account revision
    assert not auth.challenge_valid(cookie, auth.new_challenge(revision)[1], revision)  # another challenge's token
    assert not DashboardAuth(auth.store).challenge_valid(cookie, csrf, revision)  # another process has another key
    for junk in (None, 5, b"x", [], {}, ""):
        assert not auth.challenge_valid(junk, csrf, revision) and not auth.challenge_valid(cookie, junk, revision)


def restart(d, cookie, csrf):
    d.auth.challenge_key = secrets.token_bytes(32)  # what a new process has: another random key
    return cookie, csrf


TAMPERED_CHALLENGES = {
    "longer lifetime": lambda d, cookie, csrf: (str(int(cookie.split(".")[0]) + 10 ** 6) + "." + cookie.split(".")[1], csrf),
    "one character of the signature changed": lambda d, cookie, csrf: (cookie[:-1] + ("A" if cookie[-1] != "A" else "B"), csrf),
    "signature cut short": lambda d, cookie, csrf: (cookie[:-1], csrf),
    "signature removed": lambda d, cookie, csrf: (cookie.split(".")[0] + ".", csrf),
    "text added": lambda d, cookie, csrf: (cookie + "A", csrf),
    "extra part": lambda d, cookie, csrf: (cookie + ".x", csrf),
    "empty": lambda d, cookie, csrf: ("", csrf),
    "token shaped like a session": lambda d, cookie, csrf: ("forged-session-token-" * 3, csrf),
    "well formed and signed by nobody": lambda d, cookie, csrf: (f"{int(time.time()) + 300}.{'A' * 43}", csrf),
    "issued by another dashboard process": lambda d, cookie, csrf: start_sign_in(d.wu._build_app(d.wu._STATIC_DIR).test_client()),
    "issued before a restart": restart,
}


@pytest.mark.parametrize("name", TAMPERED_CHALLENGES)
def test_tampered_forged_foreign_and_restarted_challenges_answer_403(dashboard_login, name):
    d = dashboard_login
    cookie, csrf = start_sign_in(d.app.test_client())
    client = d.app.test_client()
    response = present(client, *TAMPERED_CHALLENGES[name](d, cookie, csrf), d.password)
    assert response.status_code == 403 and response.json == SIGN_IN_EXPIRED
    assert client.get_cookie(COOKIE) is None and not d.auth.sessions
    assert not d.auth.failures  # a refused challenge never reaches the credentials, so it is not a failed sign-in


def test_a_restart_ends_open_challenges_and_a_fresh_one_works(dashboard_login):
    d = dashboard_login
    cookie, csrf = start_sign_in(d.app.test_client())
    restarted = d.wu._build_app(d.wu._STATIC_DIR)
    assert present(restarted.test_client(), cookie, csrf, d.password).status_code == 403
    assert sign_in(restarted.test_client(), d.password).status_code == 200


def test_a_challenge_lasts_five_minutes(dashboard_login):
    d = dashboard_login
    for elapsed, expected in ((0, 200), (290, 200), (301, 403), (86400, 403)):
        cookie, csrf = start_sign_in(d.app.test_client())
        with patch("autopwn_suite.web_auth.time.time", return_value=time.time() + elapsed):
            response = present(d.app.test_client(), cookie, csrf, d.password)
        assert response.status_code == expected, elapsed
        if expected == 403:
            assert response.json == SIGN_IN_EXPIRED


def test_challenge_cookie_alone_is_not_enough_the_csrf_token_must_match(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    cookie, csrf = start_sign_in(client)
    other = start_sign_in(d.app.test_client())[1]  # a valid token of another client's challenge
    credentials = {"username": "admin", "password": d.password}
    for header in ({}, {"X-CSRF-Token": ""}, {"X-CSRF-Token": other}, {"X-CSRF-Token": csrf[:-1]}, {"X-CSRF-Token": csrf + "A"},
                   {"X-CSRF-Token": csrf.swapcase()}, {"X-CSRF-Token": "é" * 43}):
        response = client.post("/api/auth/login", json=credentials, headers=header)
        assert response.status_code == 403 and response.json == SIGN_IN_EXPIRED, header
    assert not d.auth.failures
    assert client.post("/api/auth/login", json=credentials, headers={"X-CSRF-Token": csrf}).status_code == 200


def test_changing_the_account_ends_the_pending_challenges(dashboard_login):
    d = dashboard_login
    cookie, csrf = start_sign_in(d.app.test_client())
    d.auth.store.reset()  # what --web-reset-account does to the running dashboard's account
    response = present(d.app.test_client(), cookie, csrf, d.password)
    assert response.status_code == 403 and response.json == SIGN_IN_EXPIRED


def test_a_replayed_challenge_only_permits_a_throttled_sign_in_attempt_and_never_reuses_a_session(dashboard_login):
    # A challenge grants no authority: any client can fetch a new one. So the server does not record used
    # challenges, which would need a store; a replayed pair can only try credentials, and the throttle counts those.
    d = dashboard_login
    client = d.app.test_client()
    cookie, csrf = start_sign_in(client)
    first = client.post("/api/auth/login", json={"username": "admin", "password": d.password}, headers={"X-CSRF-Token": csrf})
    assert first.status_code == 200 and client.get_cookie(LOGIN_COOKIE) is None
    first_session = client.get_cookie(COOKIE).value
    replayer = d.app.test_client()
    second = present(replayer, cookie, csrf, d.password)
    assert second.status_code == 200
    # The session is new and random each time (no fixation); it is not derived from the challenge.
    assert len({first_session, replayer.get_cookie(COOKIE).value, cookie}) == 3
    assert len({first.json["csrf_token"], second.json["csrf_token"], csrf}) == 3
    assert replayer.get_cookie(LOGIN_COOKIE) is None  # the response clears the challenge cookie
    for _ in range(5):
        assert present(d.app.test_client(), cookie, csrf, "incorrect-password").status_code == 401
    with patch("autopwn_suite.web_auth.password_matches") as verify:
        assert present(d.app.test_client(), cookie, csrf, d.password).status_code == 429
        verify.assert_not_called()


def test_challenge_cookie_is_http_only_strict_and_reveals_neither_the_token_nor_the_account_revision(dashboard_login):
    d = dashboard_login
    response = d.app.test_client().get("/api/auth/login")
    header = next(value for value in response.headers.getlist("Set-Cookie") if value.startswith(LOGIN_COOKIE + "="))
    value, *attributes = [part.strip() for part in header.split(";")]
    assert {"HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=300"} <= set(attributes)
    cookie = value.split("=", 1)[1]
    assert response.json["csrf_token"] not in cookie and d.auth.store.load()["revision"] not in cookie
    assert re.fullmatch(r"[0-9]{10}\.[A-Za-z0-9_-]{43}", cookie)


def test_login_input_is_bounded_and_malformed_values_are_safe(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    for password in (None, [], "\ud800", "x" * 129):
        assert sign_in(client, password).status_code == 401
    challenge = client.get("/api/auth/login").json["csrf_token"]
    response = client.post("/api/auth/login", json={"username": "admin", "password": "x" * 5000}, headers={"X-CSRF-Token": challenge})
    assert response.status_code == 413


def test_lone_surrogate_username_is_a_throttled_failed_sign_in_not_a_server_error(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    for _ in range(5):
        assert sign_in(client, d.password, username="\ud800").status_code == 401
    assert d.auth.failures["127.0.0.1"][0] == 5
    assert sign_in(client, d.password).status_code == 429


def test_sign_in_body_nested_too_deeply_is_malformed_json_not_a_server_error(dashboard_login, monkeypatch):
    d = dashboard_login
    real_loads = json.loads

    def loads(text, *args, **kwargs):  # what Python 3.10 and 3.11 do with a body this deep
        if len(text) >= 4000:
            raise RecursionError("maximum recursion depth exceeded")
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", loads)
    client = d.app.test_client()
    challenge = client.get("/api/auth/login").json["csrf_token"]
    response = client.post("/api/auth/login", data="[" * 4090, content_type="application/json", headers={"X-CSRF-Token": challenge})
    assert response.status_code == 400 and response.json == {"error": "Enter your username and password."}
    assert sign_in(client, d.password).status_code == 200  # the valid sign-in still works


def test_account_file_that_cannot_be_parsed_is_unavailable_not_a_crash(tmp_path):
    store = AccountStore(tmp_path / ACCOUNT_FILE)
    store.reset()
    with patch("autopwn_suite.web_auth.json.loads", side_effect=RecursionError("maximum recursion depth exceeded")):
        with pytest.raises(AccountUnavailable):
            store.load()


def test_https_cookie_is_secure_and_no_auth_configuration_is_downloadable(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    response = client.get("/api/auth/login", base_url="https://localhost")
    assert "Secure" in response.headers["Set-Cookie"]
    for path in ("/web_ui_auth.json", "/../web_ui_auth.json", "/%2e%2e/web_ui_auth.json"):
        assert client.get(path).status_code == 302
    authenticated, _ = logged_in(d)
    assert authenticated.get("/web_ui_auth.json").status_code == 404


def test_concurrent_first_launch_creates_only_one_account(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = tmp_path / ACCOUNT_FILE
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: AccountStore(path).initialize(), range(2)))
    created = [result for result in results if result]
    assert len(created) == 1
    assert password_matches(created[0][1], AccountStore(path).load()["password_hash"])


def test_remote_cleartext_login_is_rejected_and_forwarded_headers_cannot_override_it(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    assert client.get("/login", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 200
    for forwarded in ({}, {"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"}):
        response = client.get("/api/auth/login", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}, headers=forwarded)
        assert response.status_code == 403
        assert "HTTPS" in response.json["error"]
    response = client.get("/api/auth/login", base_url="https://localhost", environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 200 and "Secure" in response.headers["Set-Cookie"]


def test_explicit_https_proxy_configuration_sets_secure_cookie_and_checks_public_origin(dashboard_login, monkeypatch):
    d = dashboard_login
    monkeypatch.setenv("AUTOPWN_WEB_SECURE_COOKIE", "1")
    app = d.wu._build_app(d.wu._STATIC_DIR)
    client = app.test_client()
    response = client.get("/api/auth/login", headers={"Origin": "https://localhost"}, environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 200 and "Secure" in response.headers["Set-Cookie"]
    assert client.get("/api/auth/login", headers={"Origin": "http://localhost"}).status_code == 403


def test_docker_bridge_peer_is_not_loopback_so_plain_http_sign_in_needs_host_networking(dashboard_login, monkeypatch):
    # `docker run -p 127.0.0.1:8080:8080` reaches the dashboard from the bridge gateway (172.17.0.1), not from loopback.
    d = dashboard_login

    def sign_in_from(app, peer, host, origin):
        client = app.test_client()
        where = {"base_url": f"http://{host}", "environ_overrides": {"REMOTE_ADDR": peer}}
        challenge = client.get("/api/auth/login", **where)
        if challenge.status_code != 200:
            return challenge
        return client.post("/api/auth/login", json={"username": "admin", "password": d.password}, **where,
                           headers={"Origin": origin, "X-CSRF-Token": challenge.json["csrf_token"]})

    refused = sign_in_from(d.app, "172.17.0.1", "localhost:8080", "http://localhost:8080")
    assert refused.status_code == 403 and "HTTPS" in refused.json["error"]
    # Host networking with AUTOPWN_WEB_HOST=127.0.0.1 (docker-compose.yml): the peer is loopback.
    assert sign_in_from(d.app, "127.0.0.1", "localhost:8080", "http://localhost:8080").status_code == 200

    monkeypatch.setenv("AUTOPWN_WEB_SECURE_COOKIE", "1")
    proxied = d.wu._build_app(d.wu._STATIC_DIR)
    # The setting alone does not help a browser on http://localhost:8080: its Origin is no longer the expected https one.
    refused = sign_in_from(proxied, "172.17.0.1", "localhost:8080", "http://localhost:8080")
    assert refused.status_code == 403 and "Cross-origin" in refused.json["error"]
    # A TLS proxy that keeps Host: the browser's https Origin matches the Host it sent.
    assert sign_in_from(proxied, "172.17.0.1", "autopwn.example.test", "https://autopwn.example.test").status_code == 200


def test_every_document_that_says_to_publish_the_container_port_to_loopback_explains_the_bridge_limit():
    root = Path(__file__).resolve().parents[2]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "network_mode: host" in compose and "AUTOPWN_WEB_HOST=127.0.0.1" in compose  # the setup the documents point to
    instruction = re.compile(r"publish (?:its |the )?(?:port|it) to loopback|127\.0\.0\.1:8080:8080")
    giving = []
    for path in ("Dockerfile", "README.md", "AGENTS.md", *sorted(p.relative_to(root).as_posix() for p in (root / "docs").glob("*.md"))):
        text = re.sub(r"\s*\n\s*(?:#\s*)?", " ", (root / path).read_text(encoding="utf-8"))
        if instruction.search(text):
            giving.append(path)
            assert "bridge" in text and ("not loopback" in text or "non-loopback" in text), f"{path} says to publish to loopback without the bridge caveat"
    assert len(giving) >= 6, f"the instruction check found only {giving}; the wording changed shape"


def test_responses_carry_hardening_headers_and_hide_server_versions(dashboard_login):
    client = dashboard_login.app.test_client()
    login_page = client.get("/login")
    for response in (login_page, client.get("/login.js"), client.get("/api/auth/session"), client.get("/missing")):
        headers = response.headers
        assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
        assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert "camera=()" in headers["Permissions-Policy"] and "microphone=()" in headers["Permissions-Policy"]
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert "base-uri 'none'" in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"


def test_real_server_sends_exactly_one_server_header_without_versions(dashboard_login):
    import http.client
    import threading

    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", 0, dashboard_login.app, threaded=True,
                         request_handler=dashboard_login.wu._quiet_request_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/login")
        response = connection.getresponse()
        response.read()
        servers = [value for name, value in response.getheaders() if name.lower() == "server"]
        connection.close()
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()
    assert servers == ["AutoPWN-Suite"]


def test_unauthenticated_responses_get_the_strict_policy(dashboard_login):
    client = dashboard_login.app.test_client()
    for path in ("/", "/missing", "/api/scans"):
        policy = client.get(path).headers["Content-Security-Policy"]
        assert "default-src 'none'" in policy and "unsafe-inline" not in policy, path


def test_sign_in_policy_is_strict_and_dashboard_policy_stays_same_origin(dashboard_login):
    client, _ = logged_in(dashboard_login)
    login_policy = client.get("/login").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in login_policy and "unsafe-eval" not in login_policy
    assert "default-src 'none'" in login_policy and "script-src 'self'" in login_policy
    dashboard = client.get("/")
    policy = dashboard.headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy and "object-src 'none'" in policy
    assert "unsafe-eval" not in policy and "http:" not in policy and "https:" not in policy and " *" not in policy
    # The login page must not rely on inline code, or its strict policy would break it.
    markup = client.get("/login").get_data(as_text=True)
    assert "<script>" not in markup and "<style" not in markup and " onclick=" not in markup
    assert 'method="post"' in markup  # no credentials in a URL if scripts fail to load


def test_account_update_never_echoes_unexpected_error_text_but_keeps_validation_messages(dashboard_login):
    client, csrf = logged_in(dashboard_login)
    body = {"username": "admin", "current_password": dashboard_login.password, "new_password": "short"}
    rule = client.put("/api/auth/account", json=body, headers={"X-CSRF-Token": csrf})
    assert rule.status_code == 400 and "15" in rule.json["error"]  # the failed rule is shown to the user

    with patch("autopwn_suite.web_auth.AccountStore.change", side_effect=ValueError("INTERNAL-DETAIL /srv/path")):
        leaked = client.put("/api/auth/account", json={**body, "new_password": "a-long-enough-new-password"},
                            headers={"X-CSRF-Token": csrf})
    assert leaked.status_code == 400
    assert "INTERNAL-DETAIL" not in leaked.get_data(as_text=True) and "/srv/path" not in leaked.get_data(as_text=True)
