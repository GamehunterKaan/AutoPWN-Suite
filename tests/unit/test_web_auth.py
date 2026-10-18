# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Authentication boundary, browser forgery defenses and local account recovery."""

import importlib
import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from autopwn_suite.web_auth import ACCOUNT_FILE, COOKIE, LOGIN_COOKIE, AccountStore, AccountUnavailable, password_matches


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


def test_expired_session_and_forged_cookie_fail_closed(dashboard_login):
    d = dashboard_login
    client, _ = logged_in(d)
    for key, entry in list(d.auth.sessions.items()):
        if entry.authenticated:
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


def test_login_throttling_cannot_be_bypassed_by_new_challenges(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    for _ in range(5):
        assert sign_in(client, "incorrect-password").status_code == 401
    with patch("autopwn_suite.web_auth.password_matches") as verify:
        assert sign_in(client, d.password).status_code == 429
        verify.assert_not_called()
    assert sign_in(d.app.test_client(), d.password, environ_overrides={"REMOTE_ADDR": "127.0.0.2"}).status_code == 200


def test_login_input_is_bounded_and_malformed_values_are_safe(dashboard_login):
    d = dashboard_login
    client = d.app.test_client()
    for password in (None, [], "\ud800", "x" * 129):
        assert sign_in(client, password).status_code == 401
    challenge = client.get("/api/auth/login").json["csrf_token"]
    response = client.post("/api/auth/login", json={"username": "admin", "password": "x" * 5000}, headers={"X-CSRF-Token": challenge})
    assert response.status_code == 413


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
