# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Explicit real authentication for existing dashboard behavior fixtures."""

from functools import cache

from flask.testing import FlaskClient

from autopwn_suite.web_auth import ACCOUNT_FILE, COOKIE, AccountStore, password_hash

TEST_PASSWORD = "Test-only dashboard password 2026!"


@cache
def fixture_hash():
    return password_hash(TEST_PASSWORD)


def authenticated_app(wu, static_dir=None):
    path = wu._SETTINGS_FILE.parent / ACCOUNT_FILE
    store = AccountStore(path)
    with store.transaction():
        store._save("test-admin", fixture_hash())
    app = wu._build_app(static_dir or wu._STATIC_DIR, account_path=path)
    app.config["TESTING"] = True
    client = app.test_client()
    challenge = client.get("/api/auth/login").get_json()["csrf_token"]
    response = client.post("/api/auth/login", json={"username": "test-admin", "password": TEST_PASSWORD},
                           headers={"X-CSRF-Token": challenge})
    assert response.status_code == 200
    token = client.get_cookie(COOKIE).value
    csrf = response.get_json()["csrf_token"]

    class AuthenticatedClient(FlaskClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.set_cookie(COOKIE, token)

        def open(self, *args, **kwargs):
            if kwargs.get("method", "GET").upper() not in ("GET", "HEAD", "OPTIONS"):
                headers = dict(kwargs.get("headers") or {})
                headers.setdefault("X-CSRF-Token", csrf)
                kwargs["headers"] = headers
            return super().open(*args, **kwargs)

    app.test_client_class = AuthenticatedClient
    return app
