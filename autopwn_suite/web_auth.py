# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Single administrator account, private password hashes and revocable sessions."""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ACCOUNT_FILE = "web_ui_auth.json"
COOKIE = "autopwn_session"
LOGIN_COOKIE = "autopwn_login"
SESSION_SECONDS = 8 * 60 * 60
# One client address cannot hold more pending sign-in challenges than this, so a flood of cookie-less
# GET /api/auth/login requests only evicts its own challenges rather than the operator's.
PENDING_CHALLENGES_PER_ADDRESS = 16
LOGIN_ASSETS = frozenset({"/login", "/login.js", "/login.css"})
# The sign-in page uses no inline script or style, so it gets a strict policy.
LOGIN_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
             "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
# The dashboard still relies on inline event handlers and style attributes, so it must allow
# 'unsafe-inline' for now; everything else is limited to the same origin. Removing the inline
# handlers would let this become as strict as the sign-in policy.
DASHBOARD_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                 "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; form-action 'self'; "
                 "base-uri 'none'; frame-ancestors 'none'")
PERMISSIONS_POLICY = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), interest-cohort=()"
_USERNAME = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_HASH = re.compile(r"scrypt\$32768\$8\$3\$[0-9a-f]{32}\$[0-9a-f]{128}")


class AccountUnavailable(RuntimeError):
    pass


class InvalidCredentials(ValueError):
    pass


class InvalidAccount(ValueError):
    """The submitted username or password breaks the account rules; the message is safe to show."""


# Responses use these fixed texts, never the text of a caught exception.
ACCOUNT_UNAVAILABLE = "Dashboard account is unavailable. Run --web-reset-account on the server."
CREDENTIALS_REJECTED = "Current password is incorrect or the account changed."


def validate_account(username, password):
    if not isinstance(username, str) or not _USERNAME.fullmatch(username):
        raise InvalidAccount("Username must contain 1–64 letters, numbers, dots, underscores, @ or hyphens.")
    if not isinstance(password, str) or not 15 <= len(password) <= 128 or password.isspace():
        raise InvalidAccount("Password must contain 15–128 characters.")
    try:
        password.encode("utf-8")
    except UnicodeError:
        raise InvalidAccount("Password contains invalid Unicode.") from None


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=32768, r=8, p=3,
                            maxmem=64 * 1024 * 1024, dklen=64)
    return f"scrypt$32768$8$3${salt.hex()}${digest.hex()}"


def password_matches(password, encoded):
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        return False
    salt, expected = encoded.split("$")[-2:]
    try:
        candidate = password.encode("utf-8")
    except UnicodeError:
        return False
    actual = hashlib.scrypt(candidate, salt=bytes.fromhex(salt), n=32768, r=8, p=3,
                            maxmem=64 * 1024 * 1024, dklen=64)
    return secrets.compare_digest(actual.hex(), expected)


class AccountStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()

    @contextmanager
    def transaction(self):
        """Serialize changes with CLI resets, including separate processes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(str(self.path) + ".lock", flags, 0o600)
            try:
                until = time.monotonic() + 5
                while True:
                    try:
                        if os.name == "nt":
                            import msvcrt
                            os.lseek(descriptor, 0, os.SEEK_SET)
                            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() >= until:
                            raise AccountUnavailable("Account file is busy; retry the operation.") from None
                        time.sleep(.05)
                yield
            finally:
                # Closing the descriptor releases the OS lock even after failure.
                os.close(descriptor)

    def load(self):
        try:
            with self.lock, self.path.open(encoding="utf-8") as source:
                raw = source.read(4097)
            if len(raw) > 4096:
                raise ValueError("Account configuration is too large")
            data = json.loads(raw)
            if (not isinstance(data, dict) or set(data) != {"username", "password_hash", "revision"}
                    or not isinstance(data["username"], str) or not _USERNAME.fullmatch(data["username"])
                    or not isinstance(data["password_hash"], str) or not _HASH.fullmatch(data["password_hash"])
                    or not isinstance(data["revision"], str) or not re.fullmatch(r"[0-9a-f]{32}", data["revision"])):
                raise ValueError("Invalid account configuration")
            return data
        except (OSError, ValueError, UnicodeError):
            raise AccountUnavailable(ACCOUNT_UNAVAILABLE) from None

    def _save(self, username, encoded):
        data = {"username": username, "password_hash": encoded, "revision": secrets.token_hex(16)}
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(16)}.tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(data, output, indent=2)
                output.flush()
                os.fsync(output.fileno())
            # On Windows, replacing a file that another process has open fails with PermissionError until
            # it is closed, and the running dashboard opens this one on every request, so retry briefly.
            for attempt in range(20):
                try:
                    os.replace(temporary, self.path)
                    break
                except PermissionError:
                    if attempt == 19:
                        raise
                    time.sleep(.05)
        finally:
            temporary.unlink(missing_ok=True)
        return data

    def initialize(self):
        with self.transaction():
            if self.path.exists():
                self.load()  # Corruption never silently restores a default account.
                return None
            password = secrets.token_urlsafe(24)
            self._save("admin", password_hash(password))
            return "admin", password

    def reset(self):
        with self.transaction():
            password = secrets.token_urlsafe(24)
            self._save("admin", password_hash(password))
            return "admin", password

    def change(self, revision, current_password, username, new_password):
        with self.transaction():
            data = self.load()
            if data["revision"] != revision or not password_matches(current_password, data["password_hash"]):
                raise InvalidCredentials(CREDENTIALS_REJECTED)
            validate_account(username, new_password if new_password else "validation-placeholder")
            encoded = password_hash(new_password) if new_password else data["password_hash"]
            return self._save(username, encoded)


def show_credentials(credentials, path):
    if credentials:
        username, password = credentials
        print("\n  Dashboard account created. Save this password; it is shown only now.")
        print(f"  Username: {username}\n  Password: {password}\n  Account file: {path}\n")


@dataclass(frozen=True)
class LoginSession:
    revision: str
    csrf: str
    expires: float
    authenticated: bool
    address: str = ""


class DashboardAuth:
    def __init__(self, store):
        self.store = store
        self.sessions = {}
        self.failures = {}
        self.lock = threading.RLock()
        self.hash_slots = threading.BoundedSemaphore(2)

    def new_session(self, revision, *, authenticated, address=""):
        token = secrets.token_urlsafe(32)
        entry = LoginSession(revision, secrets.token_urlsafe(32), time.monotonic() + (SESSION_SECONDS if authenticated else 300), authenticated, address)
        with self.lock:
            self.sessions = {key: value for key, value in self.sessions.items() if value.expires > time.monotonic()}
            # Keep unauthenticated challenge floods from evicting logged-in users.
            matching = [key for key, value in self.sessions.items() if value.authenticated == authenticated]
            if not authenticated:
                own = [key for key in matching if self.sessions[key].address == address]
                if len(own) >= PENDING_CHALLENGES_PER_ADDRESS:
                    self.sessions.pop(own[0])
                    matching.remove(own[0])
            if len(matching) >= 128:
                self.sessions.pop(matching[0])
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = entry
        return token, entry

    def find(self, token, *, authenticated=True):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            entry = self.sessions.get(key)
        if not entry or entry.authenticated != authenticated:
            return None
        if entry.expires <= time.monotonic() or entry.revision != self.store.load()["revision"]:
            self.revoke(token)
            return None
        return entry

    def revoke(self, token):
        if isinstance(token, str):
            with self.lock:
                self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)

    def stream_valid(self, token):
        try:
            return self.find(token) is not None
        except AccountUnavailable:
            return False

    def rate_limited(self, address):
        with self.lock:
            now = time.monotonic()
            self.failures = {key: value for key, value in self.failures.items() if value[1] > now}
            return self.failures.get(address, (0, 0))[0] >= 5 or sum(value[0] for value in self.failures.values()) >= 30

    def failed(self, address):
        with self.lock:
            count, until = self.failures.get(address, (0, time.monotonic() + 60))
            self.failures[address] = count + 1, until


def install_auth(app, static_dir, account_path):
    """Install before all other handlers so new routes are private by default."""
    from urllib.parse import urlsplit

    from flask import g, jsonify, redirect, request, send_from_directory

    store = AccountStore(account_path)
    show_credentials(store.initialize(), store.path)
    auth = DashboardAuth(store)
    app.extensions["dashboard_auth"] = auth
    secure_cookie = os.environ.get("AUTOPWN_WEB_SECURE_COOKIE") == "1"
    public = {"/login", "/login.js", "/login.css", "/favicon.ico", "/api/auth/login"}

    def set_cookie(response, token, *, login=False):
        response.set_cookie(LOGIN_COOKIE if login else COOKIE, token, max_age=300 if login else SESSION_SECONDS,
                            httponly=True, secure=secure_cookie or request.is_secure, samesite="Strict", path="/")

    def csrf_valid(entry):
        token = request.headers.get("X-CSRF-Token", "")
        return bool(entry and re.fullmatch(r"[A-Za-z0-9_-]{43}", token) and secrets.compare_digest(entry.csrf, token))

    @app.before_request
    def authenticate_request():
        if request.path in ("/api/auth/login", "/api/auth/account"):
            request.max_content_length = 4096
        try:
            local = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            local = False
        # A TLS-terminating proxy must be explicitly configured and its backend
        # restricted; untrusted forwarded headers never change this decision.
        if request.path not in public - {"/api/auth/login"} and not (local or request.is_secure or secure_cookie):
            return jsonify({"error": "HTTPS is required for remote dashboard access. Use HTTPS or connect through localhost."}), 403
        origin = request.headers.get("Origin")
        expected = ("https" if secure_cookie else request.scheme, request.host.lower())
        if origin:
            try:
                parsed = urlsplit(origin)
                same = (parsed.scheme, parsed.netloc.lower()) == expected and not parsed.path and not parsed.query and not parsed.fragment
            except ValueError:
                same = False
            if not same:
                return jsonify({"error": "Cross-origin requests are not allowed."}), 403
        if request.path in public:
            return None
        try:
            g.dashboard_session = auth.find(request.cookies.get(COOKIE))
        except AccountUnavailable:
            return jsonify({"error": ACCOUNT_UNAVAILABLE}), 503
        if g.dashboard_session is None:
            if request.path.startswith("/api/") or request.method not in ("GET", "HEAD"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect("/login")
        if request.method not in ("GET", "HEAD", "OPTIONS") and not csrf_valid(g.dashboard_session):
            return jsonify({"error": "Invalid or missing CSRF token. Refresh the page and retry."}), 403

    @app.after_request
    def private_responses(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        # Only an authenticated dashboard page needs the looser policy; sign-in, redirects and errors get the strict one.
        signed_in = getattr(g, "dashboard_session", None) is not None
        response.headers["Content-Security-Policy"] = DASHBOARD_CSP if signed_in and request.path not in LOGIN_ASSETS else LOGIN_CSP
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return response

    @app.get("/login")
    def dashboard_login_page():
        return send_from_directory(str(static_dir), "login.html")

    @app.route("/api/auth/login", methods=["GET", "POST"])
    def dashboard_login():
        try:
            data = store.load()
            if request.method == "GET":
                auth.revoke(request.cookies.get(LOGIN_COOKIE))
                token, entry = auth.new_session(data["revision"], authenticated=False, address=request.remote_addr or "unknown")
                response = jsonify({"csrf_token": entry.csrf})
                set_cookie(response, token, login=True)
                return response
            challenge = auth.find(request.cookies.get(LOGIN_COOKIE), authenticated=False)
            if not csrf_valid(challenge):
                return jsonify({"error": "Sign-in expired. Refresh the page and retry."}), 403
            if not request.is_json:
                return jsonify({"error": "Sign-in requires JSON."}), 400
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) != {"username", "password"}:
                return jsonify({"error": "Enter your username and password."}), 400
            address = request.remote_addr or "unknown"
            if auth.rate_limited(address) or not auth.hash_slots.acquire(blocking=False):
                return jsonify({"error": "Too many sign-in attempts. Try again in a minute."}), 429, {"Retry-After": "60"}
            try:
                password_ok = password_matches(body["password"], data["password_hash"])
                # surrogatepass: a lone surrogate in the JSON must be a failed sign-in, not an encoding error.
                username_ok = isinstance(body["username"], str) and secrets.compare_digest(
                    body["username"].encode("utf-8", "surrogatepass"), data["username"].encode())
            finally:
                auth.hash_slots.release()
            if not username_ok or not password_ok:
                auth.failed(address)
                return jsonify({"error": "Incorrect username or password."}), 401
            auth.revoke(request.cookies.get(COOKIE))
            auth.revoke(request.cookies.get(LOGIN_COOKIE))
            token, entry = auth.new_session(data["revision"], authenticated=True)
            response = jsonify({"username": data["username"], "csrf_token": entry.csrf})
            set_cookie(response, token)
            response.delete_cookie(LOGIN_COOKIE, path="/")
            return response
        except AccountUnavailable:
            return jsonify({"error": ACCOUNT_UNAVAILABLE}), 503

    @app.get("/api/auth/session")
    def dashboard_session():
        try:
            return jsonify({"username": store.load()["username"], "csrf_token": g.dashboard_session.csrf})
        except AccountUnavailable:
            return jsonify({"error": ACCOUNT_UNAVAILABLE}), 503

    @app.post("/api/auth/logout")
    def dashboard_logout():
        auth.revoke(request.cookies.get(COOKIE))
        response = jsonify({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.put("/api/auth/account")
    def dashboard_account():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) != {"username", "current_password", "new_password"}:
            return jsonify({"error": "Enter your username, current password and optional new password."}), 400
        if not isinstance(body["new_password"], str):
            return jsonify({"error": "New password must be text."}), 400
        address = request.remote_addr or "unknown"
        if auth.rate_limited(address) or not auth.hash_slots.acquire(blocking=False):
            return jsonify({"error": "Too many attempts. Try again in a minute."}), 429
        try:
            data = store.change(g.dashboard_session.revision, body["current_password"], body["username"], body["new_password"])
            token, entry = auth.new_session(data["revision"], authenticated=True)
            auth.revoke(request.cookies.get(COOKIE))
            response = jsonify({"username": data["username"], "csrf_token": entry.csrf})
            set_cookie(response, token)
            return response
        except InvalidCredentials:
            auth.failed(address)
            return jsonify({"error": CREDENTIALS_REJECTED}), 403
        except InvalidAccount as error:
            # Intentional: these messages are written in validate_account() so the user learns which rule failed.
            return jsonify({"error": str(error)}), 400
        except ValueError:
            return jsonify({"error": "The account details could not be used."}), 400
        except (AccountUnavailable, OSError):
            return jsonify({"error": "Account could not be saved. The previous account is unchanged."}), 503
        finally:
            auth.hash_slots.release()

    return auth
