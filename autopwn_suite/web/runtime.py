# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Thread-local web scan budgets, cancellation, progress and redacted evidence."""

import hashlib
import json
import re
import time
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from autopwn_suite.nmap_progress import ScanCancelled
from autopwn_suite.text import printable, wire_url
from autopwn_suite.web.options import CHECKS as CHECKS
from autopwn_suite.web.options import TYPE_CHECK, normalize_options

ACTIVE = ContextVar("web_scan_context", default=None)


class WebBudgetExceeded(RuntimeError):
    pass


def options():
    current = ACTIVE.get()
    return current.options if current else normalize_options()


def enabled(name):
    return options()["checks"].get(name, False)


def allowed(kind):
    return enabled(TYPE_CHECK.get(kind, "headers"))


# Query parameters that hold a credential. A redacted value cannot be replayed, so a few ordinary words that contain
# a keyword are left alone: "author" (but not "authorization") and "bypass" or "passenger" (but "pass", "userpass",
# "newPass"). Every other name containing "pass" is redacted, because credential names are not words. The short
# names (sig, sid, otp, cred) count only as a whole word or as a camelCase part ("x_sig", "userSid" but not "design",
# "inside"), and "key" or "code" alone or "key" after a credential word ("access_key", "appKey" but not "sort_key",
# "monkey", "country_code", "zipcode"): an OAuth callback carries a credential in "code". Replays keep working for every
# other parameter, and a secret in a parameter with any other name is shown as is, as is a credential inside the value
# of another parameter (`redirect_uri=https%3A%2F%2Fapp%2Fcb%3Fcode%3Dabc`): only the outer name is read.
SENSITIVE_PARAMETER = re.compile(r"auth(?!or(?!iz|is))|(?<!by)(?<!com)(?<!sur)(?<!tres)pass(?!age|enger|port|ive|ion|able|over)"
                                 r"|secret|token|session|sessid|jwt|signature|csrf|xsrf|credential|bearer|pwd|cookie|hmac|verifier|samlresponse|relaystate"
                                 r"|(?:api|access|private|app|client|consumer|licen[cs]e|encryption|signing|master|service|ssh|developer).?key|^key$|^code$"
                                 r"|(?<![a-z])(?:sig|sid|otp|totp|hotp|cred|creds|pw|ticket|nonce)(?![a-z])"
                                 r"|(?-i:(?<=[a-z0-9])(?:Sig|Sid|Otp|Pw|Ticket|Nonce)(?![a-zA-Z]))"
                                 r"|(?<![a-z])(?:verif(?:y|ication)|reset|recovery|backup|activation|invite|mfa|2fa|sms|login)[_-]?code", re.I)
_SEPARATOR = re.compile(r"([&;])")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
_AUTHORITY_END = re.compile(r"[/\\?#]")
_PATH_PARAMETER = re.compile(r";([^=;/]*)=([^;/]+)")
# A word of free text ends at ASCII whitespace only. Quotes, angle brackets and Unicode spaces (U+00A0, U+2028, U+3000)
# can be part of a URL a target chose, so they must not cut one in two: the part after the cut would stay unredacted.
_WORD = re.compile(r"[^ \t\r\n]+")
_TRAILING = ".,;:)"  # sentence punctuation after a URL
_CLOSERS = {"(": ")", "<": ">", "[": "]", "{": "}", "'": "'", '"': '"'}  # what closes a bracket or a quote in front of a URL
_LEADING = "".join(_CLOSERS)


def _rewrite_query(query, rewrite):
    """Apply `rewrite(name, equals, value)` to each pair of a query string (pairs end at & or ;) and keep every other
    character as given, so an unredacted URL still replays byte for byte."""
    parts = _SEPARATOR.split(query)
    for index in range(0, len(parts), 2):
        parts[index] = rewrite(*parts[index].partition("="))
    return "".join(parts)


def _hide_named(name, equals, value):
    return f"{name}=REDACTED" if value and SENSITIVE_PARAMETER.search(unquote_plus(name)) else name + equals + value


def _hide_values(name, equals, value):
    return f"{name}=REDACTED" if value else name + equals


def _hide_every(name, equals, value):
    # A part without "=" is no name: "/verify?3f9a7c" is a bare token as often as a flag, so it goes whole.
    # Free text keeps such a part in a target without a scheme ("what?"); a whole target never does.
    return _hide_values(name, equals, value) if equals else "REDACTED" if name else ""


def redact_url(url):
    """Redact the credential-named query values and the userinfo of a URL, for findings and the requests a PoC
    replays: a value of any other name stays so that the request can still be sent. A control or layout character
    that a host put in the URL (a crawled link, a redirect) is percent-encoded as the HTTP client sends it (see
    `wire_url`), so the stored URL is plain text and names the request that was sent; `urlsplit` would otherwise drop a
    CR, LF or tab. Use `redact_text` or `redact_target` for diagnostics."""
    try:
        parts = urlsplit(wire_url(url))
        return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1],
                                         query=_rewrite_query(parts.query, _hide_named), fragment=""))
    except ValueError:
        return "Invalid URL"


def _redact_target(target, rewrites):
    """Rewrite the query and the `;name=value` parameters of one URL, or of a target typed without a scheme
    (`host:80/p?x=y`, `[::1]:80?x=y`), and drop its userinfo and fragment. Plain string work: it never raises.
    `rewrites` holds the rewrite for a target without a scheme and the one for a URL."""
    cut = target.find("://")
    scheme = target[:cut + 3] if cut == 0 or cut > 0 and _SCHEME.fullmatch(target, 0, cut) else ""
    rewrite = rewrites[bool(scheme)]
    rest = target[len(scheme):]
    lead = "//" if rest.startswith("//") else ""  # a network-path reference, //user:pw@host/
    rest = rest[len(lead):]
    found = _AUTHORITY_END.search(rest)
    end = found.start() if found else len(rest)
    userinfo, _, host = rest[:end].rpartition("@")
    path, question, query = rest[end:].partition("#")[0].partition("?")
    path = _PATH_PARAMETER.sub(lambda match: ";" + rewrite(match[1], "=", match[2]), path)
    return scheme + lead + (host if userinfo else rest[:end]) + path + (question + _rewrite_query(query, rewrite) if question else "")


def _redact_token(token, rewrites):
    core = token.rstrip(_TRAILING)
    start = core.find("://")
    if start >= 0:
        # `url=http://h/?a=b` or `(http://h/?a=b`: begin at the scheme, unless what precedes it is itself a URL part.
        while start and core[start - 1].isascii() and (core[start - 1].isalnum() or core[start - 1] in "+.-"):
            start -= 1
        if any(mark in core[:start] for mark in "?#@"):
            start = 0
    elif any(mark in core for mark in "?@") or core.find("#") > 0:
        start = len(core) - len(core.lstrip(_LEADING))
    else:
        return token
    tail = token[len(core):]
    # A URL inside quotes or brackets: the closer that matches an opener in front of it belongs to the text, not to the last value.
    for opener in reversed(core[:start]):
        if opener not in _CLOSERS:
            break
        if len(core) > start + 1 and core.endswith(_CLOSERS[opener]):
            core, tail = core[:-1], _CLOSERS[opener] + tail
            break
    return core[:start] + _redact_target(core[start:], rewrites) + tail


def redact_target(target):
    """Redact a string that is known to be one target as typed (a job record, an answer, a report file name): every
    query value, a query part without `=`, the userinfo, the fragment and `;name=value` path parameters, whatever the
    parameter is called and whatever the case of the scheme. The whole string is one target, so nothing in it (a quote,
    an angle bracket, any kind of space) can end the URL early and leave a later part unredacted. Network targets
    (`192.0.2.0/24`) come back as they were. The control characters a target can carry are dropped (see `printable`)."""
    return _redact_target(printable(str(target)), (_hide_every, _hide_every))


def redact_text(message, *, names_only=False):
    """Redact the URLs and the targets typed without a scheme in a log line, coverage note or other free text: every
    query value (names stay: `?id=REDACTED&x=REDACTED`), the userinfo, the fragment and `;name=value` path parameters,
    whatever the parameter is called and whatever the case of the scheme. Diagnostics reach the console, exports and
    saved reports, so unlike findings they cannot keep a value for a replay: `names_only=True` redacts the values of
    credential names only, as `redact_url` does, for the text of a finding. A word of the message starts a URL at its
    scheme, or holds a `?`, an `@` or a `#`, and runs to the next space, tab or line break: a quote, an angle bracket or a
    Unicode space inside it does not end it, and only sentence punctuation at its end (`.`, `,`, `;`, `:`, `)`) and the
    quote or bracket that closes the one in front of it is left out. A query part without `=` goes whole in a URL (`?3f9a7c`) and stays in a target without a scheme (`what?`);
    use `redact_target` when the string is a target. The message also loses the control characters a crawled URL can
    carry (see `printable`). A secret in the path of a URL stays, and so does a URL with a space inside it: its part after
    the space is another word."""
    rewrites = (_hide_named, _hide_named) if names_only else (_hide_values, _hide_every)
    return _WORD.sub(lambda match: _redact_token(match[0], rewrites), printable(str(message)))


def public_request(method, url, headers=None, role="probe"):
    safe_headers = {name: str(value)[:512] for name, value in (headers or {}).items()
                    if name.lower() in ("user-agent", "origin", "host", "x-forwarded-host", "x-autopwn-trace", "cache-control")}
    safe_url = redact_url(url)
    return {"method": method.upper(), "url": safe_url, "headers": safe_headers, "role": role,
            "redacted": "REDACTED" in safe_url or len(safe_url) > 8192}


class ScanContext:
    def __init__(self, target, log, *, controls=None, should_stop=None, progress=None, on_finding=None, checkpoint=None):
        self.target = target
        self.log = log
        self.options = normalize_options(controls)
        self.should_stop = should_stop or (lambda: False)
        self.progress = progress
        self.on_finding = on_finding
        self.requests = 0
        self.state = checkpoint if checkpoint is not None else {}
        self.state.setdefault("tasks", {})
        self.state.setdefault("findings", [])
        self.findings = deepcopy(self.state["findings"])
        self.finding_ids = {old["id"] for old in self.findings}
        self.records = deque(maxlen=self.options["request_budget"])
        self.issues = []
        self.phase = "Preparing web checks"
        self.discovery = False
        self.problem_revision = 0
        self.last_request = None
        self.task_name = None
        self.task_url = None

    @contextmanager
    def activate(self):
        token = ACTIVE.set(self)
        try:
            yield self
        finally:
            ACTIVE.reset(token)

    def checkpoint(self):
        if self.should_stop():
            raise ScanCancelled("Web scan stopped")

    def stage(self, name):
        self.checkpoint()
        self.phase = name
        self.publish_progress()

    def publish_progress(self):
        if self.progress:
            self.progress(self.phase, self.requests, self.options["request_budget"])

    def before(self):
        self.checkpoint()
        if self.requests >= self.options["request_budget"]:
            self.issue("Request budget reached; coverage is limited.")
            raise WebBudgetExceeded("Web request budget reached")
        # Speed controls pacing, independently of the port scanner's timing.
        delay = max((5000, 2000, 500, 100, 25, 0)[self.options["speed"]],
                    self.options["request_delay_ms"]) / 1000
        if self.last_request is not None:
            remaining = self.last_request + delay - time.monotonic()
            while remaining > 0:
                time.sleep(min(remaining, .1))
                self.checkpoint()
                remaining = self.last_request + delay - time.monotonic()
        self.last_request = time.monotonic()
        self.requests += 1
        self.publish_progress()
        return time.monotonic()

    def issue(self, message):
        message = redact_text(message)
        self.problem_revision += 1
        if message not in self.issues:
            self.issues.append(message)
            self.log.logger("warning", message)

    def task_key(self, name, url):
        return json.dumps([name, url])

    def task_done(self, name, url):
        return self.task_key(name, url) in self.state["tasks"]

    def run_task(self, name, url, action):
        self.checkpoint()
        key = self.task_key(name, url)
        if key in self.state["tasks"]:
            return deepcopy(self.state["tasks"][key])
        revision = self.problem_revision
        previous = self.task_name, self.task_url
        self.task_name, self.task_url = name, url
        try:
            results = action()
        finally:
            self.task_name, self.task_url = previous
        if self.problem_revision == revision:
            self.state["tasks"][key] = deepcopy(results)
        return results

    def capture(self, response, method, url, headers, started):
        request = public_request(method, url, headers)
        response_headers = {}
        for name, value in response.headers.items():
            if name.lower() in ("content-type", "content-length", "location", "server", "allow", "cache-control",
                                "access-control-allow-origin", "access-control-allow-credentials", "content-security-policy",
                                "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"):
                response_headers[name] = printable(redact_url(value)[:2048] if name.lower() == "location" else str(value)[:2048])
        captured = {"request": request, "phase": self.phase, "response": {"status": response.status_code, "headers": response_headers,
                    "bytes_captured": len(response.content), "sha256": hashlib.sha256(response.content).hexdigest(),
                    "truncated": response.autopwn_truncated,
                    "duration_ms": round(1000 * (time.monotonic() - started), 1)}}
        self.records.append(captured)
        if response.autopwn_truncated:
            self.issue("Response size limit reached; content coverage is limited.")
        return captured

    def annotate(self, result, reproduction=None):
        from autopwn_suite.web.details import describe_finding
        result = deepcopy(result)
        result["url"] = redact_url(result["url"])
        result["id"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:24]
        result["observed_at"] = datetime.now(timezone.utc).isoformat()
        reproduction = deepcopy(reproduction or {"strategy": "response", "requests": [{"method": "GET", "url": result["url"]}]})
        reproduction["requests"] = [public_request(row.get("method", "GET"), row["url"], row.get("headers"), row.get("role", "probe"))
                                    for row in reproduction.get("requests", [])[:12]]
        # A replay reads only the origin of the target; the requests carry the URLs, so every value can go here.
        reproduction["target"] = redact_target(reproduction.get("target", self.target))
        reproduction["verify_tls"] = self.options["verify_tls"]
        result["reproduction"] = reproduction
        result["observations"] = []
        used = set()
        for planned in reproduction["requests"]:
            matches = [(index, record) for index, record in enumerate(self.records) if index not in used and record["request"]["method"] == planned["method"]
                          and record["request"]["url"] == planned["url"]
                          and all(record["request"]["headers"].get(name) == value for name, value in planned["headers"].items())
                          and not any(name in record["request"]["headers"] and name not in planned["headers"] for name in ("Origin", "Host", "X-Forwarded-Host", "X-Autopwn-Trace"))]
            phased = [match for match in matches if match[1].get("phase") == self.phase]
            matches = phased or matches
            if matches:
                index, match = matches[-1] if planned["role"] == "baseline" else matches[0]
                used.add(index)
                exchanges = [match, *match.get("redirects", [])]
                final_request = exchanges[-1]["request"]
                planned.update(url=final_request["url"], headers=deepcopy(final_request["headers"]),
                               redacted=final_request["redacted"])
                for offset, exchange in enumerate(exchanges):
                    record = deepcopy(exchange)
                    record.pop("redirects", None)
                    record["request"]["role"] = planned["role"] if offset == len(exchanges) - 1 else planned["role"] + " redirect"
                    result["observations"].append(record)
        result["details"] = describe_finding(result)
        return result

    def record_finding(self, result):
        if not allowed(result["type"]):
            return
        if result["id"] not in self.finding_ids:
            self.finding_ids.add(result["id"])
            self.findings.append(deepcopy(result))
            # Copy only the new finding: copying the whole list for each one is quadratic in the findings.
            self.state["findings"].append(deepcopy(result))
            if self.on_finding:
                self.on_finding(deepcopy(result))


def stage(name):
    current = ACTIVE.get()
    if current:
        current.stage(name)


def run_task(name, url, action):
    current = ACTIVE.get()
    return current.run_task(name, url, action) if current else action()


def task_done(name, url):
    current = ACTIVE.get()
    return bool(current and current.task_done(name, url))


def parameter_done(name, url, index):
    return task_done(name + "_parameter", json.dumps([url, index]))


def begin_parameter():
    current = ACTIVE.get()
    return current.problem_revision if current else 0


def finish_parameter(name, url, index, revision):
    current = ACTIVE.get()
    if current and current.problem_revision == revision:
        key = current.task_key(name + "_parameter", json.dumps([url, index]))
        current.state["tasks"][key] = []
