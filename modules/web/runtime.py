"""Thread-local web scan budgets, cancellation, progress and redacted evidence."""

from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from modules.nmap_progress import ScanCancelled
from modules.web.options import CHECKS, TYPE_CHECK, normalize_options


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


def redact_url(url):
    try:
        parts = urlsplit(url)
        pairs = [(key, "REDACTED" if value and re.search(r"pass|secret|token|api.?key|auth|session|jwt|signature|csrf", key, re.I) else value)
                 for key, value in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], query=urlencode(pairs), fragment=""))
    except ValueError:
        return "Invalid URL"


def public_request(method, url, headers=None, role="probe"):
    safe_headers = {name: str(value)[:512] for name, value in (headers or {}).items()
                    if name.lower() in ("user-agent", "origin", "host", "x-forwarded-host", "x-autopwn-trace", "cache-control")}
    safe_url = redact_url(url)
    return {"method": method.upper(), "url": safe_url, "headers": safe_headers, "role": role,
            "redacted": "REDACTED" in safe_url or len(safe_url) > 8192}


class ScanContext:
    def __init__(self, target, log, *, controls=None, should_stop=None, progress=None, on_finding=None):
        self.target = target
        self.log = log
        self.options = normalize_options(controls)
        self.should_stop = should_stop or (lambda: False)
        self.progress = progress
        self.on_finding = on_finding
        self.requests = 0
        self.findings = []
        self.records = deque(maxlen=self.options["request_budget"])
        self.issues = []
        self.phase = "Preparing web checks"
        self.discovery = False

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
        self.requests += 1
        self.publish_progress()
        return time.monotonic()

    def issue(self, message):
        if message not in self.issues:
            self.issues.append(message)
            self.log.logger("warning", message)

    def capture(self, response, method, url, headers, started):
        request = public_request(method, url, headers)
        response_headers = {}
        for name, value in response.headers.items():
            if name.lower() in ("content-type", "content-length", "location", "server", "allow", "cache-control",
                                "access-control-allow-origin", "access-control-allow-credentials", "content-security-policy",
                                "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"):
                response_headers[name] = redact_url(value)[:2048] if name.lower() == "location" else str(value)[:2048]
        captured = {"request": request, "phase": self.phase, "response": {"status": response.status_code, "headers": response_headers,
                    "bytes_captured": len(response.content), "sha256": hashlib.sha256(response.content).hexdigest(),
                    "truncated": response.autopwn_truncated,
                    "duration_ms": round(1000 * (time.monotonic() - started), 1)}}
        self.records.append(captured)
        if response.autopwn_truncated:
            self.issue("Response size limit reached; content coverage is limited.")
        return captured

    def annotate(self, result, reproduction=None):
        from modules.web.details import describe_finding
        result = deepcopy(result)
        result["url"] = redact_url(result["url"])
        result["id"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()[:24]
        result["observed_at"] = datetime.now(timezone.utc).isoformat()
        reproduction = deepcopy(reproduction or {"strategy": "response", "requests": [{"method": "GET", "url": result["url"]}]})
        reproduction["requests"] = [public_request(row.get("method", "GET"), row["url"], row.get("headers"), row.get("role", "probe"))
                                    for row in reproduction.get("requests", [])[:12]]
        reproduction["target"] = redact_url(reproduction.get("target", self.target))
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
                planned["headers"] = deepcopy(match["request"]["headers"])
                record = deepcopy(match)
                record["request"]["role"] = planned["role"]
                result["observations"].append(record)
        result["details"] = describe_finding(result)
        return result

    def record_finding(self, result):
        if not allowed(result["type"]):
            return
        if not any(old["id"] == result["id"] for old in self.findings):
            self.findings.append(deepcopy(result))
            if self.on_finding:
                self.on_finding(deepcopy(result))


def stage(name):
    current = ACTIVE.get()
    if current:
        current.stage(name)
