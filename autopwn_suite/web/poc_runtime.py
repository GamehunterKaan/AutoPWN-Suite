# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Portable evidence reproducer. Used by downloads and dashboard verification."""

import hashlib
import ipaddress
import re
import socket
import ssl
import warnings
from collections import Counter
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html import escape
from html.parser import HTMLParser
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests

from autopwn_suite.web.transport import read_response


def _origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError("Expected a credential-free HTTP(S) URL")
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid target port")
    return parts.scheme, parts.hostname.lower(), port


def validate_plan(plan):
    scope = _origin(plan["target"])
    if not isinstance(plan.get("verify_tls", True), bool):
        raise ValueError("Invalid PoC TLS verification setting")
    rows = plan.get("requests", [])
    if not isinstance(rows, list) or len(rows) > 12:
        raise ValueError("PoC request limit exceeded")
    counts = {"response": 1, "sqli_error": 3, "file_inclusion": 3, "boolean_sqli": 6, "cors": 2,
              "cors_config": 2, "redirect": 2, "trace": 2, "methods": 1, "host_header": 2, "xss_reflection": 1, "directory": 3, "tls": 0}
    if plan.get("strategy") not in counts or len(rows) != counts[plan["strategy"]]:
        raise ValueError("Incomplete PoC request plan")
    for row in rows:
        if _origin(row["url"]) != scope or row.get("method", "GET") not in ("GET", "OPTIONS", "TRACE"):
            raise ValueError("PoC requests must remain on the recorded target origin")
        if "REDACTED" in row["url"]:
            raise ValueError("Replace redacted query values locally before running this PoC")
        if set(name.lower() for name in row.get("headers", {})) - {"origin", "host", "x-forwarded-host", "x-autopwn-trace", "user-agent", "cache-control"}:
            raise ValueError("Unsupported PoC header")
    return scope


# Same as SENSITIVE_PARAMETER in runtime.py, which a downloaded PoC does not have.
_SENSITIVE_PARAMETER = re.compile(r"auth(?!or(?!iz|is))|(?<!by)(?<!com)(?<!sur)(?<!tres)pass(?!age|enger|port|ive|ion|able|over)"
                                  r"|secret|token|api.?key|session|jwt|signature|csrf", re.I)


def _public_url(value):
    try:
        parts = urlsplit(value)
        pairs = [(key, "REDACTED" if item and _SENSITIVE_PARAMETER.search(key) else item)
                 for key, item in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], query=urlencode(pairs), fragment=""))
    except ValueError:
        return "Invalid URL"


def _public_headers(response):
    allowed = {"content-type", "location", "allow", "access-control-allow-origin", "access-control-allow-credentials",
               "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"}
    return {name: (_public_url(value) if name.lower() == "location" else value)[:2048]
            for name, value in response.headers.items() if name.lower() in allowed}


_INACTIVE_TAGS = ("textarea", "title", "style", "xmp", "noscript", "template")


class _Document(HTMLParser):
    def __init__(self, marker=""):
        super().__init__(convert_charrefs=True)
        self.stack, self.links, self.urls, self.heading = [], [], [], []
        self.marker, self.active = marker, False
        # Counts of the open elements, kept beside the stack: scanning the stack for every tag costs the page's
        # depth each, which is quadratic on the deeply nested page a target controls.
        self.open, self.inactive = {}, 0

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if self.marker and not self.inactive and any(name.startswith("on") and self.marker in (value or "") for name, value in attributes.items()):
            self.active = True
        if tag == "a" and "href" in attributes:
            self.links.append(attributes["href"])
        if tag in ("a", "link", "script", "img", "form"):
            self.urls.extend(attributes[name] for name in ("href", "src", "action") if attributes.get(name))
        if tag not in ("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"):
            self.stack.append((tag, attributes))
            self.open[tag] = self.open.get(tag, 0) + 1
            if tag in _INACTIVE_TAGS:
                self.inactive += 1

    def handle_endtag(self, tag):
        if not self.open.get(tag):
            return
        index = len(self.stack) - 1
        while self.stack[index][0] != tag:
            index -= 1
        for name, _ in self.stack[index:]:
            self.open[name] -= 1
            if name in _INACTIVE_TAGS:
                self.inactive -= 1
        del self.stack[index:]

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] in ("title", "h1"):
            self.heading.append(data)
        if self.marker and self.stack and self.stack[-1][0] == "script":
            attributes = self.stack[-1][1]
            if (not self.inactive
                    and not attributes.get("src")
                    and attributes.get("type", "").strip().lower() in ("", "module", "text/javascript", "application/javascript")
                    and self.marker in data):
                self.active = True


def _sql_errors(text):
    # Bounded gaps and a cut body: the target controls the text and re holds the GIL while it matches.
    patterns = [r"you have an error in your sql syntax", r"warning.{0,200}?mysql(?:i)?[_\W]",
                r"postgresql.{0,200}?error|pg_query\(\).{0,200}?failed|psycopg\w*\.errors\.syntaxerror",
                r"unclosed quotation mark after the character string", r"microsoft.{0,200}?(?:odbc|oledb).{0,200}?sql server|sqlserverexception",
                r"\bORA-\d{5}\b", r"microsoft.{0,200}?(?:jet|access).{0,200}?database",
                r"sqlite(?:3)?\.(?:operationalerror|exception)|sqlite_error|sqlite.{0,200}?syntax error", r"syntax error.{0,200}?at or near"]
    text = text[:50_000]
    return {pattern for pattern in patterns if re.search(pattern, text, re.I)}


def _files(text):
    unix = bool(re.search(r"(?:^|[\r\n>])root:[^:\r\n]*:0:0:[^:\r\n]*:[^:\r\n]+:[^<\r\n]+", text))
    windows = len(set(value.lower() for value in re.findall(r"^\[(fonts|extensions|mci extensions|files)\]\s*$", text, re.I | re.M))) >= 2
    return {name for name, matched in (("Unix passwd", unix), ("Windows win.ini", windows)) if matched}


def _similarity(left, right):
    # Same as similarity() in similarity.py, which a downloaded PoC does not have: difflib's ratio, on shorter
    # prefixes when a hostile body of many different characters would make it take minutes.
    counts = Counter(right)
    popular = len(right) // 100 + 1 if len(right) >= 200 else len(right)
    work = sum(counts[char] for char in left if counts[char] <= popular)
    if work > 500_000:
        keep = max(1000, int(len(left) * (500_000 / work) ** .5))
        left, right = left[:keep], right[:keep]
    return SequenceMatcher(None, left, right).ratio()


def _normalized(response, row, plan):
    text = response.text[:100000]
    values = [row["url"], urlsplit(row["url"]).query]
    parameter = plan.get("parameter")
    if parameter:
        values += parse_qs(urlsplit(row["url"]).query).get(parameter, [])
    for value in sorted(set(values), key=len, reverse=True):
        if len(value) > 4:
            for encoded in (value, quote(value, safe="%/"), escape(value), escape(value, quote=False)):
                text = text.replace(encoded, "{probe}")
    return text


def _response_condition(plan, response):
    kind, evidence = plan["kind"], plan.get("evidence", "")
    text, path = response.text[:100000], unquote(urlsplit(plan["requests"][0]["url"]).path).lower()
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    is_html = content_type in ("text/html", "application/xhtml+xml") if content_type else "<" in text
    if kind == "DIR":
        return 200 <= response.status_code < 400 or response.status_code in (401, 403)
    if kind == "DIR_LISTING":
        document = _Document()
        document.feed(text)
        target = plan["requests"][0]["url"]
        children = set()
        for link in document.links:
            try:
                child = urljoin(target, link)
                if not link.startswith(("?", "#")) and _origin(child) == _origin(target) and urlsplit(child).path.startswith(urlsplit(target).path.rstrip("/") + "/"):
                    children.add(urlsplit(child).path)
            except ValueError:
                continue
        return is_html and 200 <= response.status_code < 300 and bool(re.search(r"\b(?:Index of|Directory listing for)\s+/", " ".join(document.heading), re.I)) and len(children) >= 2
    if kind == "ERROR_DISCLOSURE":
        patterns = [r"Traceback \(most recent call last\):[\s\S]{0,4000}File [\"']",
                    r"(?:Fatal error|Uncaught \w+(?:Exception|Error))[\s\S]{0,2000}Stack trace:",
                    r"\b(?:\w*Exception|\w*Error):[\s\S]{0,2000}\bat [\w.$]+\([^)]*\.java:\d+\)",
                    r"Server Error in [\s\S]{0,4000}(?:Stack Trace:|Source Error:)"]
        return response.status_code >= 500 and any(re.search(pattern, text, re.I) for pattern in patterns)
    if kind == "DEBUG_DISCLOSURE":
        php = 200 <= response.status_code < 300 and re.search(r"<title>\s*phpinfo\(\)", text, re.I) and "PHP Version" in text
        django = ((200 <= response.status_code < 300 or response.status_code >= 500) and 'id="summary"' in text and "Django" in text
                  and ("DEBUG = True" in text or "You're seeing this error because" in text))
        return bool(is_html and (php or django))
    if kind == "EXPOSED_FILE":
        if not 200 <= response.status_code < 300 or (is_html and re.search(r"<(?:!doctype html|html|body)\b", text, re.I)):
            return False
        if ".env" in path:
            keys = [match[1] for line in text.splitlines()[:5000] if (match := re.match(r"[ \t]*(?:export[ \t]+)?([A-Z_][A-Z0-9_]*)[ \t]*=.", line[:500]))]
            return len(set(keys)) >= 2 and any(re.search(r"SECRET|PASSWORD|TOKEN|DATABASE|DB_", key) for key in keys)
        if path.endswith("/.git/head"):
            return bool(re.fullmatch(r"(?:ref: refs/(?:heads|tags)/[^\s]+|[0-9a-f]{40})\s*", text, re.I))
        if path.endswith("/.git/config"):
            return bool(re.search(r"^\[core\]", text, re.M)) and "repositoryformatversion" in text
        if path.endswith((".sql", ".sql.bak")):
            return bool(re.search(r"-- (?:MySQL|PostgreSQL).{0,200}dump|CREATE TABLE\s", text, re.I))
        if path.endswith((".bak", ".old", "~", ".save")):
            return "<?php" in text and bool(re.search(r"\$\w+\s*=|function\s+\w+", text))
        if path.endswith("/web.config"):
            return "<configuration" in text and bool(re.search(r"<system\.(?:web|webServer)|<connectionStrings", text))
        return "backup" in path and ((path.endswith(".zip") and response.content.startswith(b"PK\x03\x04")) or (path.endswith((".tar.gz", ".tgz")) and response.content.startswith(b"\x1f\x8b")))
    if kind == "WEB_CONFIG":
        if not (200 <= response.status_code < 300 or response.status_code in (401, 403)):
            return False
        lowered = evidence.lower()
        if "x-content-type-options" in lowered:
            return response.headers.get("X-Content-Type-Options", "").strip().lower() != "nosniff"
        if "no enforced" in lowered:
            return is_html and not response.headers.get("Content-Security-Policy", "").strip()
        if "frame-ancestors" in lowered:
            policy = response.headers.get("Content-Security-Policy", "")
            frames = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", policy, re.I)
            return is_html and (bool(frames and "*" in frames[1].split()) or (not frames and response.headers.get("X-Frame-Options", "").strip().lower() not in ("deny", "sameorigin")))
        if "hsts" in lowered:
            age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", response.headers.get("Strict-Transport-Security", ""), re.I)
            return not age or not age[1].strip("0")
        if "cookie " in lowered:
            from http.cookies import SimpleCookie
            name = re.search(r"Cookie (.*?):", evidence)[1]
            raw = response.raw.headers.getlist("Set-Cookie") if response.raw else []
            cookies = SimpleCookie()
            for header in raw or [response.headers.get("Set-Cookie", "")]:
                cookies.load(header)
            if name not in cookies:
                return False
            cookie = cookies[name]
            if "samesite=none" in lowered:
                return cookie["samesite"].lower() == "none" and not cookie["secure"]
            if "secure" in lowered:
                return not cookie["secure"]
            if "httponly" in lowered:
                return not cookie["httponly"]
            return cookie["samesite"].lower() not in ("lax", "strict", "none")
    return None


def _check_http(plan, responses):
    strategy = plan["strategy"]
    rows = plan["requests"]
    if strategy in ("sqli_error", "file_inclusion"):
        classifier = _sql_errors if strategy == "sqli_error" else _files
        if len(responses) != 3:
            return False
        baseline, first, repeat = [classifier(response.text) for response in responses]
        return bool((first - baseline) & (repeat - baseline))
    if strategy == "boolean_sqli":
        if len(responses) != 6 or not 200 <= responses[0].status_code < 300 or len({(row.status_code, row.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()) for row in responses}) != 1:
            return False
        texts = [_normalized(response, row, plan) for response, row in zip(responses, rows, strict=False)]
        similar = _similarity
        return (similar(texts[0], texts[1]) >= .98 and all(similar(texts[0], texts[index]) >= .98 for index in (2, 4))
                and all(similar(texts[0], texts[index]) <= .85 for index in (3, 5)) and similar(texts[3], texts[5]) >= .98
                and not any(_sql_errors(response.text) for response in responses))
    if strategy in ("cors", "cors_config"):
        return all(200 <= response.status_code < 300 and response.headers.get("Access-Control-Allow-Origin", "").strip() == ("*" if strategy == "cors_config" else row["headers"]["Origin"])
                   and response.headers.get("Access-Control-Allow-Credentials", "").strip() == "true" for response, row in zip(responses, rows, strict=False))
    if strategy == "redirect":
        for response, row in zip(responses, rows, strict=False):
            values = parse_qs(urlsplit(row["url"]).query).get(plan["parameter"], [])
            if not values or response.status_code not in (301, 302, 303, 307, 308) or urlsplit(urljoin(row["url"], response.headers.get("Location", ""))).hostname != urlsplit(values[0]).hostname:
                return False
        return bool(responses)
    if strategy == "trace":
        return all(response.status_code == 200 and re.search(r"^TRACE \S+ HTTP/\d(?:\.\d)?\s*$", response.text, re.M)
                   and re.search(r"^X-Autopwn-Trace:\s*" + re.escape(plan["marker"]) + r"\s*$", response.text, re.I | re.M) for response in responses)
    if strategy == "methods":
        advertised = set(responses[0].headers.get("Allow", "").upper().replace(" ", "").split(","))
        return (200 <= responses[0].status_code < 300 or responses[0].status_code == 405) and bool(advertised & {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
    if strategy == "host_header":
        for response, row in zip(responses, rows, strict=False):
            marker = row["headers"][plan["header"]]
            document = _Document()
            document.feed(response.text)
            urls = [response.headers.get("Location", "")] + document.urls
            if not 200 <= response.status_code < 400 or not any((urlsplit(value).scheme in ("http", "https") or value.startswith("//")) and urlsplit(value).hostname == marker for value in urls):
                return False
        return bool(responses)
    if strategy == "xss_reflection":
        response = responses[0]
        mime = response.headers.get("Content-Type", "text/html").split(";", 1)[0].lower()
        document = _Document(plan["marker"])
        document.feed(response.text)
        return mime in ("text/html", "application/xhtml+xml") and plan["payload"] in response.text and document.active
    if strategy == "directory":
        probe = responses[2]
        if not (200 <= probe.status_code < 400 or probe.status_code in (401, 403)):
            return False
        for response, row in zip(responses[:2], rows[:2], strict=False):
            if response.status_code != probe.status_code:
                continue
            def normalize(value, url):
                return value.replace(url, "{path}").replace(urlsplit(url).path, "{path}")
            if probe.status_code in (301, 302, 303, 307, 308):
                if normalize(probe.headers.get("Location", ""), rows[2]["url"]) == normalize(response.headers.get("Location", ""), row["url"]):
                    return False
            elif _similarity(normalize(probe.text[:20000], rows[2]["url"]), normalize(response.text[:20000], row["url"])) >= .98:
                return False
        return True
    return _response_condition(plan, responses[0]) if responses else None


def _check_tls(plan):
    hostname, port = _origin(plan["target"])[1:]
    hostname = hostname.encode("idna").decode("ascii")
    context = ssl.create_default_context()
    kind = plan["kind"]
    if kind != "TLS_TRUST":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if kind == "TLS_PROTOCOL":
        version = ssl.TLSVersion.TLSv1_1 if "TLSv1.1" in plan["evidence"] else ssl.TLSVersion.TLSv1
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        with socket.create_connection((hostname, port), timeout=10) as connection:
            # TLS_PROTOCOL intentionally repeats an exact legacy-version handshake.
            # No HTTP, credentials or application data is sent; other checks keep default TLS versions.
            with context.wrap_socket(connection, server_hostname=hostname) as secure:
                if kind == "TLS_TRUST":
                    return False
                if kind == "TLS_PROTOCOL":
                    return secure.version() == ("TLSv1.1" if "TLSv1.1" in plan["evidence"] else "TLSv1")
                from cryptography import x509
                certificate = x509.load_der_x509_certificate(secure.getpeercert(binary_form=True))
    except ssl.SSLCertVerificationError:
        return True if kind == "TLS_TRUST" else None
    now = datetime.now(timezone.utc)
    if "expired" in plan["evidence"]:
        return now > certificate.not_valid_after_utc
    if "not valid before" in plan["evidence"]:
        return now < certificate.not_valid_before_utc
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return True
    try:
        address = ipaddress.ip_address(hostname)
        return address not in names.get_values_for_type(x509.IPAddress)
    except ValueError:
        hostname = hostname.lower().rstrip(".")
        def matches(name):
            name = name.lower().rstrip(".")
            if "*" not in name:
                return name == hostname
            labels, host_labels = name.split("."), hostname.split(".")
            return len(labels) >= 3 and labels[0] == "*" and len(labels) == len(host_labels) and labels[1:] == host_labels[1:]
        return not any(matches(name) for name in names.get_values_for_type(x509.DNSName))


def verify_plan(plan, transport=None):
    validate_plan(plan)
    observations, responses = [], []
    try:
        if plan["strategy"] == "tls":
            matched = _check_tls(plan)
        else:
            for row in plan["requests"]:
                response = read_response(transport, row.get("method", "GET"), row["url"], headers=row.get("headers", {}),
                    verify=plan.get("verify_tls", True), timeout=10, allow_redirects=False)
                responses.append(response)
                observations.append({"method": row.get("method", "GET"), "url": _public_url(row["url"]), "role": row.get("role", "probe"),
                    "status": response.status_code, "headers": _public_headers(response), "bytes_captured": len(response.content),
                    "sha256": hashlib.sha256(response.content).hexdigest(), "truncated": response.autopwn_truncated})
            matched = None if any(row["truncated"] for row in observations) else _check_http(plan, responses)
        status = "reproduced" if matched is True else "not_reproduced" if matched is False else "inconclusive"
    except (requests.RequestException, OSError, ValueError, KeyError, ImportError):
        status = "inconclusive"
    return {"status": status, "summary": {"reproduced": "Recorded response evidence reproduced; review the stated impact limitations.",
            "not_reproduced": "Recorded evidence was not reproduced by this run.", "inconclusive": "Verification could not establish the expected evidence."}[status],
            "impact_verified": False, "observations": observations, "checked_at": datetime.now(timezone.utc).isoformat()}
