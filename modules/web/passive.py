# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Response configuration advisories; these are not exploitability claims."""

import ipaddress
import re
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

from modules.web.findings import emit, finding
from modules.web.http import is_html


def inspect_response(url, response, console):
    if response.status_code not in range(200, 300) and response.status_code not in (401, 403):
        return []
    headers = {name.lower(): value for name, value in response.headers.items() if isinstance(value, str)}
    results = []

    def advise(evidence, severity="low"):
        results.append(finding("WEB_CONFIG", url, evidence, severity=severity, confidence="advisory"))

    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        advise("X-Content-Type-Options is missing or is not nosniff")
    if is_html(response):
        csp = headers.get("content-security-policy", "")
        if not csp.strip():
            advise("No enforced Content-Security-Policy on this HTML response")
        frame_sources = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
        restricted_frames = frame_sources and "*" not in frame_sources.group(1).split()
        xfo = headers.get("x-frame-options", "").strip().lower()
        if (frame_sources and not restricted_frames) or (not frame_sources and xfo not in ("deny", "sameorigin")):
            advise("No restrictive CSP frame-ancestors or valid X-Frame-Options on this HTML response")
    parts = urlsplit(url)
    try:
        ipaddress.ip_address(parts.hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if parts.scheme == "https" and not is_ip:
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", headers.get("strict-transport-security", ""), re.I)
        if not max_age or not max_age.group(1).strip("0"):
            advise("HSTS is missing or has no positive max-age")

    cookie_headers = response.raw.headers.getlist("Set-Cookie") if getattr(response.raw, "headers", None) is not None else []
    if not isinstance(cookie_headers, list) or not cookie_headers:
        cookie_headers = [headers["set-cookie"]] if "set-cookie" in headers else []
    for header in cookie_headers:
        cookies = SimpleCookie()
        try:
            cookies.load(header)
        except CookieError:
            continue
        for name, cookie in cookies.items():
            if parts.scheme == "https" and not cookie["secure"]:
                advise(f"Cookie {name}: missing Secure flag; review whether it contains sensitive data")
            if not cookie["httponly"]:
                advise(f"Cookie {name}: missing HttpOnly flag; review whether JavaScript access is required")
            same_site = cookie["samesite"].lower()
            if same_site not in ("lax", "strict", "none"):
                advise(f"Cookie {name}: no valid explicit SameSite policy")
            if same_site == "none" and not cookie["secure"]:
                advise(f"Cookie {name}: SameSite=None without Secure", severity="medium")
    for result in results:
        emit(console, result)
    return results
