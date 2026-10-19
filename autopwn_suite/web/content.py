# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Recognize exposed content without retaining secrets or stack trace text."""

import re
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from autopwn_suite.web.findings import emit, finding
from autopwn_suite.web.http import is_html, resolve_url, same_origin

# One assignment per line. The patterns below read target-controlled text and re holds the GIL while it matches,
# so no pattern may backtrack over the whole body: lines are matched one at a time and gaps are bounded.
ENV_ASSIGNMENT = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Z_][A-Z0-9_]*)[ \t]*=.")


def inspect_content(url, response, console):
    from autopwn_suite.web.runtime import ACTIVE
    current = ACTIVE.get()
    if current and getattr(response, "autopwn_truncated", False):
        current.issue("Response size limit reached; content coverage is limited.")
    results = []
    text = response.text[:100_000]
    path = unquote(urlsplit(url).path).lower()

    def add(kind, evidence, severity="medium", confidence="candidate"):
        from autopwn_suite.web.runtime import allowed
        if not allowed(kind):
            return
        results.append(finding(kind, url, evidence, severity=severity, confidence=confidence))

    if 200 <= response.status_code < 300:
        if not is_html(response) or not re.search(r"<(?:!doctype html|html|body)\b", text, re.I):
            if path.endswith(("/.env", "/.env.local", "/.env.production")):
                keys = [match[1] for line in text.splitlines()[:5_000] if (match := ENV_ASSIGNMENT.match(line[:500]))]
                if len(set(keys)) >= 2 and any(re.search(r"SECRET|PASSWORD|TOKEN|DATABASE|DB_", key) for key in keys):
                    add("EXPOSED_FILE", "Environment configuration with sensitive-key assignments; values omitted", "high")
            if path.endswith("/.git/head") and re.fullmatch(r"(?:ref: refs/(?:heads|tags)/[^\s]+|[0-9a-f]{40})\s*", text, re.I):
                add("EXPOSED_FILE", "Publicly readable Git HEAD structure", "low", "observation")
            if path.endswith("/.git/config") and re.search(r"^\[core\]", text, re.M) and "repositoryformatversion" in text:
                add("EXPOSED_FILE", "Publicly readable Git repository configuration; contents omitted")
            if path.endswith((".sql", ".sql.bak")) and re.search(r"(?:-- (?:MySQL|PostgreSQL).{0,200}dump|CREATE TABLE\s)", text, re.I):
                add("EXPOSED_FILE", "Database dump structure; records omitted", "high")
            if path.endswith((".bak", ".old", "~", ".save")) and "<?php" in text and re.search(r"\$\w+\s*=|function\s+\w+", text):
                add("EXPOSED_FILE", "Unprocessed PHP source in a backup file; source omitted", "high")
            if path.endswith("/web.config") and "<configuration" in text and re.search(r"<system\.(?:web|webServer)|<connectionStrings", text):
                add("EXPOSED_FILE", "Server configuration structure; values omitted")
            if "backup" in path and ((path.endswith(".zip") and response.content.startswith(b"PK\x03\x04"))
                                     or (path.endswith((".tar.gz", ".tgz")) and response.content.startswith(b"\x1f\x8b"))):
                add("EXPOSED_FILE", "Backup archive signature; archive was not extracted")
        if is_html(response):
            soup = BeautifulSoup(text, "html.parser")
            # Unclosed headings nest, and each one's text covers its whole subtree, so reading every heading is
            # quadratic in the page: read the first few, and only their start.
            heading = " ".join(node.get_text(" ", strip=True)[:500] for node in soup.find_all(["title", "h1"], limit=8))
            children = set()
            for link in soup.find_all("a", href=True):
                href = link["href"]
                child = resolve_url(url, href)
                if child and not href.startswith(("?", "#")) and same_origin(url, child) and urlsplit(child).path.startswith(urlsplit(url).path.rstrip("/") + "/"):
                    children.add(urlsplit(child).path)
            if re.search(r"\b(?:Index of|Directory listing for)\s+/", heading, re.I) and len(children) >= 2:
                add("DIR_LISTING", "Directory index heading and multiple child-file links", "low", "observation")
            if re.search(r"<title>\s*phpinfo\(\)", text, re.I) and "PHP Version" in text:
                add("DEBUG_DISCLOSURE", "Public phpinfo diagnostic page; environment details omitted")
            if 'id="summary"' in text and "Django" in text and ("You're seeing this error because" in text or "DEBUG = True" in text):
                add("DEBUG_DISCLOSURE", "Framework debug error page; settings omitted")
    if response.status_code >= 500:
        if is_html(response) and 'id="summary"' in text and "Django" in text and ("You're seeing this error because" in text or "DEBUG = True" in text):
            add("DEBUG_DISCLOSURE", "Framework debug error page; settings omitted")
        signatures = [
            ("Python traceback", r"Traceback \(most recent call last\):[\s\S]{0,4000}File [\"']"),
            ("PHP stack trace", r"(?:Fatal error|Uncaught \w+(?:Exception|Error))[\s\S]{0,2000}Stack trace:"),
            ("Java stack trace", r"\b(?:\w*Exception|\w*Error):[\s\S]{0,1000}\bat [\w.$]+\([^)]{0,100}\.java:\d+\)"),
            ("ASP.NET detailed error", r"Server Error in [\s\S]{0,4000}(?:Stack Trace:|Source Error:)"),
        ]
        for label, pattern in signatures:
            if re.search(pattern, text, re.I):
                add("ERROR_DISCLOSURE", label + " in an HTTP error response; trace details omitted")
                break
    for result in results:
        emit(console, result)
    return results
