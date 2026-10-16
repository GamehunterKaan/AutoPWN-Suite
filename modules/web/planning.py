# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Prefer injectable inputs and diverse paths over repeated query variations."""

import re
from collections import defaultdict, deque
from urllib.parse import parse_qsl, unquote, urlsplit

_FILE_INPUTS = {"file", "filename", "path", "include", "template", "document", "doc", "folder"}
_ROUTING_INPUTS = {"page", "view", "module", "route"}
_ASSETS = {".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
           ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi",
           ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
_ACTIONS = re.compile(r"(?:^|[/_.-])(?:logout|logoff|reset|delete|remove|truncate|drop|purge|"
                      r"setup|set-up|toggle|disable|enable)(?:$|[/_.-])", re.I)


def skip_discovered_url(url):
    """Keep navigation read-only and avoid fetching non-HTML static assets."""
    parts = urlsplit(url)
    path = unquote(parts.path).lower()
    if _ACTIONS.search(path):
        return True
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if any(name.lower() in {"delete", "drop", "truncate", "reset", "logout", "purge"} for name, _ in pairs):
        return True
    if any(name.lower() in _ROUTING_INPUTS | {"action", "do", "task", "operation", "op"}
           and _ACTIONS.search(value) for name, value in pairs):
        return True
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    return suffix in _ASSETS and (not pairs or all(name.lower() in {"v", "ver", "version", "_", "cache", "cb"}
                                                  for name, _ in pairs))


def parameter_priority(name, value):
    name = name.lower()
    return 0 if name in _FILE_INPUTS or (name in _ROUTING_INPUTS and re.search(r"[/\\]|\.(?:php|html?|inc|txt|xml)\b", value, re.I)) else 1


def _priority(url):
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return min((parameter_priority(name, value) for name, value in pairs), default=2)


def prioritize_urls(urls, preferred=None):
    """Round-robin endpoint shapes, retaining route values and duplicate inputs.

    Values still affect application routing, so they are not discarded. One
    path with hundreds of value variants cannot occupy every early position.
    """
    groups = defaultdict(list)
    for url in set(urls):
        parts = urlsplit(url)
        names = tuple(name for name, _ in parse_qsl(parts.query, keep_blank_values=True))
        groups[(parts.scheme, parts.netloc, parts.path, names)].append(url)
    def rank(url):
        return (url != preferred, _priority(url), url)
    ordered = [deque(sorted(group, key=rank)) for group in groups.values()]
    ordered.sort(key=lambda group: rank(group[0]))
    result = []
    while ordered:
        for group in ordered:
            result.append(group.popleft())
        ordered = [group for group in ordered if group]
    return result
