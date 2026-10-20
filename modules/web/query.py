# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Build one-parameter probes without losing the page's other query inputs."""

from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit


def probe_url(base_url, url_params, index, payload):
    params = list(url_params)
    name = params[index].split("=", 1)[0]
    # Preserve intentional percent-encoded payloads, but escape query delimiters.
    params[index] = f"{name}={quote(payload, safe='%/')}"
    return f"{base_url}?{'&'.join(params)}"


def query_parts(url):
    """Strip browser fragments while keeping raw query encoding and order."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(query="", fragment="")), parts.query.split("&") if parts.query else []


def parameter_indexes(params, *, names=None):
    # A repeated name is a separate input; preserve its position and context.
    from modules.web.planning import parameter_priority
    from modules.web.runtime import ACTIVE, parameter_done
    current = ACTIVE.get()
    indexes = [index for index, param in enumerate(params) if param.split("=", 1)[0]]
    if names is not None:
        indexes = [index for index in indexes if unquote(params[index].split("=", 1)[0]).lower() in names]
    indexes.sort(key=lambda index: parameter_priority(*parse_qsl(params[index], keep_blank_values=True)[0]))
    if current and current.task_name in ("lfi", "sqli", "xss", "boolean_sqli", "redirects"):
        indexes = [index for index in indexes if not parameter_done(current.task_name, current.task_url, index)]
    if current and len(indexes) > current.options["max_parameters"]:
        current.issue(_("Query parameter limit reached; coverage is limited."))
        indexes = indexes[:current.options["max_parameters"]]
    return iter(indexes)
