"""Build one-parameter probes without losing the page's other query inputs."""

from urllib.parse import quote, urlsplit, urlunsplit


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


def parameter_indexes(params):
    # A repeated name is a separate input; preserve its position and context.
    return (index for index, param in enumerate(params) if param.split("=", 1)[0])
