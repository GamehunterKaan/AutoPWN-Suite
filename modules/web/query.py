"""Build one-parameter probes without losing the page's other query inputs."""

from urllib.parse import quote


def probe_url(base_url, url_params, index, payload):
    params = list(url_params)
    name = params[index].split("=", 1)[0]
    # Preserve intentional percent-encoded payloads, but escape query delimiters.
    params[index] = f"{name}={quote(payload, safe='%/')}"
    return f"{base_url}?{'&'.join(params)}"
