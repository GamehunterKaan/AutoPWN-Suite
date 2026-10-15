"""Bounded web requests that validate redirects before following them."""

from copy import deepcopy
from urllib.parse import urldefrag, urljoin, urlsplit

from requests.exceptions import RequestException, TooManyRedirects
from requests import request
from requests.auth import AuthBase
from modules.web.options import LIMITS


class AnonymousAuth(AuthBase):
    """Suppress Requests' automatic .netrc authentication for diagnostic probes."""

    def __call__(self, prepared):
        for name in ("Authorization", "Cookie", "Proxy-Authorization"):
            prepared.headers.pop(name, None)
        return prepared


def bounded_request(call, *args, max_bytes=1_048_576, **kwargs):
    """Keep only a bounded response prefix and release the connection."""
    from modules.web.runtime import ACTIVE
    current = ACTIVE.get()
    started = current.before() if current else None
    if current:
        kwargs["timeout"] = current.options["timeout"]
        max_bytes = current.options["max_response_kb"] * 1024
    try:
        response = call(*args, stream=True, **kwargs)
    except RequestException:
        if current and not current.discovery:
            current.issue("A web request failed; coverage is incomplete.")
        raise
    body = bytearray()
    response.autopwn_truncated = False
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = max_bytes - len(body)
            body.extend(chunk[:remaining])
            if len(chunk) > remaining:
                response.autopwn_truncated = True
                break
    finally:
        response.close()
    response._content = bytes(body)
    response._content_consumed = True
    if current:
        method, url = (args[0], args[1]) if len(args) > 1 else ("GET", args[0])
        response.autopwn_observation = current.capture(response, method, url, kwargs.get("headers", {}), started)
    return response


class ProbeLimitReached(RequestException):
    pass


class ProbeClient:
    """One origin, no followed redirects, no authenticated or write requests."""

    def __init__(self, url, log, headers=None, *, max_requests=LIMITS["request_budget"][0]):
        self.origin = origin(url)
        self.log = log
        self.headers = {key: value for key, value in (headers or {}).items() if key.lower() not in ("authorization", "cookie")}
        self.max_requests = max_requests
        self.requests = 0
        self.exhausted = False
        self.baselines = {}
        self.truncated_urls = set()

    def send(self, url, method="GET", headers=None):
        if origin(url) != self.origin or method not in ("GET", "OPTIONS", "TRACE"):
            raise RequestException("Probe is outside the permitted origin or methods")
        if self.requests >= self.max_requests:
            if not self.exhausted:
                self.log.logger("warning", "Additional web probe budget reached; coverage is limited.")
                self.exhausted = True
            raise ProbeLimitReached("Additional web probe budget reached")
        self.requests += 1
        probe_headers = dict(self.headers, **{"Cache-Control": "no-cache, no-store"})
        probe_headers.update(headers or {})
        for name in list(probe_headers):
            if name.lower() in ("authorization", "cookie"):
                del probe_headers[name]
        response = bounded_request(request, method, url, headers=probe_headers,
                                   auth=AnonymousAuth(), verify=False, timeout=10, allow_redirects=False)
        if response.autopwn_truncated and url not in self.truncated_urls:
            self.truncated_urls.add(url)
            self.log.logger("warning", f"Web response exceeded 1 MiB on {url}; content coverage is limited.")
        return response

    def baseline(self, url):
        if url not in self.baselines:
            self.baselines[url] = self.send(url)
        return self.baselines[url]


def origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError("Expected an HTTP(S) URL without credentials")
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Expected a valid TCP port")
    return parts.scheme, parts.hostname.lower(), port


def same_origin(left, right):
    try:
        return origin(left) == origin(right)
    except ValueError:
        return False


def resolve_url(base, reference):
    """Treat malformed server-provided links as unusable, not scanner errors."""
    try:
        return urldefrag(urljoin(base, reference))[0]
    except ValueError:
        return None


def scoped_get(get, url, *, allow_upgrade=False, **kwargs):
    """Follow at most three redirects; never send a probe to another origin.

    Only initial endpoint discovery may upgrade the same host from port 80 to
    HTTPS on port 443. Injection probes remain on their exact original origin.
    """
    from modules.web.runtime import ACTIVE
    context = ACTIVE.get()
    exchanges = []

    def finish(response):
        if len(exchanges) > 1:
            # Link only the exchanges from this successful scoped request.
            # Evidence can then retain the hops and replay the final URL.
            exchanges[0]["redirects"] = deepcopy(exchanges[1:])
        return response

    try:
        initial_origin = origin(url)
    except ValueError as exc:
        raise RequestException(str(exc)) from exc
    current = urldefrag(url)[0]
    visited = set()
    for _ in range(4):
        if current in visited:
            raise TooManyRedirects("Redirect loop in web scan")
        visited.add(current)
        response = bounded_request(get, current, timeout=10, verify=False, allow_redirects=False, **kwargs)
        if context:
            exchanges.append(response.autopwn_observation)
        if response.status_code not in (301, 302, 303, 307, 308):
            return finish(response)
        location = response.headers.get("Location")
        if not isinstance(location, str) or not location:
            return finish(response)
        response.close()
        try:
            destination = urldefrag(urljoin(current, location))[0]
            next_origin = origin(destination)
        except ValueError as exc:
            raise RequestException("Invalid web scan redirect") from exc
        upgrade = (allow_upgrade and initial_origin[0] == "http" and initial_origin[2] == 80
                   and next_origin == ("https", initial_origin[1], 443))
        if next_origin != initial_origin and not upgrade:
            raise RequestException("Web scan redirect leaves the target origin")
        initial_origin = next_origin
        current = destination
    raise TooManyRedirects("Web scan redirect limit reached")


def is_html(response):
    content_type = response.headers.get("Content-Type", "")
    if isinstance(content_type, str) and content_type:
        return content_type.split(";", 1)[0].strip().lower() in ("text/html", "application/xhtml+xml")
    return isinstance(response.text, str) and "<" in response.text
