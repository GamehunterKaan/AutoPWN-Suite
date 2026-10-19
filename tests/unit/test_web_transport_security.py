# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Real loopback adversaries exercise the HTTP boundary, not mocked reads."""

import errno
import os
import select
import socket
import socketserver
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from autopwn_suite.nmap_progress import ScanCancelled
from autopwn_suite.web.http import ProbeClient, bounded_request, scoped_get
from autopwn_suite.web.poc import python_poc
from autopwn_suite.web.poc_runtime import verify_plan
from autopwn_suite.web.runtime import ScanContext
from autopwn_suite.web.transport import RequestCancelled, read_response
from autopwn_suite.web.webvuln import webvuln

# Several tests deliberately disable certificate verification against a loopback server.
pytestmark = pytest.mark.filterwarnings("ignore:Unverified HTTPS request:urllib3.exceptions.InsecureRequestWarning")


@pytest.fixture
def local_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture
def diagnostic_server(local_certificate):
    @contextmanager
    def serve(mode="healthy", *, tls=False):
        stop, received = threading.Event(), threading.Event()
        headers = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, local_certificate))

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                connection = self.request
                try:
                    if mode == "tls_stall":
                        received.set()
                        stop.wait(2)
                        return
                    if tls:
                        connection = context.wrap_socket(connection, server_side=True)
                    connection.settimeout(2)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        data += connection.recv(4096)
                        if not data:
                            return
                    headers.append(data.decode("latin-1"))
                    received.set()
                    if mode == "healthy":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nSet-Cookie: secret=value\r\n\r\nsafe")
                        return
                    if mode == "headers":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                    elif mode == "body":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                    else:
                        connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        if mode == "chunk_body":
                            connection.sendall(b"FFFF\r\n")
                        elif mode == "trailer":
                            connection.sendall(b"0\r\nX-Drip: ")
                    # Each read receives progress faster than its inactivity timeout.
                    for _ in range(70):
                        if stop.wait(.03):
                            break
                        connection.sendall(b"a")
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    connection.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        with Server(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02})
            worker.start()
            try:
                yield f'{"https" if tls else "http"}://127.0.0.1:{server.server_address[1]}/', received, headers
            finally:
                stop.set()
                server.shutdown()
                worker.join(2)
    return serve


@pytest.mark.parametrize("mode", ["headers", "body", "chunk_size", "chunk_body", "trailer"])
@pytest.mark.parametrize("tls", [False, True])
def test_deadline_interrupts_partial_http_reads_and_releases_watchdog(diagnostic_server, mode, tls):
    with diagnostic_server(mode, tls=tls) as (url, received, _):
        started = time.monotonic()
        with pytest.raises(requests.Timeout):
            bounded_request(requests.get, url, timeout=.3, verify=False, allow_redirects=False)
        elapsed = time.monotonic() - started
        assert received.is_set()
        assert .2 <= elapsed < 1.5
    assert not any(thread.name == "autopwn-http-deadline" for thread in threading.enumerate())
    with diagnostic_server() as (url, _, _):
        response = scoped_get(requests.get, url)
        assert response.text == "safe"
        assert response.raw.headers.getlist("Set-Cookie") == ["secret=value"]


@pytest.mark.parametrize("mode", ["headers", "body", "chunk_size", "trailer", "tls_stall"])
def test_scan_stop_interrupts_socket_and_propagates_cancellation(diagnostic_server, mode):
    stop = threading.Event()
    context = ScanContext("local", MagicMock(), controls={"speed": 5, "verify_tls": False}, should_stop=stop.is_set)
    with diagnostic_server(mode, tls=True) as (url, received, _):
        timer = threading.Timer(.2, stop.set)
        timer.start()
        started = time.monotonic()
        try:
            with context.activate(), pytest.raises(ScanCancelled):
                scoped_get(requests.get, url)
        finally:
            timer.cancel()
            timer.join()
        assert received.is_set()
        assert time.monotonic() - started < 1.5
    assert not any(thread.name == "autopwn-http-deadline" for thread in threading.enumerate())


def test_stream_timeout_marks_task_incomplete_and_keeps_resume_available(diagnostic_server):
    with diagnostic_server("body") as (url, _, _):
        context = ScanContext(url, MagicMock(), controls={"speed": 5, "timeout": 1})
        def action():
            try:
                scoped_get(requests.get, url)
            except requests.RequestException:
                return []
        with context.activate():
            assert context.run_task("crawl", url, action) == []
        assert context.issues
        assert not context.task_done("crawl", url)


@pytest.mark.parametrize("path", ["core", "scoped", "probe", "replay"])
def test_diagnostic_paths_never_send_synthetic_netrc_or_explicit_credentials(diagnostic_server, tmp_path, monkeypatch, path):
    netrc = tmp_path / "synthetic.netrc"
    netrc.write_text("default login TEST_ONLY_USER password TEST_ONLY_PASSWORD\n", encoding="ascii")
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with diagnostic_server() as (url, _, captured):
        # Positive reproduction control: ordinary Requests DOES load this fixture.
        requests.get(url, timeout=2).close()
        assert "Authorization: Basic " in captured.pop()
        if path == "core":
            bounded_request(requests.get, url)
            bounded_request(requests.get, url, headers={"Authorization": "secret", "Cookie": "secret=value", "Proxy-Authorization": "secret"})
        elif path == "scoped":
            scoped_get(requests.get, url)
        elif path == "probe":
            ProbeClient(url, MagicMock()).send(url)
        else:
            result = verify_plan({"strategy": "response", "kind": "WEB_CONFIG", "evidence": "X-Content-Type-Options is missing or is not nosniff",
                                  "target": url, "requests": [{"url": url}]})
            assert result["status"] == "reproduced"
        assert len(captured) == (2 if path == "core" else 1)
        assert all("authorization:" not in row.lower() and "cookie:" not in row.lower() for row in captured)


def test_downloaded_poc_is_standalone_and_obeys_its_network_deadline(diagnostic_server):
    with diagnostic_server("body") as (url, _, _):
        finding = {"type": "WEB_CONFIG", "url": url, "endpoint": url, "evidence": "X-Content-Type-Options is missing or is not nosniff"}
        namespace = {"__name__": "downloaded_poc"}
        code = python_poc(finding)
        assert "from autopwn_suite." not in code
        exec(compile(code, "downloaded_poc.py", "exec"), namespace)
        # Same generated implementation, shortened local deadline keeps CI fast.
        original = namespace["_RequestDeadline"]
        class ShortDeadline(original):
            def __init__(self, timeout, should_stop):
                super().__init__(.3, should_stop)
        namespace["_RequestDeadline"] = ShortDeadline
        started = time.monotonic()
        result = namespace["verify_plan"]({"strategy": "response", "kind": "WEB_CONFIG", "evidence": finding["evidence"],
                                          "target": url, "requests": [{"url": url}]})
        assert result["status"] == "inconclusive"
        assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("host", ["example..test", "a" * 70 + ".test"])
def test_host_that_cannot_be_encoded_is_a_connection_failure_not_a_unicode_error(host):
    with pytest.raises(requests.exceptions.ConnectionError):
        scoped_get(requests.get, f"http://{host}/")
    log = MagicMock()
    assert webvuln(f"http://{host}/", log, MagicMock()) == []
    log.logger.assert_any_call("warning", f"No reachable in-scope web endpoint on http://{host}/.")


@pytest.mark.skipif(not hasattr(select, "poll"), reason="Only platforms with poll() have select()'s descriptor limit to work around")
@pytest.mark.parametrize("tls", [False, True])
def test_requests_work_when_descriptors_are_above_the_select_limit(diagnostic_server, tls):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 1400:
        pytest.skip("The descriptor limit cannot be raised past select()'s 1024")
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 1400), hard))
    except (ValueError, OSError):  # for example a platform that caps the soft limit below the one asked for
        pytest.skip("The descriptor limit cannot be raised past select()'s 1024")
    held = []
    try:
        # Sockets opened now get descriptors of 1100 and more, which select() rejects with ValueError.
        held = [os.open(os.devnull, os.O_RDONLY) for _ in range(1100)]
        with diagnostic_server(tls=tls) as (url, _, _):
            assert read_response(None, "GET", url, timeout=5, verify=False).text == "safe"
    finally:
        for descriptor in held:
            os.close(descriptor)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_precancelled_request_never_opens_a_socket():
    with patch("requests.Session") as session, pytest.raises(RequestCancelled):
        read_response(None, "GET", "http://127.0.0.1/", should_stop=lambda: True)
    session.assert_not_called()


def test_pollable_tls_preserves_certificate_and_hostname_validation(diagnostic_server, local_certificate):
    with diagnostic_server(tls=True) as (url, _, _):
        with pytest.raises(requests.exceptions.SSLError):
            read_response(None, "GET", url, timeout=2, verify=True)
        with pytest.raises(requests.exceptions.SSLError):
            read_response(None, "GET", url, timeout=2, verify=str(local_certificate[0]))
        result = read_response(None, "GET", url.replace("127.0.0.1", "localhost"), timeout=5, verify=str(local_certificate[0]))
        assert result.text == "safe"


@pytest.mark.parametrize("cancel", [False, True])
def test_pending_tcp_connect_uses_one_deadline_and_honors_stop(monkeypatch, cancel):
    import autopwn_suite.web.transport as transport
    stop = threading.Event()
    sockets = []
    original_socket = socket.socket
    class PendingSocket(original_socket):
        def connect_ex(self, address):
            sockets.append(self)
            return errno.EINPROGRESS
    def never_ready(readers, writers, errors, timeout):
        time.sleep(timeout)
        return [], [], []
    # Multiple blackholed A/AAAA answers must not multiply the request budget.
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))] * 4
    monkeypatch.setattr(transport.socket, "getaddrinfo", lambda *args: addresses)
    monkeypatch.setattr(transport.socket, "socket", PendingSocket)
    monkeypatch.setattr(transport.select, "select", never_ready)
    timer = threading.Timer(.1, stop.set)
    if cancel:
        timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(RequestCancelled if cancel else requests.Timeout):
            read_response(None, "GET", "http://example.invalid/", timeout=5 if cancel else .3, should_stop=stop.is_set)
    finally:
        if cancel:
            timer.cancel()
            timer.join()
    assert time.monotonic() - started < 1
    assert len(sockets) == 1
    assert sockets[0].fileno() == -1
    assert not any(thread.name == "autopwn-http-deadline" for thread in threading.enumerate())


def test_unsupported_address_family_still_falls_back_to_working_address(diagnostic_server, monkeypatch):
    from urllib.parse import urlsplit

    import autopwn_suite.web.transport as transport
    original_socket = socket.socket
    def create(family, kind, protocol=0, **kwargs):
        if family == socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, "IPv6 unavailable")
        return original_socket(family, kind, protocol, **kwargs)
    with diagnostic_server() as (url, _, _):
        port = urlsplit(url).port
        addresses = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        monkeypatch.setattr(transport.socket, "getaddrinfo", lambda *args: addresses)
        monkeypatch.setattr(transport.socket, "socket", create)
        assert read_response(None, "GET", url, timeout=2).text == "safe"


def test_untrusted_certificate_is_rejected_by_default_with_actionable_issue(diagnostic_server):
    context = ScanContext("local", MagicMock(), controls={"speed": 5})
    assert context.options["verify_tls"] is True
    with diagnostic_server("healthy", tls=True) as (url, _, _):
        with context.activate(), pytest.raises(requests.exceptions.SSLError):
            scoped_get(requests.get, url)
    assert any("certificate verification" in str(issue) and "--insecure-tls" in str(issue) for issue in context.issues)


def test_insecure_tls_option_is_an_explicit_per_scan_opt_out(diagnostic_server):
    context = ScanContext("local", MagicMock(), controls={"speed": 5, "verify_tls": False})
    with diagnostic_server("healthy", tls=True) as (url, _, _):
        with context.activate():
            response = scoped_get(requests.get, url)
    assert response.status_code == 200 and response.text == "safe"


def test_verify_tls_control_is_validated_and_defaults_to_verification():
    from autopwn_suite.web.options import normalize_options
    assert normalize_options()["verify_tls"] is True
    assert normalize_options({"verify_tls": False})["verify_tls"] is False
    # A later resume that omits the control keeps the original choice.
    assert normalize_options({"speed": 2}, {"verify_tls": False})["verify_tls"] is False
    for bad in ("false", 0, None):
        with pytest.raises(ValueError, match="verify_tls"):
            normalize_options({"verify_tls": bad})


def test_poc_plans_and_curl_commands_keep_the_recorded_tls_policy():
    from autopwn_suite.web.poc import build_plan, curl_poc
    from autopwn_suite.web.poc_runtime import validate_plan
    finding = {"endpoint": "https://example.test/", "url": "https://example.test/", "type": "CORS", "evidence": "x",
               "reproduction": {"strategy": "response", "target": "https://example.test/",
                                "requests": [{"url": "https://example.test/", "method": "GET"}]}}
    assert build_plan(finding)["verify_tls"] is True
    assert "--insecure" not in curl_poc(finding)
    finding["reproduction"]["verify_tls"] = False
    assert build_plan(finding)["verify_tls"] is False
    assert "--insecure" in curl_poc(finding)
    plan = build_plan(finding)
    plan["verify_tls"] = "no"
    with pytest.raises(ValueError, match="TLS verification"):
        validate_plan(plan)


def test_new_findings_record_the_scan_tls_policy():
    for controls, expected in (({}, True), ({"verify_tls": False}, False)):
        context = ScanContext("https://example.test/", MagicMock(), controls=controls)
        recorded = context.annotate({"type": "CORS", "url": "https://example.test/", "evidence": "x"})
        assert recorded["reproduction"]["verify_tls"] is expected
