# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Optional system-Nmap checks against temporary services bound only to loopback."""

import importlib.util
import shutil
import socket
import ssl
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock
from xml.etree import ElementTree

import pytest

from api import AutoScanner
from modules.nmap_backend import PortScanner
from modules.scanner import AnalyseScanResults, PortScan, TestArp, TestPing
from modules.web.webvuln import web_endpoints

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(shutil.which("nmap") is None, reason="System Nmap is not installed")]


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        # Keep idle connections open past Nmap's tcpwrapped threshold.
        self.connection.settimeout(5)
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, TimeoutError, ssl.SSLError):
            pass

    def do_GET(self):
        body = b"<html><title>AutoPWN Nmap integration</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


@contextmanager
def local_server(*, ipv6=False, tls_context=None):
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

        def get_request(self):
            connection, address = super().get_request()
            if tls_context is not None:
                # Perform each probe's TLS handshake in its worker, so a plain
                # TCP or malformed TLS probe cannot block other connections.
                connection = tls_context.wrap_socket(connection, server_side=True,
                                                     do_handshake_on_connect=False)
            return connection, address
    try:
        server = Server(("::1" if ipv6 else "127.0.0.1", 0), Handler)
    except OSError:
        if ipv6:
            pytest.skip("IPv6 loopback is not available")
        raise
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_live_discovery_cli_api_and_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.scanner.is_root", lambda: False)
    monkeypatch.setattr("api.is_root", lambda: False)
    assert TestPing("127.0.0.1", offline=True) == ["127.0.0.1"]
    assert TestArp("127.0.0.1", offline=True) == ["127.0.0.1"]
    with local_server() as port:
        flags = f"-sT -p {port} -n --version-light --script http-title"
        progress = []
        nm = PortScan("127.0.0.1", MagicMock(), host_timeout="15s", customflags=flags,
                      progress=lambda *args: progress.append(args))
        service = nm["127.0.0.1"]["tcp"][port]
        assert service["state"] == "open" and service["name"] == "http"
        assert service["product"] == "BaseHTTPServer" and service["version"] == "0.6"
        assert service["script"]["http-title"] == "AutoPWN Nmap integration"
        rows = AnalyseScanResults(nm, MagicMock(), MagicMock(), "127.0.0.1")
        assert rows[0][1] == port
        assert web_endpoints("127.0.0.1", rows, nm) == [f"http://127.0.0.1:{port}/"]
        assert progress and nm.scanstats()["uphosts"] == "1"
        assert b"<nmaprun" in nm.get_nmap_last_output()

        api_result = AutoScanner().scan("127.0.0.1", scan_vulns=False, offline=True,
                                        host_timeout="15s", nmap_args=flags)
        assert api_result["127.0.0.1"]["ports"][port]["product"] == service["product"]

        monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
        spec = importlib.util.spec_from_file_location("live_nmap_dashboard", Path(__file__).parents[2] / "modules/web_ui.py")
        dashboard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dashboard)
        monkeypatch.setattr(dashboard, "_notify", MagicMock())
        job = dashboard.ScanJob("live-adapter", "127.0.0.1", {
            "target": "127.0.0.1", "skip_discovery": True, "scan_vulns": False,
            "host_timeout": 30, "nmap_flags": flags})
        dashboard._run_scan(job)
        assert job.status == "completed"
        assert job.hosts_list()[0]["ports"][0]["port"] == port
        assert job.hosts_list()[0]["ports"][0]["product"] == service["product"]


def test_live_ipv6_scan_retains_ipv6_host_key():
    with local_server(ipv6=True) as port:
        nm = PortScanner()
        nm.scan("::1", arguments=f"-6 -sT -Pn -n -p {port}", timeout=15)
        assert nm.all_hosts(up_only=True) == ["::1"]
        assert nm["::1"]["tcp"][port]["state"] == "open"


def test_live_tls_service_and_nse_certificate_are_preserved(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    monkeypatch.setattr("modules.scanner.is_root", lambda: False)
    with local_server(tls_context=context) as port:
        nm = PortScanner()
        nm.scan("127.0.0.1", arguments=f"-sT -sV -Pn -n --version-light -p {port} --script ssl-cert",
                timeout=30)
        service = nm["127.0.0.1"]["tcp"][port]
        assert service["state"] == "open" and service["tunnel"] == "ssl"
        source = ElementTree.fromstring(nm.get_nmap_last_output()).find("host/ports/port/service")
        assert all(service[field] == source.get(field, "")
                   for field in ("name", "product", "version", "tunnel"))
        assert "ssl-cert" in service["script"]
        assert "localhost" in service["script"]["ssl-cert"]
        assert service["script_details"][0]["elements"]
        rows = AnalyseScanResults(nm, MagicMock(), MagicMock(), "127.0.0.1")
        # Preserve Nmap's actual classification. TLS on an arbitrary port does
        # not itself prove HTTP; recorded XML tests cover the HTTP+TLS mapping.
        expected = [f"https://127.0.0.1:{port}/"] if "http" in service["name"] else ["127.0.0.1"]
        assert web_endpoints("127.0.0.1", rows, nm) == expected
