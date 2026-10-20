# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""TLS peer authentication must precede SMTP credentials on every mail path."""

import smtplib
import socketserver
import ssl
import threading
from unittest.mock import MagicMock, mock_open, patch

import pytest

from autopwn_suite.report import SendEmail
from tests.unit.test_web_dashboard import dashboard as dashboard
from tests.unit.test_web_transport_security import local_certificate as local_certificate


def assert_validating(context):
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("port", [465, 587])
def test_cli_smtp_authenticates_peer_before_sending(port):
    with patch("autopwn_suite.report.SMTP") as plain, patch("autopwn_suite.report.SMTP_SSL") as implicit, \
         patch("autopwn_suite.report.open", mock_open(read_data="report")):
        SendEmail("user", "password", "to", "from", "mail.example", port, MagicMock())
        factory = implicit if port == 465 else plain
        server = factory.return_value
        context = factory.call_args.kwargs.get("context") if port == 465 else server.starttls.call_args.kwargs.get("context")
        assert_validating(context)
        server.login.assert_called_once_with("user", "password")
        server.sendmail.assert_called_once()


@pytest.mark.parametrize("port", [465, 587])
def test_dashboard_smtp_authenticates_peer_and_rejects_certificate_failure(dashboard, port):
    wu, _ = dashboard
    config = {"smtp_host": "mail.example", "smtp_port": port, "username": "user", "password": "password"}
    with patch.object(wu.smtplib, "SMTP") as plain, patch.object(wu.smtplib, "SMTP_SSL") as implicit:
        factory = implicit if port == 465 else plain
        server = factory.return_value.__enter__.return_value
        with wu._smtp_connection(config) as connection:
            assert connection is server
        context = factory.call_args.kwargs.get("context") if port == 465 else server.starttls.call_args.kwargs.get("context")
        assert_validating(context)
        server.login.assert_called_once_with("user", "password")
        server.reset_mock()
        if port == 465:
            factory.side_effect = ssl.SSLCertVerificationError("untrusted")
        else:
            server.starttls.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
        with pytest.raises(ssl.SSLCertVerificationError), wu._smtp_connection(config):
            pytest.fail("Unverified connection must not be yielded")
        server.login.assert_not_called()


def test_cli_certificate_failure_skips_login_and_report_and_cleans_up():
    with patch("autopwn_suite.report.SMTP") as factory, patch("autopwn_suite.report.open", mock_open(read_data="report")):
        server = factory.return_value
        server.starttls.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
        log = MagicMock()
        SendEmail("user", "password", "to", "from", "mail.example", 587, log)
        server.login.assert_not_called()
        server.sendmail.assert_not_called()
        server.quit.assert_called_once()
        log.logger.assert_called_with("error", "An error occurred while trying to send email report.")


@pytest.mark.parametrize("port", [465, 587])
@pytest.mark.parametrize("trusted,hostname", [(False, "localhost"), (True, "localhost"), (True, "127.0.0.1")])
@pytest.mark.parametrize("entry", ["cli", "dashboard"])
def test_real_smtp_tls_rejects_unknown_peer_and_preserves_trusted_delivery(dashboard, local_certificate, port, trusted, hostname, entry):
    wu, _ = dashboard
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, local_certificate))
    commands = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            connection = self.request
            stream = None
            try:
                connection.settimeout(3)
                if port == 465:
                    connection = context.wrap_socket(connection, server_side=True)
                connection.sendall(b"220 localhost ESMTP\r\n")
                stream = connection.makefile("rb")
                while True:
                    line = stream.readline()
                    if not line:
                        return
                    commands.append(line)
                    command = line.split()[0].upper()
                    if command in (b"EHLO", b"HELO"):
                        connection.sendall(b"250-localhost\r\n250-AUTH PLAIN\r\n250 STARTTLS\r\n")
                    elif command == b"STARTTLS":
                        connection.sendall(b"220 Begin TLS\r\n")
                        stream.close()
                        stream = None
                        connection = context.wrap_socket(connection, server_side=True)
                        stream = connection.makefile("rb")
                    elif command == b"AUTH":
                        connection.sendall(b"235 Authenticated\r\n")
                    elif command == b"DATA":
                        connection.sendall(b"354 Send message\r\n")
                        while stream.readline() not in (b".\r\n", b""):
                            pass
                        connection.sendall(b"250 Accepted\r\n")
                    elif command == b"QUIT":
                        connection.sendall(b"221 Bye\r\n")
                        return
                    else:
                        connection.sendall(b"250 OK\r\n")
            except (OSError, ssl.SSLError):
                pass
            finally:
                if stream:
                    stream.close()
                connection.close()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    client_context = ssl.create_default_context()
    if trusted:
        client_context.load_verify_locations(cafile=str(local_certificate[0]))
    real_plain, real_ssl = smtplib.SMTP, smtplib.SMTP_SSL
    accepted = trusted and hostname == "localhost"
    with Server(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02})
        worker.start()
        actual_port = server.server_address[1]
        def plain(host, configured_port, **kwargs):
            return real_plain(host, actual_port, local_hostname="autopwn-test", **kwargs)
        def implicit(host, configured_port, **kwargs):
            return real_ssl(host, actual_port, local_hostname="autopwn-test", **kwargs)
        try:
            if entry == "cli":
                log = MagicMock()
                with patch("autopwn_suite.report.SMTP", side_effect=plain), patch("autopwn_suite.report.SMTP_SSL", side_effect=implicit), \
                     patch("autopwn_suite.report.ssl.create_default_context", return_value=client_context), \
                     patch("autopwn_suite.report.open", mock_open(read_data="report")):
                    SendEmail("synthetic-user", "synthetic-password", "to@example.invalid", "from@example.invalid", hostname, port, log)
                assert log.logger.call_args.args[0] == ("success" if accepted else "error")
            else:
                cfg = {"smtp_host": hostname, "smtp_port": port, "username": "synthetic-user", "password": "synthetic-password"}
                with patch.object(wu.smtplib, "SMTP_SSL" if port == 465 else "SMTP", side_effect=implicit if port == 465 else plain), \
                     patch.object(wu.ssl, "create_default_context", return_value=client_context):
                    if accepted:
                        with wu._smtp_connection(cfg) as connection:
                            connection.sendmail("from@example.invalid", "to@example.invalid", "Subject: test\r\n\r\nreport")
                    else:
                        with pytest.raises(ssl.SSLCertVerificationError), wu._smtp_connection(cfg):
                            pytest.fail("Untrusted peer was accepted")
        finally:
            server.shutdown()
            worker.join(2)
    assert any(line.startswith(b"AUTH ") for line in commands) is accepted
    assert any(line.upper().startswith(b"DATA") for line in commands) is accepted
