# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the report module.
"""
import smtplib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, mock_open, patch

import pytest

from autopwn_suite.report import (
    InitializeEmailReport,
    InitializeReport,
    InitializeWebhookReport,
    ReportMail,
    ReportType,
    SendEmail,
    SendWebhook,
)


@pytest.mark.unit
class TestSendMail:
    """Tests for the SendMail function."""

    @patch("autopwn_suite.report.SMTP")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_success(self, mock_file, mock_smtp):
        """Verify that an email is sent correctly on success."""
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        mock_log = MagicMock()

        SendEmail(
            "user@example.com", "password", "to@example.com", "from@example.com", "smtp.example.com", 587, mock_log
        )

        mock_server.login.assert_called_once_with("user@example.com", "password")
        mock_server.sendmail.assert_called_once()
        mock_log.logger.assert_called_with("success", "Email report sent successfully.")
        # Verify it tried to open the temp report file
        mock_file.assert_called_with("tmp_report.html", "r", encoding="utf-8")

    @patch("autopwn_suite.report.SMTP")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_auth_error(self, mock_file, mock_smtp):
        """Verify that an authentication error is handled."""
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(1, "failed")
        mock_smtp.return_value = mock_server

        report_obj = ReportMail("user", "wrongpass", "to", "from", "server", 465)
        mock_log = MagicMock()

        SendEmail(report_obj.email, report_obj.password, report_obj.email_to, report_obj.email_from, report_obj.server, 587, mock_log)
        mock_log.logger.assert_called_with("error", "An error occured while trying to send email report.")
        mock_server.quit.assert_called_once()

    @patch("autopwn_suite.report.SMTP")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_smtp_error(self, mock_file, mock_smtp):
        """Verify that a generic SMTP error during sendmail is handled."""
        mock_server = MagicMock()
        # Simulate an error during the sendmail call
        mock_server.sendmail.side_effect = smtplib.SMTPException("Send failed")
        mock_smtp.return_value = mock_server

        mock_log = MagicMock()

        SendEmail("user", "pass", "to", "from", "server", 587, mock_log)

        # Verify the error was logged
        mock_log.logger.assert_called_with("error", "An error occured while trying to send email report.")

    @patch("autopwn_suite.report.SMTP_SSL")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_implicit_tls_uses_ssl_without_starttls(self, mock_file, mock_smtp_ssl):
        SendEmail("user", "pass", "to", "from", "server", 465, MagicMock())
        mock_smtp_ssl.assert_called_once_with("server", 465, timeout=30, context=mock_smtp_ssl.call_args.kwargs["context"])
        mock_smtp_ssl.return_value.starttls.assert_not_called()
        mock_smtp_ssl.return_value.sendmail.assert_called_once()

    @patch("autopwn_suite.report.SMTP", side_effect=OSError("Connection refused"))
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_smtp_connection_failure_does_not_abort_scan(self, mock_file, mock_smtp):
        log = MagicMock()
        SendEmail("user", "pass", "to", "from", "server", 587, log)
        log.logger.assert_called_with("error", "An error occured while trying to send email report.")


@pytest.mark.unit
class TestSendWebhook:
    """Tests for the SendWebhook function."""

    @patch("autopwn_suite.report.post")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_success(self, mock_file, mock_post):
        """Verify that a webhook is sent correctly on success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook_url = "https://example.com/webhook"
        mock_log = MagicMock()

        SendWebhook(webhook_url, mock_log)

        # Verify it tried to open the temp report file
        mock_file.assert_called_with("report.log", "r", encoding="utf-8")
        assert "files" in mock_post.call_args.kwargs
        mock_log.logger.assert_called_with("success", "Webhook report sent succesfully.")

    @patch("autopwn_suite.report.post")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_http_error(self, mock_file, mock_post):
        """Verify that an HTTP error is handled."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response
        mock_log = MagicMock()

        SendWebhook("url", mock_log) # mock_post is the first argument, so this is fine

        mock_log.logger.assert_any_call("error", "Webhook report failed to send.")

    @patch("autopwn_suite.report.post")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_http_error_reports_the_status_but_never_the_response_body(self, mock_file, mock_post, capsys):
        """The body is server controlled: it often echoes the request path (the secret) and can carry terminal escapes."""
        mock_post.return_value = MagicMock(status_code=404, text="Not Found: /hook/SECRETTOKEN \x1b[2J")
        mock_log = MagicMock()

        SendWebhook("https://hooks.example.invalid/hook/SECRETTOKEN", mock_log)

        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""
        logged = " ".join(str(call.args[1]) for call in mock_log.logger.call_args_list)
        assert "HTTP 404" in logged
        assert "SECRETTOKEN" not in logged and "\x1b" not in logged

    @patch("autopwn_suite.report.post", side_effect=ConnectionError("Test connection error"))
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_connection_error(self, mock_file, mock_post):
        """Verify that a connection error is handled."""
        mock_log = MagicMock()

        SendWebhook("url", mock_log)

        # Verify the generic "failed to send" message is logged
        mock_log.logger.assert_any_call("error", "Webhook report failed to send.")

        # The error class is logged; its text is not, because requests quotes the webhook URL (a credential).
        logged = [str(call.args[1]) for call in mock_log.logger.call_args_list]
        assert any("ConnectionError" in text for text in logged), "the error class was not logged"
        assert not any("Test connection error" in text for text in logged)

    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_failure_never_logs_the_secret_url(self, mock_file):
        """A failed delivery must not put the webhook URL, which is a credential, into the console or report."""
        from requests.exceptions import ConnectionError as RequestsConnectionError

        url = "https://hooks.example.invalid/services/T000/B000/SECRETTOKEN"
        error = RequestsConnectionError(f"HTTPSConnectionPool(host='hooks.example.invalid', port=443): Max retries exceeded with url: {url}")
        mock_log = MagicMock()
        with patch("autopwn_suite.report.post", side_effect=error):
            SendWebhook(url, mock_log)
        logged = " ".join(str(call.args[1]) for call in mock_log.logger.call_args_list)
        assert "SECRETTOKEN" not in logged
        assert "Webhook report failed to send." in logged

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_a_redirect_is_a_failed_delivery_and_is_not_followed(self, status, tmp_path, monkeypatch):
        """A 307/308 would make requests POST the whole report again to the Location, possibly over plain HTTP."""
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        received = []

        class Sink(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)

        class Redirector(Sink):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(status)
                self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/collect")
                self.send_header("Content-Length", "0")
                self.end_headers()

        redirector = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
        servers = [sink, redirector]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        report = tmp_path / "report.log"
        report.write_text("SCAN REPORT BODY", encoding="utf-8")
        log = MagicMock()
        try:
            SendWebhook(f"http://127.0.0.1:{redirector.server_port}/hook", log, str(report))
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()

        assert received == [], "the redirect target must never receive the report"
        logged = [call.args for call in log.logger.call_args_list]
        assert ("error", f"Webhook delivery failed: HTTP {status}") in logged
        assert ("error", "Webhook report failed to send.") in logged
        assert not any(level == "success" for level, _ in logged)

    @pytest.mark.parametrize("status", [201, 202, 204])
    @patch("autopwn_suite.report.post")
    @patch("autopwn_suite.report.open", new_callable=mock_open, read_data="report content")
    def test_all_success_codes_are_accepted(self, mock_file, mock_post, status):
        mock_post.return_value.status_code = status
        log = MagicMock()
        SendWebhook("url", log)
        assert mock_post.call_args.kwargs["timeout"] == 30
        assert mock_post.call_args.kwargs["allow_redirects"] is False
        log.logger.assert_called_with("success", "Webhook report sent succesfully.")


@pytest.mark.unit
class TestInitializeReport:
    """Tests for the InitializeReport function."""

    @patch("autopwn_suite.report.InitializeEmailReport")
    def test_initialize_report_email(self, mock_init_email, mock_rich_console):
        """Verify InitializeReport calls SendMail for email reports."""
        report_obj = MagicMock()
        mock_log = MagicMock()
        InitializeReport(ReportType.EMAIL, report_obj, mock_log, mock_rich_console)
        mock_init_email.assert_called_once_with(report_obj, mock_log, mock_rich_console)

    @patch("autopwn_suite.report.InitializeWebhookReport")
    def test_initialize_report_webhook(self, mock_init_webhook, mock_rich_console):
        """Verify InitializeReport calls SendWebhook for webhook reports."""
        report_obj = "https://example.com/webhook"
        mock_log = MagicMock()
        InitializeReport(ReportType.WEBHOOK, report_obj, mock_log, mock_rich_console)
        mock_init_webhook.assert_called_once_with(report_obj, mock_log, mock_rich_console)

    def test_initialize_report_none(self, mock_rich_console):
        """Verify InitializeReport does nothing for ReportType.NONE."""
        with patch("autopwn_suite.report.InitializeEmailReport") as mock_init_email, \
             patch("autopwn_suite.report.InitializeWebhookReport") as mock_init_webhook:

            InitializeReport(ReportType.NONE, None, MagicMock(), mock_rich_console)

            mock_init_email.assert_not_called()
            mock_init_webhook.assert_not_called()

    @patch("autopwn_suite.report.SendEmail")
    @patch("autopwn_suite.report.TemporaryDirectory")
    def test_initialize_email_report(self, mock_temp_directory, mock_send_email, mock_rich_console):
        """Verify InitializeEmailReport saves HTML and calls SendEmail."""
        report_obj = ReportMail("user", "pass", "to", "from", "server", 123)
        mock_log = MagicMock()
        InitializeEmailReport(report_obj, mock_log, mock_rich_console)
        mock_rich_console.save_html.assert_called_once()
        assert mock_rich_console.save_html.call_args.kwargs["clear"] is False
        mock_send_email.assert_called_once()
        assert mock_send_email.call_args.args[-1] == mock_rich_console.save_html.call_args.args[0]
        mock_temp_directory.return_value.__exit__.assert_called_once()

    @patch("autopwn_suite.report.SendWebhook")
    @patch("autopwn_suite.report.TemporaryDirectory")
    def test_initialize_webhook_report(self, mock_temp_directory, mock_send_webhook, mock_rich_console):
        """Verify InitializeWebhookReport saves text and calls SendWebhook."""
        webhook_url = "https://example.com/webhook"
        mock_log = MagicMock()
        InitializeWebhookReport(webhook_url, mock_log, mock_rich_console)
        mock_rich_console.save_text.assert_called_once()
        assert mock_rich_console.save_text.call_args.kwargs["clear"] is False
        mock_send_webhook.assert_called_once_with(webhook_url, mock_log, mock_rich_console.save_text.call_args.args[0])
        mock_temp_directory.return_value.__exit__.assert_called_once()
