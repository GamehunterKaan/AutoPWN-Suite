"""
Unit tests for the report module.
"""
import smtplib
from unittest.mock import MagicMock, mock_open, patch

import pytest
from requests.exceptions import HTTPError

from modules.report import (
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

    @patch("modules.report.SMTP")
    @patch("modules.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_success(self, mock_file, mock_smtp):
        """Verify that an email is sent correctly on success."""
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        mock_log = MagicMock()

        SendEmail(
            "user@example.com", "password", "to@example.com", "from@example.com", "smtp.example.com", 465, mock_log
        )

        mock_server.login.assert_called_once_with("user@example.com", "password")
        mock_server.sendmail.assert_called_once()
        mock_log.logger.assert_called_with("success", "Email report sent successfully.")
        # Verify it tried to open the temp report file
        mock_file.assert_called_with("tmp_report.html", "rb")

    @patch("modules.report.SMTP")
    @patch("modules.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_auth_error(self, mock_file, mock_smtp):
        """Verify that an authentication error is handled."""
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(1, "failed")
        mock_smtp.return_value = mock_server

        report_obj = ReportMail("user", "wrongpass", "to", "from", "server", 465)
        mock_log = MagicMock()

        with pytest.raises(smtplib.SMTPAuthenticationError):
            SendEmail(report_obj.email, report_obj.password, report_obj.email_to, report_obj.email_from, report_obj.server, report_obj.port, mock_log)

    @patch("modules.report.SMTP")
    @patch("modules.report.open", new_callable=mock_open, read_data="<h1>Test</h1>")
    def test_send_mail_smtp_error(self, mock_file, mock_smtp):
        """Verify that a generic SMTP error during sendmail is handled."""
        mock_server = MagicMock()
        # Simulate an error during the sendmail call
        mock_server.sendmail.side_effect = smtplib.SMTPException("Send failed")
        mock_smtp.return_value = mock_server

        mock_log = MagicMock()

        SendEmail("user", "pass", "to", "from", "server", 465, mock_log)

        # Verify the error was logged
        mock_log.logger.assert_called_with("error", "An error occured while trying to send email report.")


@pytest.mark.unit
class TestSendWebhook:
    """Tests for the SendWebhook function."""

    @patch("modules.report.post")
    @patch("modules.report.open", new_callable=mock_open, read_data="report content")
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

    @patch("modules.report.post")
    @patch("modules.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_http_error(self, mock_file, mock_post):
        """Verify that an HTTP error is handled."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response
        mock_log = MagicMock()

        SendWebhook("url", mock_log) # mock_post is the first argument, so this is fine

        mock_log.logger.assert_any_call("error", "Webhook report failed to send.")

    @patch("modules.report.post", side_effect=ConnectionError("Test connection error"))
    @patch("modules.report.open", new_callable=mock_open, read_data="report content")
    def test_send_webhook_connection_error(self, mock_file, mock_post):
        """Verify that a connection error is handled."""
        mock_log = MagicMock()

        SendWebhook("url", mock_log)

        # Verify the generic "failed to send" message is logged
        mock_log.logger.assert_any_call("error", "Webhook report failed to send.")
        
        # Verify the exception itself was also logged by checking all calls
        exception_logged = any(isinstance(call.args[1], ConnectionError) for call in mock_log.logger.call_args_list)
        assert exception_logged, "ConnectionError was not logged"


@pytest.mark.unit
class TestInitializeReport:
    """Tests for the InitializeReport function."""

    @patch("modules.report.InitializeEmailReport")
    def test_initialize_report_email(self, mock_init_email, mock_rich_console):
        """Verify InitializeReport calls SendMail for email reports."""
        report_obj = MagicMock()
        mock_log = MagicMock()
        InitializeReport(ReportType.EMAIL, report_obj, mock_log, mock_rich_console)
        mock_init_email.assert_called_once_with(report_obj, mock_log, mock_rich_console)

    @patch("modules.report.InitializeWebhookReport")
    def test_initialize_report_webhook(self, mock_init_webhook, mock_rich_console):
        """Verify InitializeReport calls SendWebhook for webhook reports."""
        report_obj = "https://example.com/webhook"
        mock_log = MagicMock()
        InitializeReport(ReportType.WEBHOOK, report_obj, mock_log, mock_rich_console)
        mock_init_webhook.assert_called_once_with(report_obj, mock_log, mock_rich_console)

    def test_initialize_report_none(self, mock_rich_console):
        """Verify InitializeReport does nothing for ReportType.NONE."""
        with patch("modules.report.InitializeEmailReport") as mock_init_email, \
             patch("modules.report.InitializeWebhookReport") as mock_init_webhook:
            
            InitializeReport(ReportType.NONE, None, MagicMock(), mock_rich_console)
            
            mock_init_email.assert_not_called()
            mock_init_webhook.assert_not_called()

    @patch("modules.report.SendEmail")
    @patch("modules.report.remove")
    def test_initialize_email_report(self, mock_remove, mock_send_email, mock_rich_console):
        """Verify InitializeEmailReport saves HTML and calls SendEmail."""
        report_obj = ReportMail("user", "pass", "to", "from", "server", 123)
        mock_log = MagicMock()
        InitializeEmailReport(report_obj, mock_log, mock_rich_console)
        mock_rich_console.save_html.assert_called_once_with("tmp_report.html")
        mock_send_email.assert_called_once()

    @patch("modules.report.SendWebhook")
    @patch("modules.report.remove")
    def test_initialize_webhook_report(self, mock_remove, mock_send_webhook, mock_rich_console):
        """Verify InitializeWebhookReport saves text and calls SendWebhook."""
        webhook_url = "https://example.com/webhook"
        mock_log = MagicMock()
        InitializeWebhookReport(webhook_url, mock_log, mock_rich_console)
        mock_rich_console.save_text.assert_called_once_with("report.log")
        mock_send_webhook.assert_called_once_with(webhook_url, mock_log)