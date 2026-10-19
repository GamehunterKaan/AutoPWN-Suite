# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import ssl
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from smtplib import SMTP, SMTP_SSL
from tempfile import TemporaryDirectory

from requests import post

from autopwn_suite.credential_files import delivery_error_summary


class ReportType(Enum):
    """
    Enum for report types.
    """

    NONE = 0
    EMAIL = 1
    WEBHOOK = 2


@dataclass()
class ReportMail:
    """
    Report mail.
    """

    email: str
    password: str
    email_to: str
    email_from: str
    server: str
    port: int


def InitializeEmailReport(EmailObj, log, console) -> None:
    """
    Initialize email report.
    """
    email = EmailObj.email
    password = EmailObj.password
    email_to = EmailObj.email_to
    email_from = EmailObj.email_from
    server = EmailObj.server
    port = EmailObj.port

    with TemporaryDirectory(prefix="autopwn-report-") as directory:
        report_path = str(Path(directory) / "report.html")
        console.save_html(report_path, clear=False)
        log.logger("info", "Sending email report...")
        SendEmail(email, password, email_to, email_from, server, port, log, report_path)


def SendEmail(email, password, email_to, email_from, server, port, log, report_path="tmp_report.html") -> None:
    """
    Send email report.
    """

    # Since google disabled sending emails via
    # smtp, i didn't have an opportunity to test
    # please create an issue if you test this
    msg = MIMEMultipart()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = "AutoPWN Report"

    body = "AutoPWN Report"
    msg.attach(MIMEText(body, "plain"))

    with open(report_path, "r", encoding="utf-8") as f:
        html = f.read()
    part = MIMEText(html, "html")
    msg.attach(part)

    mail = None
    try:
        context = ssl.create_default_context()
        if int(port) == 465:
            mail = SMTP_SSL(server, port, timeout=30, context=context)
        else:
            mail = SMTP(server, port, timeout=30)
            mail.starttls(context=context)
        mail.login(email, password)
        text = msg.as_string()
        mail.sendmail(email, email_to, text)
    except Exception:
        log.logger("error", "An error occured while trying to send email report.")
    else:
        log.logger("success", "Email report sent successfully.")
    finally:
        if mail is not None:
            try:
                mail.quit()
            except Exception:
                try:
                    mail.close()
                except Exception:
                    pass


def InitializeWebhookReport(Webhook, log, console) -> None:
    """
    Initialize webhook report.
    """
    log.logger("info", "Sending webhook report...")
    with TemporaryDirectory(prefix="autopwn-report-") as directory:
        report_path = str(Path(directory) / "report.log")
        console.save_text(report_path, clear=False)
        SendWebhook(Webhook, log, report_path)


def SendWebhook(url, log, report_path="report.log") -> None:
    """
    Send webhook report.
    """
    with open(report_path, "r", encoding="utf-8") as file:
        payload = {"payload": file}

        try:
            # A 307/308 redirect would re-send the whole report to whatever host the Location names, possibly
            # over plain HTTP, so a redirect is a failed delivery.
            req = post(url, files=payload, timeout=30, allow_redirects=False)
            if 200 <= req.status_code < 300:
                log.logger("success", "Webhook report sent succesfully.")
            else:
                # The response body is server controlled and often echoes the request path, which is the secret.
                log.logger("error", f"Webhook delivery failed: HTTP {req.status_code}")
                log.logger("error", "Webhook report failed to send.")
        except Exception as e:
            log.logger("error", f"Webhook delivery failed: {delivery_error_summary(e)}")
            log.logger("error", "Webhook report failed to send.")


def InitializeReport(Method, ReportObject, log, console) -> None:
    """
    Initialize report.
    """
    if Method == ReportType.EMAIL:
        InitializeEmailReport(ReportObject, log, console)
    elif Method == ReportType.WEBHOOK:
        InitializeWebhookReport(ReportObject, log, console)
