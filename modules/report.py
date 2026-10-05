from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from smtplib import SMTP, SMTP_SSL
from tempfile import TemporaryDirectory

from requests import post


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
        if int(port) == 465:
            mail = SMTP_SSL(server, port, timeout=30)
        else:
            mail = SMTP(server, port, timeout=30)
            mail.starttls()
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
            req = post(url, files=payload, timeout=30)
            if 200 <= req.status_code < 300:
                log.logger("success", "Webhook report sent succesfully.")
            else:
                log.logger("error", "Webhook report failed to send.")
                print(req.text)
        except Exception as e:
            log.logger("error", e)
            log.logger("error", "Webhook report failed to send.")


def InitializeReport(Method, ReportObject, log, console) -> None:
    """
    Initialize report.
    """
    if Method == ReportType.EMAIL:
        InitializeEmailReport(ReportObject, log, console)
    elif Method == ReportType.WEBHOOK:
        InitializeWebhookReport(ReportObject, log, console)
