from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from os import remove
from smtplib import SMTP

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

    console.save_html("tmp_report.html")

    log.logger("info", "Sending email report...")

    SendEmail(email, password, email_to, email_from, server, port, log)

    remove("tmp_report.html")


def SendEmail(email, password, email_to, email_from, server, port, log) -> None:
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

    html = open("tmp_report.html", "rb").read()
    part = MIMEText(html, "text/html")
    msg.attach(part)

    mail = SMTP(server, port)
    mail.starttls()
    mail.login(email, password)
    text = msg.as_string()
    mail.sendmail(email, email_to, text)
    mail.quit()
    log.logger("success", "Email report sent successfully.")


def InitializeWebhookReport(Webhook, log, console) -> None:
    """
    Initialize webhook report.
    """
    # Send webhook report
    log.logger("info", "Sending webhook report...")
    console.save_text("report.log")
    SendWebhook(Webhook, log)
    remove("report.log")


def SendWebhook(url, log) -> None:
    """
    Send webhook report.
    """
    file = open("report.log", "r")  # read of closed file
    payload = {"payload": file}

    try:
        req = post(url, files=payload)
        file.close()
        if req.status_code == 200:
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
