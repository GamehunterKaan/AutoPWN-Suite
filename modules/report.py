from dataclasses import dataclass
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from requests import post
from rich.console import Console
from enum import Enum


console = Console()


class ReportType(Enum):
    """
    Enum for report types.
    """
    NONE = 0
    EMAIL = 1
    WEBHOOK = 2


@dataclass()
class ReportMail():
    """
    Report mail.
    """
    email : str
    password : str
    email_to : str
    email_from : str
    server : str
    port : int
    attachment : str


@dataclass()
class ReportWebhook():
    """
    Report webhook.
    """
    url : str
    attachment : str


def InitializeEmailReport(EmailObj):
    """
    Initialize email report.
    """
    email = EmailObj.email
    password = EmailObj.password
    email_to = EmailObj.email_to
    email_from = EmailObj.email_from
    server = EmailObj.server
    port = EmailObj.port
    attachment = EmailObj.attachment

    # Send email report
    print("Sending email report...")
    SendEmail(
        email,
        password,
        email_to,
        email_from,
        server,
        port,
        attachment
    )


def SendEmail(
        email,
        password,
        email_to,
        email_from,
        server,
        port,
        attachment
    ):
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

    attachment = attachment
    part = MIMEBase("application", "octet-stream")
    part.set_payload(open(attachment, "rb").read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition", f"attachment; filename='{attachment}'"
    )
    msg.attach(part)

    mail = SMTP(server, port)
    mail.starttls()
    mail.login(email, password)
    text = msg.as_string()
    mail.sendmail(email, email_to, text)
    mail.quit()
    console.print("Email report sent successfully", style="green")


def InitializeWebhookReport(WebhookObj):
    """
    Initialize webhook report.
    """
    url = WebhookObj.url
    attachment = WebhookObj.attachment

    # Send webhook report
    print("Sending webhook report...")
    SendWebhook(url, attachment)


def SendWebhook(url, attachment):
    """
    Send webhook report.
    """
    with open(attachment, "rb") as file:
        payload = {"payload": file}

    try:
        post(url, files=payload)
    except ConnectionError:
        console.print("Webhook report failed to send", style="red")


def InitializeReport(Method, ReportObject):
    """
    Initialize report.
    """
    if Method == ReportType.EMAIL:
        InitializeEmailReport(ReportObject)
    elif Method == ReportType.WEBHOOK:
        InitializeWebhookReport(ReportObject)
    elif Method == ReportType.NONE:
        pass
