from enum import Enum
from dataclasses import dataclass

class ReportType(Enum):
    """
    Enum for report types.
    """
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