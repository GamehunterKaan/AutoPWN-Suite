# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Read runtime credentials from files kept apart from configuration and settings.

Each credential can be supplied through an environment variable naming a file
(the Docker/Kubernetes ``*_FILE`` convention), so it can be stored with owner-only
permissions, mounted as a secret, and replaced without editing configuration or
restarting with new command-line arguments.
"""

import os
from pathlib import Path

MAX_CREDENTIAL_BYTES = 4096

NIST_API_KEY = "AUTOPWN_NIST_API_KEY_FILE"
SMTP_PASSWORD = "AUTOPWN_SMTP_PASSWORD_FILE"
WEBHOOK_URL = "AUTOPWN_WEBHOOK_URL_FILE"


class CredentialFileError(ValueError):
    """The configured credential file cannot be used; the message never contains its content."""


def read_credential_file(path):
    path = Path(path)
    try:
        if not path.is_file():
            raise CredentialFileError(f"Credential file {path} is not a regular file.")
        with path.open("rb") as source:
            raw = source.read(MAX_CREDENTIAL_BYTES + 1)
    except OSError:
        raise CredentialFileError(f"Credential file {path} could not be read.") from None
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise CredentialFileError(f"Credential file {path} is larger than {MAX_CREDENTIAL_BYTES} bytes.")
    try:
        # A trailing newline and a leading byte order mark (Windows PowerShell writes one) are editor
        # artifacts, never part of the secret.
        value = raw.decode("utf-8-sig").rstrip("\r\n")
    except UnicodeError:
        raise CredentialFileError(f"Credential file {path} is not valid UTF-8.") from None
    if not value or "\n" in value or "\r" in value:
        raise CredentialFileError(f"Credential file {path} must contain exactly one non-empty line.")
    return value


def credential_from_environment(variable):
    """Return the credential named by ``variable``, or None when it is not configured."""
    path = os.environ.get(variable, "").strip()
    return read_credential_file(path) if path else None


def delivery_error_summary(error):
    """Describe a failed notification delivery without the exception text.

    ``requests`` quotes the full request URL in its messages, and a webhook URL is itself a credential,
    so only the exception class and, when the server answered, the HTTP status are safe to log.
    """
    status = getattr(getattr(error, "response", None), "status_code", None)
    name = type(error).__name__
    return f"{name} (HTTP {status})" if isinstance(status, int) else name
