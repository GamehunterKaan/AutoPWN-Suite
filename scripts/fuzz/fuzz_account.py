# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Coverage-guided fuzzing of the dashboard account validation, which handles credentials from a sign-in form."""
import sys

import atheris

with atheris.instrument_imports():
    from autopwn_suite.web_auth import validate_account


def TestOneInput(data):
    provider = atheris.FuzzedDataProvider(data)
    username = provider.ConsumeUnicodeNoSurrogates(provider.ConsumeIntInRange(0, 64))
    password = provider.ConsumeUnicodeNoSurrogates(provider.ConsumeIntInRange(0, 256))
    try:
        validate_account(username, password)
    except ValueError:
        pass  # the documented rejection; anything else is a finding


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
