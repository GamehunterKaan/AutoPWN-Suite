# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Coverage-guided fuzzing of the dashboard's scan-option schema, which validates JSON from API clients."""
import json
import sys

import atheris

with atheris.instrument_imports():
    from autopwn_suite.web.options import normalize_options


def TestOneInput(data):
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    try:
        candidate = json.loads(text)
    except (ValueError, RecursionError):
        return  # not JSON (or nested too deeply for Python 3.10 and 3.11), so it never reaches the schema
    try:
        result = normalize_options(candidate, None)
    except ValueError:
        return  # the documented rejection
    assert isinstance(result["verify_tls"], bool)
    assert all(isinstance(result[name], int) and not isinstance(result[name], bool)
               for name in result if name not in ("checks", "verify_tls"))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
