# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Coverage-guided fuzzing of the Nmap XML parser, which reads target-influenced output."""
import sys

import atheris

with atheris.instrument_imports():
    from autopwn_suite.nmap_backend import parse_nmap_xml


def TestOneInput(data):
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    try:
        parse_nmap_xml(text)
    except RuntimeError:
        pass  # the documented rejection of a malformed document; anything else is a finding


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
