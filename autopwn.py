# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Source-checkout launcher: `python autopwn.py` runs the same CLI as `autopwn-suite`."""
from autopwn_suite.cli import run

if __name__ == "__main__":
    run()
