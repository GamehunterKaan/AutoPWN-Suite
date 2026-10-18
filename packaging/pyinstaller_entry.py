# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Entry point of the standalone binaries (see autopwn-suite.spec)."""
import multiprocessing

from autopwn_suite.cli import run

if __name__ == "__main__":
    # The noise scan starts worker processes; a frozen build re-executes itself to run them.
    multiprocessing.freeze_support()
    run()
