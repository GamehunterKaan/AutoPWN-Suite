# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Source-checkout launcher: `python autopwn.py` runs the same CLI as `autopwn-suite`."""
import os
import signal

from autopwn_suite.cli import run


def exit_on_sigterm_as_pid_1() -> None:
    """The container image starts this launcher as PID 1. The kernel applies no default action to a signal that
    PID 1 has no handler for, so `docker stop` (SIGTERM) would be ignored until Docker kills the container after
    10 seconds. Elsewhere the default action already ends the process, and the handler is left out."""
    if os.getpid() != 1:
        return

    def stop(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop)


if __name__ == "__main__":
    exit_on_sigterm_as_pid_1()
    run()
