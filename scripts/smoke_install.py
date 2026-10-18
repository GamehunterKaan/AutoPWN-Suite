#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Smoke-test an installed AutoPWN Suite command (wheel, standalone binary or source launcher).

Usage: smoke_install.py EXPECTED_VERSION COMMAND [ARG ...]

Checks that `COMMAND --version` reports EXPECTED_VERSION, then starts the dashboard on a free
loopback port with an empty data directory and fetches its sign-in page, which proves the bundled
web assets are present. No scan runs and nothing outside a temporary directory is written.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

STARTUP_SECONDS = 90


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - fixed loopback http URL
            return response.status, response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return None, ""


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    version, command = argv[1], argv[2:]

    reported = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=120, check=False)
    expected = f"AutoPWN Suite v{version}"
    if expected not in reported.stdout:
        print(f"FAIL: expected {expected!r}, got {reported.stdout!r} {reported.stderr!r}", file=sys.stderr)
        return 1
    print(f"ok: {expected}")

    port = free_port()
    with tempfile.TemporaryDirectory(prefix="autopwn-smoke-") as data_dir:
        env = {**os.environ, "AUTOPWN_DATA_DIR": data_dir, "PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1"}
        server = subprocess.Popen(
            [*command, "--web", "--web-host", "127.0.0.1", "--web-port", str(port), "--no-color"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + STARTUP_SECONDS
            status, body = None, ""
            while time.monotonic() < deadline and server.poll() is None:
                status, body = fetch(f"http://127.0.0.1:{port}/login")
                if status is not None:
                    break
                time.sleep(1)
            if status != 200 or "<html" not in body.lower():
                print(f"FAIL: dashboard sign-in page not served (status {status}, exit {server.poll()})", file=sys.stderr)
                return 1
            print("ok: dashboard serves its sign-in page")
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
