# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Environment for the system programs (nmap, ip, systemctl) that AutoPWN Suite starts."""
import os
import sys


def child_environment():
    """None (inherit the environment) except in the standalone Linux binary.

    The PyInstaller bootloader of a onefile binary points LD_LIBRARY_PATH at the directory it unpacked itself
    into, so a system program started from the binary would load the bundled libssl, libz and the like, built
    on another distribution, instead of its own. The bootloader keeps the original value in
    LD_LIBRARY_PATH_ORIG; children get that value back, or none when there was none."""
    if not (sys.platform.startswith("linux") and getattr(sys, "frozen", False)):
        return None
    environment = dict(os.environ)
    original = environment.get("LD_LIBRARY_PATH_ORIG")
    if original:
        environment["LD_LIBRARY_PATH"] = original
    else:
        environment.pop("LD_LIBRARY_PATH", None)
    return environment
