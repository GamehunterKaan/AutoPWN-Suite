# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import os
import sys
from pathlib import Path

APP_DIR_NAME = "autopwn-suite"


def default_data_dir() -> Path:
    """Per-user directory for the dashboard account, settings and the local CVE database."""
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / APP_DIR_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME", "")
    return (Path(xdg) if os.path.isabs(xdg) else Path.home() / ".local" / "share") / APP_DIR_NAME


def data_dir() -> Path:
    """`AUTOPWN_DATA_DIR` when set, otherwise the per-user default."""
    configured = os.environ.get("AUTOPWN_DATA_DIR")
    return Path(configured) if configured else default_data_dir()
