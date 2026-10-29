# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
from typing import Any

# Installs the default `_()`/`ngettext()` so any module of the package can translate, even when it is
# imported on its own (a library user, a fuzz harness) and never reaches the CLI.
from autopwn_suite import i18n  # noqa: F401

__version__ = "2.9.0"


def __getattr__(name: str) -> Any:
    # AutoScanner is resolved lazily so `import autopwn_suite` stays cheap.
    if name == "AutoScanner":
        from autopwn_suite.api import AutoScanner

        return AutoScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
