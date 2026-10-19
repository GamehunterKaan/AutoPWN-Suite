# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""README.md is the PyPI project description, and PyPI cannot resolve relative paths, so every target must be absolute."""
import re
from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"
ABSOLUTE = ("https://", "http://", "#", "mailto:")


def test_readme_links_and_images_are_absolute():
    text = re.sub(r"```.*?```", "", README.read_text(encoding="utf-8"), flags=re.DOTALL)
    targets = re.findall(r"\]\(([^)\s]+)", text) + re.findall(r'(?:href|src)="([^"]+)"', text)
    relative = sorted({target for target in targets if not target.startswith(ABSOLUTE)})
    assert not relative, f"PyPI cannot resolve relative README targets: {relative}"
