# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The agent guide must keep naming files that exist, and Claude Code must read the same text as other agents."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUIDE = (ROOT / "AGENTS.md").read_text(encoding="utf-8")


def referenced_paths():
    """Backticked tokens that look like paths inside this repository (not commands, globs or regex)."""
    top_level = {entry.name for entry in ROOT.iterdir() if entry.is_dir()}
    for token in sorted(set(re.findall(r"`([^`]+)`", GUIDE))):
        if re.search(r"[\s*{}<>()$^|]|\.\.\.", token):
            continue
        in_tree = "/" in token and token.split("/")[0] in top_level
        root_file = re.fullmatch(r"[\w.-]+\.(md|py|toml|txt|yml|tsv|json|sh)", token) is not None
        if in_tree or root_file:
            yield token


def is_gitignored(path):
    return subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", path], check=False).returncode == 0


def test_every_path_the_guide_names_exists():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    paths = list(referenced_paths())
    assert len(paths) > 20, "the path check found almost nothing; the guide or this pattern changed shape"
    # Runtime files the guide mentions (such as the gitignored api.txt) need not exist in a clean checkout.
    missing = [path for path in paths if not (ROOT / path).exists() and not is_gitignored(path)]
    assert not missing, f"AGENTS.md names files that do not exist: {missing}"


def test_claude_code_reads_the_same_guide():
    assert (ROOT / "CLAUDE.md").read_text(encoding="utf-8").split() == ["@AGENTS.md"]


def test_the_guide_stays_short_enough_to_load_every_session():
    assert len(GUIDE.split()) < 1800, "move reference material into docs/ and point to it"
