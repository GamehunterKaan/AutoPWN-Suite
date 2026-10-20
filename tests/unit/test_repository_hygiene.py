# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Release artifacts are built by CI; no generated or executable binaries belong in the repository."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".whl", ".pyc", ".pyd", ".jar", ".class", ".a", ".o"}
MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def tracked_files():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    output = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [ROOT / name.decode() for name in output.split(b"\0") if name]


def test_no_executables_libraries_or_distributions_are_tracked():
    offenders = []
    for path in tracked_files():
        if not path.is_file():
            continue  # deleted in the working tree
        with path.open("rb") as handle:
            head = handle.read(4)
        if path.suffix.lower() in BINARY_SUFFIXES or head.startswith(MAGIC):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert not offenders, f"generated binaries must not be committed: {offenders}"


def test_ignore_rules_cover_what_the_release_builds_produce():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("dist/", "build/", "*.exe", "*.whl", "SHA256SUMS*", "*.sigstore.json", "*.intoto.jsonl"):
        assert pattern in ignored.splitlines(), f".gitignore must list {pattern}"
