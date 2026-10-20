#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Extract translatable strings into autopwn.pot and compile/check catalogs.

Usage:
    python scripts/i18n_messages.py extract           # regenerate autopwn.pot
    python scripts/i18n_messages.py merge --lang tr   # merge .pot into tr.po
    python scripts/i18n_messages.py compile --lang tr # regenerate tr.mo
    python scripts/i18n_messages.py check --lang tr    # exit 1 on .mo/.po drift (CI)
"""

from __future__ import annotations

import argparse
import filecmp
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ROOT / "autopwn_suite" / "locales"
POT_FILE = LOCALES / "autopwn.pot"


def _sources() -> list[str]:
    paths = sorted((ROOT / "autopwn_suite").rglob("*.py"))
    return [str(p.relative_to(ROOT)) for p in paths if "__pycache__" not in str(p)]


def extract() -> None:
    LOCALES.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "xgettext",
            "--language=Python",
            "--from-code=UTF-8",
            "--keyword=_",
            "--keyword=N_",
            "--keyword=ngettext:1,2",
            "--package-name=AutoPWN Suite",
            "--copyright-holder=Kaan Gültekin",
            "-o",
            str(POT_FILE),
            *_sources(),
        ],
        cwd=ROOT,
        check=True,
    )


def _po_path(lang: str) -> Path:
    return LOCALES / lang / "LC_MESSAGES" / "autopwn.po"


def _mo_path(lang: str) -> Path:
    return LOCALES / lang / "LC_MESSAGES" / "autopwn.mo"


def merge(lang: str) -> None:
    po = _po_path(lang)
    if not po.exists():
        raise SystemExit(f"{po} does not exist; create it before merging.")
    subprocess.run(["msgmerge", "--update", "--backup=none", str(po), str(POT_FILE)], check=True)


def compile_mo(lang: str) -> None:
    # --use-fuzzy: fuzzy-marked entries (machine-translated, unreviewed) must
    # still be served, not silently dropped back to English by msgfmt's default.
    po = _po_path(lang)
    mo = _mo_path(lang)
    mo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["msgfmt", "--use-fuzzy", "-o", str(mo), str(po)], check=True)


def check(lang: str) -> None:
    po = _po_path(lang)
    mo = _mo_path(lang)
    if not mo.exists():
        raise SystemExit(f"{mo} is missing; run: python scripts/i18n_messages.py compile --lang {lang}")
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "fresh.mo"
        subprocess.run(["msgfmt", "--use-fuzzy", "-o", str(fresh), str(po)], check=True)
        if not filecmp.cmp(fresh, mo, shallow=False):
            raise SystemExit(
                f"{mo} is out of date with {po}; run: "
                f"python scripts/i18n_messages.py compile --lang {lang}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("extract", "merge", "compile", "check"))
    parser.add_argument("--lang", default="tr")
    args = parser.parse_args()

    if args.action == "extract":
        extract()
    elif args.action == "merge":
        merge(args.lang)
    elif args.action == "compile":
        compile_mo(args.lang)
    else:
        check(args.lang)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
