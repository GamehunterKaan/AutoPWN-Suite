#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Build one standalone binary with the pinned toolchain; optionally build it twice and require identical bytes.

Usage: build_binary.py --target TARGET --work-dir DIR --source-date-epoch SECONDS --output FILE [--repeat]

The toolchain is the CPython that packaging/build-python.json pins by SHA-256 (a self-contained
python-build-standalone archive, so no library of the build machine ends up in the binary), a virtual
environment installed from the hash-pinned requirements-locked.txt and packaging/requirements-build.txt, and
PyInstaller run with PYTHONHASHSEED=1 and SOURCE_DATE_EPOCH. Run it on the release source (docs/BUILDING.md
explains how to check a published binary with it). It needs only the standard library of the Python running it.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "packaging" / "build-python.json"
SPEC = ROOT / "packaging" / "autopwn-suite.spec"
REQUIREMENTS = (ROOT / "requirements-locked.txt", ROOT / "packaging" / "requirements-build.txt")
DOWNLOAD_PREFIX = "https://github.com/astral-sh/python-build-standalone/releases/download/"


def is_windows(target):
    return target.startswith("windows-")


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_pins(path=PINS):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fetch_python(pins, target, work):
    """Download the pinned interpreter archive (unless it is already there), check its hash and unpack it."""
    entry = pins["archives"][target]
    if not pins["url"].startswith(DOWNLOAD_PREFIX):
        raise SystemExit(f"refusing to download from {pins['url']}")
    archive = work / entry["file"]
    if not archive.is_file():
        with urllib.request.urlopen(pins["url"] + urllib.parse.quote(entry["file"]), timeout=300) as response, open(archive, "wb") as stream:  # noqa: S310 - https URL checked above
            shutil.copyfileobj(response, stream)
    found = sha256_of(archive)
    if found != entry["sha256"]:
        raise SystemExit(f"{archive.name} has SHA-256 {found}, expected {entry['sha256']}")
    destination = work / "python"
    shutil.rmtree(destination, ignore_errors=True)
    with tarfile.open(archive) as tar:
        tar.extractall(destination, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))  # noqa: S202 - hash-checked archive
    return destination / "python" / ("python.exe" if is_windows(target) else "bin/python3")


def make_environment(interpreter, work, target):
    """A virtual environment of that interpreter holding the hash-pinned runtime and build requirements."""
    venv = work / "venv"
    shutil.rmtree(venv, ignore_errors=True)
    subprocess.run([str(interpreter), "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if is_windows(target) else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "--only-binary=:all:", "--no-deps",
                    *[arg for path in REQUIREMENTS for arg in ("-r", str(path))]], check=True)
    return python


def run_pyinstaller(python, work, target, epoch):
    """One clean PyInstaller build; returns the path of the executable."""
    dist, build = work / "dist", work / "build"
    for path in (dist, build):
        shutil.rmtree(path, ignore_errors=True)
    # PYTHONHASHSEED fixes the order PyInstaller derives from set iteration, SOURCE_DATE_EPOCH its timestamps, and a
    # private config directory keeps a cache of the user's earlier builds out of the result.
    env = {**os.environ, "PYTHONHASHSEED": "1", "SOURCE_DATE_EPOCH": str(epoch), "PYINSTALLER_CONFIG_DIR": str(work / "config")}
    subprocess.run([str(python), "-m", "PyInstaller", "--clean", "--noconfirm", "--distpath", str(dist), "--workpath", str(build), str(SPEC)],
                   cwd=ROOT, env=env, check=True)
    return dist / ("autopwn-suite.exe" if is_windows(target) else "autopwn-suite")


def build(python, work, target, epoch, repeat):
    """Build the binary, and with `repeat` build it a second time from scratch and require the same bytes."""
    built = run_pyinstaller(python, work, target, epoch)
    if repeat:
        first = work / ("first-build" + built.suffix)
        shutil.copy2(built, first)
        again = run_pyinstaller(python, work, target, epoch)
        if sha256_of(first) != sha256_of(again):
            raise SystemExit(f"the second build of {target} differs: {sha256_of(first)} then {sha256_of(again)}")
    return built


def main(argv=None):
    pins = load_pins()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, choices=sorted(pins["archives"]))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, default=os.environ.get("SOURCE_DATE_EPOCH"),
                        help="commit time of the source, in seconds (default: $SOURCE_DATE_EPOCH)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", action="store_true", help="build twice and fail unless both builds are identical")
    args = parser.parse_args(argv)
    if args.source_date_epoch is None or args.source_date_epoch < 0:
        parser.error("--source-date-epoch (or SOURCE_DATE_EPOCH) must be a non-negative number of seconds")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    python = make_environment(fetch_python(pins, args.target, work), work, args.target)
    built = build(python, work, args.target, args.source_date_epoch, args.repeat)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, args.output)
    print(f"{sha256_of(args.output)}  {args.output.name}")


if __name__ == "__main__":
    sys.exit(main())
