# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Install checksum-pinned, upstream security tools on Linux CI runners."""

import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

TOOLS = {
    "osv-scanner": (
        "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64",
        "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"),
    "syft": (
        "https://github.com/anchore/syft/releases/download/v1.54.1/syft_1.54.1_linux_amd64.tar.gz",
        "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47"),
}


def install(name, directory):
    url, expected = TOOLS[name]
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Checksum mismatch for {name}")
    if name == "syft":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember("syft")
            if not member.isfile():
                raise ValueError("Expected a regular executable")
            data = archive.extractfile(member).read()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    destination.write_bytes(data)
    destination.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--syft", action="store_true")
    args = parser.parse_args()
    install("osv-scanner", args.directory)
    if args.syft:
        install("syft", args.directory)
