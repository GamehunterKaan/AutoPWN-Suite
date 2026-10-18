#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Write a CycloneDX SBOM for one standalone binary from the environment that built it.

Usage: binary_sbom.py --version VERSION --target TARGET --output FILE [--requirements requirements-locked.txt]

The binary freezes the packages of the hash-pinned runtime requirements that apply to its platform, the
Python interpreter it was built with and PyInstaller's bootloader, so the SBOM lists exactly those:
every requirement installed in this environment (markers such as `platform_system == "Windows"` decide
what applies), the interpreter and PyInstaller. Run it after installing the requirements and building.
"""
import argparse
import json
import platform
import re
import sys
from importlib import metadata
from pathlib import Path

REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", re.MULTILINE)


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def pinned(requirements):
    """(name, version) pairs pinned in a requirements file."""
    return [(normalized(name), version) for name, version in REQUIREMENT.findall(requirements)]


def library(name, version):
    return {"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"}


def build_sbom(requirements, version, target):
    components = []
    for name, locked in pinned(requirements):
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue  # excluded by an environment marker on this platform
        if installed != locked:
            raise ValueError(f"{name} is installed as {installed} but locked as {locked}")
        components.append(library(name, installed))
    components.append(library("pyinstaller", metadata.version("pyinstaller")))
    interpreter = platform.python_version()
    components.append({"type": "platform", "name": "cpython", "version": interpreter, "purl": f"pkg:generic/cpython@{interpreter}"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": f"autopwn-suite-{target}", "version": version},
            "properties": [{"name": "build:target", "value": target}],
        },
        "components": sorted(components, key=lambda component: (component["type"], component["name"])),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, default=Path("requirements-locked.txt"))
    args = parser.parse_args(argv)
    sbom = build_sbom(args.requirements.read_text(encoding="utf-8"), args.version, args.target)
    args.output.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{args.output}: {len(sbom['components'])} components")


if __name__ == "__main__":
    sys.exit(main())
