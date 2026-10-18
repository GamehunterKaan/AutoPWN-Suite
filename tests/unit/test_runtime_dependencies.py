# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Keep both install paths complete and independent of the removed Nmap wrapper."""

import ast
import re
import sys
from importlib.metadata import packages_distributions
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def required_packages():
    lines = (ROOT / "requirements.txt").read_text().splitlines()
    return {normalized(Requirement(line).name) for line in lines if line.strip() and not line.startswith("#")}


def test_runtime_manifests_agree_and_exclude_nmap_wrapper():
    block = (ROOT / "pyproject.toml").read_text().split("[tool.poetry.dependencies]", 1)[1].split("\n[", 1)[0]
    poetry = {normalized(name) for name in re.findall(r'^([\w-]+)\s*=', block, re.MULTILINE)} - {"python"}
    assert required_packages() == poetry
    assert "python-nmap" not in poetry
    assert not re.search(r'^name\s*=\s*"python-nmap"', (ROOT / "poetry.lock").read_text(), re.MULTILINE)


def test_every_runtime_import_has_a_declared_python_dependency():
    sources = [ROOT / "api.py", ROOT / "autopwn.py", *sorted((ROOT / "autopwn_suite").rglob("*.py"))]
    imports = set()
    for source in sources:
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8-sig"))):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".")[0])
    external = imports - sys.stdlib_module_names - {"api", "autopwn", "autopwn_suite"}
    distributions = packages_distributions()
    declared = required_packages()
    missing = {name for name in external if not any(normalized(distribution) in declared
                                                    for distribution in distributions.get(name, []))}
    assert not missing, f"Undeclared runtime imports: {sorted(missing)}"
    assert "nmap" not in external
