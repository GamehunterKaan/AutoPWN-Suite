# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The per-binary SBOM lists what that platform's binary really bundles."""
import importlib.util
import json
import platform
from importlib import metadata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("binary_sbom", ROOT / "scripts" / "binary_sbom.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)

REQUIREMENTS = """requests==2.33.1 \\
    --hash=sha256:00
flask==3.1.3 \\
    --hash=sha256:11
colorama==0.4.6 ; platform_system == "Windows" \\
    --hash=sha256:22
Some_Package.Name==1.0 ; python_version < "3.0"
"""


@pytest.fixture
def installed(monkeypatch):
    versions = {"requests": "2.33.1", "flask": "3.1.3", "pyinstaller": "6.22.3"}

    def version(name):
        try:
            return versions[name]
        except KeyError:
            raise metadata.PackageNotFoundError(name) from None

    monkeypatch.setattr(sbom.metadata, "version", version)
    return versions


def test_requirement_parser_handles_markers_hashes_and_name_spelling():
    assert sbom.pinned(REQUIREMENTS) == [("requests", "2.33.1"), ("flask", "3.1.3"), ("colorama", "0.4.6"), ("some-package-name", "1.0")]


def test_only_requirements_installed_on_this_platform_are_listed(installed):
    document = sbom.build_sbom(REQUIREMENTS, "2.7.0", "linux-amd64")
    names = {component["name"] for component in document["components"]}
    assert names == {"requests", "flask", "pyinstaller", "cpython"}  # colorama and the old-Python package are skipped
    assert document["bomFormat"] == "CycloneDX"
    assert document["metadata"]["component"] == {"type": "application", "name": "autopwn-suite-linux-amd64", "version": "2.7.0"}


def test_a_platform_that_installs_a_conditional_requirement_lists_it(installed):
    installed["colorama"] = "0.4.6"
    names = {component["name"] for component in sbom.build_sbom(REQUIREMENTS, "2.7.0", "windows-amd64")["components"]}
    assert "colorama" in names


def test_components_carry_purls_and_the_interpreter_version(installed):
    components = {c["name"]: c for c in sbom.build_sbom(REQUIREMENTS, "2.7.0", "macos-arm64")["components"]}
    assert components["requests"]["purl"] == "pkg:pypi/requests@2.33.1"
    assert components["pyinstaller"]["purl"] == "pkg:pypi/pyinstaller@6.22.3"
    assert components["cpython"]["version"] == platform.python_version()


def test_a_version_that_differs_from_the_lock_is_an_error(installed):
    installed["requests"] = "2.0.0"
    with pytest.raises(ValueError, match="installed as 2.0.0 but locked as 2.33.1"):
        sbom.build_sbom(REQUIREMENTS, "2.7.0", "linux-amd64")


def test_command_line_writes_a_stable_document(installed, tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text(REQUIREMENTS, encoding="utf-8")
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    for output in (first, second):
        sbom.main(["--version", "2.7.0", "--target", "linux-arm64", "--output", str(output), "--requirements", str(lock)])
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text())["metadata"]["properties"] == [{"name": "build:target", "value": "linux-arm64"}]
