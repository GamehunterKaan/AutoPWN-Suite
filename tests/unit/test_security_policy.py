# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Security checks must reject findings, missing coverage and broad suppressions."""

import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "security_policy", Path(__file__).resolve().parents[2] / "scripts/security_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "vex").mkdir()
    (tmp_path / "vex/index.json").write_text('{"schema_version":1,"documents":[]}')
    (tmp_path / "license-overrides.json").write_text('{}')
    (tmp_path / "sast-exceptions.json").write_text('[]')
    return tmp_path


def report(vulns=(), licenses=("MIT",)):
    return {"results": [{"packages": [{"package": {
        "name": "example", "version": "1.0", "ecosystem": "PyPI", "purl": "pkg:pypi/example@1.0",
    }, "licenses": list(licenses), "vulnerabilities": [{"id": v} for v in vulns]}]}]}


def write_vex(root, *, version="2.6.0", component="pkg:pypi/example@1.0", timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    (root / "vex/index.json").write_text('{"schema_version":1,"documents":["review.openvex.json"]}')
    (root / "vex/review.openvex.json").write_text(json.dumps({
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/vex/1",
        "author": "test", "timestamp": timestamp, "version": 1, "statements": [{
            "vulnerability": {"name": "CVE-TEST-1"}, "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": "Synthetic test evidence only.", "status_notes": "tests/test_case.py",
            "products": [{"@id": f"pkg:github/GamehunterKaan/AutoPWN-Suite@{version}",
                          "subcomponents": [{"@id": component}]}],
        }],
    }))


def test_sca_blocks_all_known_vulnerabilities_and_malware(root):
    violations, count = policy.evaluate_sca(report(["CVE-TEST-1", "MAL-TEST-1"]), "2.6.0", root)
    assert count == 1 and len(violations) == 2


def os_report(vulns=(), ecosystem="Debian:13"):
    return {"results": [{"packages": [{"package": {
        "name": "libc6", "version": "2.41", "ecosystem": ecosystem, "purl": "pkg:deb/debian/libc6@2.41",
    }, "vulnerabilities": [{"id": v} for v in vulns]}]}]}


def test_only_python_requirements_block_on_known_vulnerabilities(root):
    # Operating-system packages from the base image are inventoried but do not block.
    assert policy.evaluate_sca(os_report(["DEBIAN-CVE-TEST-1"]), "2.6.0", root) == ([], 1)
    # The same finding in a Python requirement (including one installed in an image) blocks.
    combined = {"results": os_report(["DEBIAN-CVE-TEST-1"])["results"] + report(["CVE-TEST-1"])["results"]}
    violations, count = policy.evaluate_sca(combined, "2.6.0", root)
    assert count == 2 and violations == ["pkg:pypi/example@1.0: CVE-TEST-1"]


def test_known_malware_blocks_in_any_ecosystem(root):
    violations, _ = policy.evaluate_sca(os_report(["MAL-TEST-1"]), "2.6.0", root)
    assert violations == ["pkg:deb/debian/libc6@2.41: MAL-TEST-1"]


def test_clean_inventory_passes_and_missing_package_fails(root):
    assert policy.evaluate_sca(report(), "2.6.0", root, expected={("example", "1.0")}) == ([], 1)
    with pytest.raises(ValueError, match="omitted"):
        policy.evaluate_sca(report(), "2.6.0", root, expected={("missing", "1.0")})
    with pytest.raises(ValueError, match="no package"):
        policy.evaluate_sca({"results": []}, "2.6.0", root)


@pytest.mark.parametrize("licenses", [[], ["non-standard"], ["GPL-3.0-only"], ["MIT", "UNKNOWN"]])
def test_unknown_or_unapproved_python_license_blocks(root, licenses):
    assert policy.evaluate_sca(report(licenses=licenses), "2.6.0", root)[0]


def test_release_build_tools_are_pinned_and_scanned_by_osv_name():
    root = Path(__file__).resolve().parents[2]
    names = {name for name, _ in policy.build_tool_pins(root)}
    assert {"pyinstaller", "poetry-core", "bandit"} <= names
    assert all(name == name.lower() and "_" not in name for name in names)


def test_build_tool_vulnerabilities_block_but_their_licenses_do_not(root):
    # PyInstaller is GPL with a bootloader exception and is never shipped, so only vulnerabilities gate it.
    gpl = report(licenses=("GPL-2.0-or-later",))
    assert policy.evaluate_sca(gpl, "2.6.0", root, licenses=False)[0] == []
    assert policy.evaluate_sca(report(["CVE-TEST-1"], licenses=("GPL-2.0-or-later",)), "2.6.0", root, licenses=False)[0]


def test_a_scan_that_misses_a_pinned_build_tool_is_rejected(root):
    with pytest.raises(ValueError, match="omitted locked packages"):
        policy.evaluate_sca(report(), "2.6.0", root, expected={("example", "1.0"), ("pyinstaller", "6.22.3")}, licenses=False)


def test_packaging_requirement_files_are_hash_pinned_and_match_their_inputs():
    root = Path(__file__).resolve().parents[2]
    for stem in ("packaging/requirements-build", "packaging/requirements-publish", ".security/requirements-bandit"):
        inputs = (root / f"{stem}.in").read_text(encoding="utf-8")
        compiled = (root / f"{stem}.txt").read_text(encoding="utf-8")
        wanted = dict(re.findall(r"^([A-Za-z0-9._-]+)==(\S+)$", inputs, re.MULTILINE))
        pinned = {name.lower(): version for name, version in policy.re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", compiled, re.MULTILINE)}
        assert wanted and all(pinned.get(name.lower()) == version for name, version in wanted.items())
        blocks = re.split(r"\n(?=[A-Za-z0-9])", compiled)
        assert all("--hash=sha256:" in block for block in blocks if re.match(r"[A-Za-z0-9]+==", block))


def test_poetry_core_pin_matches_the_release_toolchain():
    root = Path(__file__).resolve().parents[2]
    backend = re.search(r'^requires\s*=\s*\["poetry-core==([^"]+)"\]', (root / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)
    assert backend, "[build-system] must pin poetry-core exactly so wheels do not depend on the latest release"
    assert ("poetry-core", backend[1]) in policy.build_tool_pins(root)


def test_vex_exemption_binds_product_component_and_version(root):
    write_vex(root)
    assert not policy.evaluate_sca(report(["CVE-TEST-1"]), "2.6.0", root)[0]
    assert policy.evaluate_sca(report(["CVE-TEST-1"]), "2.6.1", root)[0]
    write_vex(root, component="pkg:pypi/example@2.0")
    assert policy.evaluate_sca(report(["CVE-TEST-1"]), "2.6.0", root)[0]


def test_vex_cannot_suppress_malware_or_expired_assessments(root):
    write_vex(root)
    data = json.loads((root / "vex/review.openvex.json").read_text())
    data["statements"][0]["vulnerability"]["aliases"] = ["MAL-TEST-1"]
    (root / "vex/review.openvex.json").write_text(json.dumps(data))
    assert policy.evaluate_sca(report(["MAL-TEST-1"]), "2.6.0", root)[0]
    write_vex(root, timestamp="2000-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="expired"):
        policy.evaluate_sca(report(), "2.6.0", root)


def test_vex_paths_cannot_escape_feed_directory(root):
    (root / "vex/index.json").write_text('{"schema_version":1,"documents":["../other.openvex.json"]}')
    with pytest.raises(ValueError, match="document name"):
        policy.vex_exceptions("2.6.0", root)


def test_sast_high_severity_blocks_and_scan_errors_fail_closed(root):
    finding = {"filename": "source.py", "line_number": 1, "code": "1 bad()",
               "test_id": "B000", "issue_severity": "HIGH"}
    assert policy.evaluate_sast({"errors": [], "metrics": {"_totals": {}}, "results": [finding]}, root)
    finding["issue_severity"] = "MEDIUM"
    assert not policy.evaluate_sast({"errors": [], "metrics": {"_totals": {}}, "results": [finding]}, root)
    with pytest.raises(ValueError, match="complete"):
        policy.evaluate_sast({"errors": ["parse failure"], "metrics": {}, "results": []}, root)


def test_missing_report_or_failed_scanner_cannot_pass(tmp_path, monkeypatch):
    class Result:
        returncode = 2
    monkeypatch.setattr(policy.subprocess, "run", lambda *a, **kw: Result())
    with pytest.raises(ValueError, match="Scanner failed"):
        policy.run_scanner(["scanner"], tmp_path / "missing.json")
