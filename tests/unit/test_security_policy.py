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


def test_image_scan_must_inventory_the_python_runtime_packages(root):
    """An image inventory of operating-system packages alone (or missing a pinned Python package) cannot pass."""
    assert policy.evaluate_sca(report(), "2.6.0", root, expected_names={"example"}) == ([], 1)
    with pytest.raises(ValueError, match="omitted installed Python packages"):
        policy.evaluate_sca(os_report(), "2.6.0", root, expected_names={"example"})
    with pytest.raises(ValueError, match="omitted installed Python packages"):
        policy.evaluate_sca(report(), "2.6.0", root, expected_names={"example", "flask"})
    spelled = report()
    spelled["results"][0]["packages"][0]["package"]["name"] = "Example_Pkg"
    assert policy.evaluate_sca(spelled, "2.6.0", root, expected_names={"example-pkg"}) == ([], 1)


def test_image_runtime_packages_are_the_unconditional_locked_pins(tmp_path):
    (tmp_path / "requirements-locked.txt").write_text(
        "# Generated\nFlask-Cors==6.0.1 \\\n    --hash=sha256:aa\n"
        'cffi==2.1.1 ; platform_python_implementation != "PyPy" \\\n    --hash=sha256:bb\n'
        'colorama==0.4.6 ; platform_system == "Windows" \\\n    --hash=sha256:cc\nMarkupSafe==3.0.2\n')
    assert policy.image_runtime_packages(tmp_path) == {"flask-cors", "markupsafe"}
    with pytest.raises(ValueError, match="requirements-locked"):
        policy.image_runtime_packages(tmp_path / "missing")
    real = policy.image_runtime_packages(Path(__file__).resolve().parents[2])
    assert {"flask", "requests", "rich", "beautifulsoup4"} <= real and not {"cffi", "colorama"} & real


def run_image_policy(tmp_path, monkeypatch, scanned):
    """Run main() in image mode against this repository with a fake scanner that returns `scanned`."""
    monkeypatch.setattr(policy, "run_scanner", lambda command, output: scanned)
    monkeypatch.setattr(policy.sys, "argv", ["security_policy.py", "--repo", str(Path(__file__).resolve().parents[2]),
                                             "--output", str(tmp_path / "reports"), "--image-archive", str(tmp_path / "image.tar")])
    policy.main()
    return json.loads((tmp_path / "reports/policy-result.json").read_text())


def test_image_policy_fails_when_the_scan_found_no_python_packages(tmp_path, monkeypatch):
    real = policy.image_runtime_packages(Path(__file__).resolve().parents[2])
    complete = {"results": [{"packages": [{"package": {"name": name, "version": "1", "ecosystem": "PyPI", "purl": f"pkg:pypi/{name}@1"},
                                           "licenses": ["MIT"]} for name in sorted(real)]}]}
    assert run_image_policy(tmp_path, monkeypatch, complete)["violations"] == []
    with pytest.raises(ValueError, match="omitted installed Python packages"):
        run_image_policy(tmp_path, monkeypatch, os_report())


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


def test_a_tag_without_the_build_requirement_files_is_refused_with_a_clear_message(tmp_path, monkeypatch):
    """Dispatching publish-docker or the backfill for a tag before v2.7.0 must say why it stops."""
    with pytest.raises(ValueError, match="before v2.7.0"):
        policy.build_tool_pins(tmp_path)
    repo = tmp_path / "v2.6.1"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('[tool.poetry]\nversion = "2.6.1"\n')
    (repo / "poetry.lock").write_text('[[package]]\nname = "example"\nversion = "1.0"\n')
    scans = []
    monkeypatch.setattr(policy, "run_scanner", lambda command, output: scans.append(command) or report())
    monkeypatch.setattr(policy.sys, "argv", ["security_policy.py", "--repo", str(repo), "--output", str(tmp_path / "reports")])
    with pytest.raises(ValueError, match="before v2.7.0"):
        policy.main()
    # Only the source scan ran: the build tool scan was never started against missing files.
    assert len(scans) == 1


def test_security_testing_doc_lists_every_workflow_and_only_existing_ones():
    """AGENTS.md: a new or changed workflow is documented in docs/SECURITY_TESTING.md in the same change."""
    project = Path(__file__).resolve().parents[2]
    document = (project / "docs/SECURITY_TESTING.md").read_text(encoding="utf-8")
    workflows = {path.name for path in (project / ".github/workflows").glob("*.yml")}
    assert workflows
    assert not sorted(name for name in workflows if f"`{name}`" not in document)
    assert set(re.findall(r"`([A-Za-z0-9_-]+\.yml)`", document)) <= workflows


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
