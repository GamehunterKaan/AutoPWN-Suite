# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Fail closed on dependency and static-analysis policy violations.

Scanners run without installing application dependencies or executing project code.
The JSON reports are retained even when a finding blocks the change or release.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tomllib

POLICY_ROOT = Path(__file__).resolve().parents[1] / ".security"
ALLOWED_LICENSES = {
    "Apache-2.0", "Apache-2.0 OR BSD-2-Clause", "Apache-2.0 OR BSD-3-Clause",
    "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MIT-0", "MPL-2.0", "PSF-2.0",
    "0BSD", "Unlicense",
}
JUSTIFICATIONS = {
    "component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def vex_exceptions(version, root=POLICY_ROOT, now=None):
    """Only recent, version/component-specific not_affected statements suppress."""
    now = now or datetime.now(timezone.utc)
    result = set()
    index = read_json(root / "vex/index.json")
    if index.get("schema_version") != 1 or not isinstance(index.get("documents"), list):
        raise ValueError("Invalid VEX feed index")
    product_id = f"pkg:github/GamehunterKaan/AutoPWN-Suite@{version}"
    for name in index["documents"]:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*\.openvex\.json", name):
            raise ValueError("Invalid VEX document name")
        doc = read_json(root / "vex" / name)
        if (doc.get("@context") != "https://openvex.dev/ns/v0.2.0" or not doc.get("@id")
                or not doc.get("author") or not isinstance(doc.get("version"), int)
                or doc["version"] < 1 or not doc.get("statements")):
            raise ValueError("Invalid OpenVEX document")
        for statement in doc["statements"]:
            if statement.get("status") != "not_affected":
                continue
            if (statement.get("justification") not in JUSTIFICATIONS
                    or not statement.get("impact_statement", "").strip()
                    or not statement.get("status_notes", "").strip()):
                raise ValueError("Non-exploitability requires justification and evidence")
            assessed = datetime.fromisoformat(statement.get("timestamp", doc["timestamp"]).replace("Z", "+00:00"))
            if assessed.tzinfo is None or assessed > now or now - assessed > timedelta(days=90):
                raise ValueError("VEX assessment expired or has an invalid timestamp")
            vuln = statement["vulnerability"]
            ids = [vuln["name"], *vuln.get("aliases", [])]
            for product in statement.get("products", []):
                if product.get("@id") == product_id:
                    for component in product.get("subcomponents", []):
                        purl = component.get("@id", "")
                        if not purl.startswith("pkg:") or "@" not in purl:
                            raise ValueError("VEX component needs an exact versioned purl")
                        result.update((identifier, purl) for identifier in ids)
    return result


def evaluate_sca(report, version, root=POLICY_ROOT, expected=None, licenses=True):
    exemptions = vex_exceptions(version, root)
    overrides = read_json(root / "license-overrides.json")
    packages = [p for source in report["results"] for p in source["packages"]]
    if not packages:
        raise ValueError("SCA produced no package inventory")
    found = set()
    violations = []
    for item in packages:
        package = item["package"]
        found.add((package["name"], package["version"]))
        purl = package.get("purl", "")
        for vuln in item.get("vulnerabilities", []):
            identifiers = [vuln["id"], *vuln.get("aliases", [])]
            # A known malicious distribution is never exempted as unreachable.
            malware = any(identifier.startswith("MAL-") for identifier in identifiers)
            # The project's dependencies are its Python requirements. Operating-system packages
            # inherited from the base image stay in the inventory and reports but do not block;
            # a known malicious package blocks in any ecosystem.
            if package.get("ecosystem") != "PyPI" and not malware:
                continue
            if malware or not any((identifier, purl) in exemptions for identifier in identifiers):
                violations.append(f"{purl or package['name']}: {vuln['id']}")
        if licenses and package.get("ecosystem") == "PyPI":
            detected = item.get("licenses", [])
            if detected == ["non-standard"] and purl in overrides:
                correction = overrides[purl]
                if not correction.get("evidence", "").startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", correction.get("sha256", "")):
                    raise ValueError("License correction needs upstream evidence and digest")
                detected = [correction["license"]]
            if not detected or any(license_id not in ALLOWED_LICENSES for license_id in detected):
                violations.append(f"{purl}: unapproved/unknown license {detected}")
    if expected is not None and not expected.issubset(found):
        raise ValueError(f"SCA omitted locked packages: {sorted(expected - found)}")
    return violations, len(packages)


def sast_fingerprint(item):
    return hashlib.sha256(json.dumps({
        "path": Path(item["filename"]).as_posix().removeprefix("./"),
        "rule": item["test_id"], "code": item["code"],
    }, sort_keys=True).encode()).hexdigest()


def evaluate_sast(report, root=POLICY_ROOT, now=None):
    if report.get("errors") or not report.get("metrics") or "results" not in report:
        raise ValueError("SAST did not complete source analysis")
    now = now or datetime.now(timezone.utc)
    exceptions = {}
    for entry in read_json(root / "sast-exceptions.json"):
        expiry = datetime.fromisoformat(entry["expires"].replace("Z", "+00:00"))
        if (not entry.get("evidence") or not entry.get("reason") or expiry.tzinfo is None
                or expiry <= now or expiry - now > timedelta(days=90)):
            raise ValueError("SAST exception requires current evidence and at most 90 days")
        exceptions[entry["fingerprint"]] = entry
    return [f"{item['filename']}:{item['line_number']} {item['test_id']}"
            for item in report["results"] if item["issue_severity"] == "HIGH"
            and sast_fingerprint(item) not in exceptions]


def run_scanner(command, output):
    result = subprocess.run(command, check=False)
    if result.returncode not in (0, 1) or not output.is_file():
        raise ValueError(f"Scanner failed: {command[0]} (exit {result.returncode})")
    return read_json(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--osv", default="osv-scanner")
    parser.add_argument("--image-archive", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    version = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["poetry"]["version"]
    report_path = args.output / "sca.json"
    command = [args.osv, "scan", "image" if args.image_archive else "source",
               "--all-packages", "--all-vulns", "--format=json", f"--output-file={report_path.resolve()}",
               "--no-call-analysis=go", "--no-call-analysis=rust"]
    expected = None
    if args.image_archive:
        command += ["--licenses", "--archive", str(args.image_archive.resolve())]
    else:
        command += ["--licenses", f"--lockfile={repo / 'poetry.lock'}"]
        locked = tomllib.loads((repo / "poetry.lock").read_text(encoding="utf-8"))["package"]
        if any(p.get("source") for p in locked):
            raise ValueError("Only standard PyPI lockfile dependencies are approved")
        expected = {(p["name"], p["version"]) for p in locked}
    report = run_scanner(command, report_path)
    violations, count = evaluate_sca(report, version, expected=expected)
    if not args.image_archive:
        tracked = subprocess.check_output(["git", "-C", str(repo), "ls-files", "--", "*.py"], text=True).splitlines()
        sources = [str(repo / p) for p in tracked if not p.startswith("tests/")]
        if not sources:
            raise ValueError("No Python source selected")
        report_path = args.output / "sast.json"
        report = run_scanner([sys.executable, "-m", "bandit", "--ignore-nosec", "-f", "json",
                              "-o", str(report_path.resolve()), *sources], report_path)
        for item in report["results"]:
            item["filename"] = Path(item["filename"]).relative_to(repo).as_posix()
        violations += evaluate_sast(report)
    (args.output / "policy-result.json").write_text(json.dumps({
        "version": version, "packages": count, "violations": violations,
    }, indent=2) + "\n", encoding="utf-8")
    if violations:
        raise ValueError("Security policy violations:\n" + "\n".join(violations))
    print(f"Security policy passed: {count} packages; no blocking findings")


if __name__ == "__main__":
    main()
