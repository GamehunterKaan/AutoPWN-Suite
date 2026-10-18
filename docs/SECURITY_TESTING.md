# Automated security policy

The maintainer owns triage; an independent human reviews code, dependency,
workflow and exception changes before merge. Run the **Security policy** check
on every PR and main push, without path filters. Require it alongside tests and
CodeQL in branch protection. Run it again on the exact release commit, then scan
both built image architectures before any image push/signing/upload. Scanner
failure, malformed/missing reports or incomplete lockfile coverage fail closed.
There is no automatic merge or publication on a failed security check.

## Software composition analysis (SCA)

OSV-Scanner 2.7.0 queries OSV's known-vulnerability/malicious-package records for
all 35 current locked runtime and development Python dependencies. The inventory
must cover every package/version in `poetry.lock`; new lockfile entries are
included automatically. Only standard PyPI sources are approved. Human review
also checks provenance, unexpected package names, maintainer changes and install
scripts: no scanner proves that an unknown package is benign. The release scan
checks the Python packages actually installed in each Docker image, covering
pip resolution differences from the Poetry environment. Operating-system packages
inherited from the base image are inventoried in the signed SBOM and scan reports but
do not block a release; a known malicious package blocks in any ecosystem.

**Threshold:** every known applicable dependency vulnerability, regardless of
severity or available fix, blocks merge/release until upgraded, removed or
documented as non-exploitable in a reviewed, current OpenVEX statement. Known
malicious distributions (`MAL-` identifiers) always block and cannot be exempted.
Do not install or execute a flagged package to investigate it. Revoke credentials
and investigate prior exposure if malicious code was executed.

Python dependency licenses must resolve to an approved SPDX expression in
`scripts/security_policy.py`. Unknown, missing or other licenses block merge and
release pending replacement or a reviewed policy change with distribution
obligations documented. Four exact-version corrections in
`.security/license-overrides.json` resolve OSV's non-standard labels using
upstream license URLs and SHA-256 digests; these do not waive vulnerabilities.
Retain copyright/license notices, including MPL file-level obligations.

The pinned tools that build the release artifacts (`packaging/requirements-build.txt` for
PyInstaller and `packaging/requirements-publish.txt` for the wheel build) are scanned by the
same OSV-Scanner run and block on any known vulnerability or malicious package; their
licenses are not gated because they are not distributed. The standalone binaries carry
an SBOM each, generated from the build environment (installed runtime packages,
PyInstaller, CPython), which is not a scan of the executable and omits native libraries
copied from the runner. Each binary embeds `LICENSE`, `NOTICE` and the metadata of every
bundled package for attribution; Nmap is not bundled.

The image SBOM also inventories native packages and their license information.
The release manager must review native/base-image license obligations (including
Nmap), retain notices and provide corresponding source/offers where required
before publishing. Python's allowlist does not automatically approve native
redistribution. Neither the scanner nor this policy substitutes for that review.

Triage alerts immediately; target initial assessment within 7 days. Malicious or
actively exploited dependencies require immediate containment, critical/high
vulnerabilities target remediation within 7 days, others within 30 days. These
targets never waive the merge/release gate. Resolve all policy violations before
**every release**, including historical rebuilds. An unavailable fix is not a
non-exploitability justification. Archive reports in Actions (30 days) and review
current database results when cutting a release.

An independently reviewed **authenticity backfill** may add signatures and
assessment metadata to an already published release without rebuilding,
replacing or retagging any software image. Its source checks must pass; its
complete image findings, policy results and SBOMs are published under signed
hashes, explicitly marked as having no security clearance. This operation does
not suppress findings or create a new software release. All new versions and
all rebuilds retain the blocking policy above, including historical rebuilds.
See [Releasing](RELEASING.md#authenticity-backfill-for-an-existing-release).

## Static application security testing (SAST)

Bandit 1.9.4 inspects every tracked non-test Python file, including release
scripts, on every change and release. `--ignore-nosec` prevents inline exclusions
from silently hiding findings. GitHub CodeQL separately analyzes Python,
JavaScript/TypeScript and Actions; retain its required checks.

**Threshold:** Bandit HIGH findings at any confidence block merge/release.
Medium/low results remain visible in retained reports and require triage within
14 days; target medium remediation within 30 days and low within 90 days. Review
CodeQL security alerts with the same high/critical blocking threshold and
medium/low targets. Existing open medium findings remain disclosed in the
[assessment](SECURITY_ASSESSMENT.md) and [advisories](SECURITY_ADVISORIES.md).
Passing automated checks does not remediate those findings or prove safety.

The only SAST suppression mechanism is `.security/sast-exceptions.json`: a
reviewed exact finding fingerprint, source-backed non-exploitability reason and
evidence, with a UTC expiry at most 90 days away. There are currently **none**.
False-positive/non-exploitability decisions require independent human review.
Risk acceptance, age of the finding, convenience and a failing test are not valid
suppression reasons. Resolve expired exceptions and reassess when source,
configuration, dependencies or deployment assumptions change. Do not use broad
rule/path exclusions or change severity merely to pass a check.

## VEX feed and local execution

See [VEX policy](../.security/vex/README.md). Non-exploitability is an evidence
claim about an exact product and component version, not a default for an
uninvestigated advisory. A product's own vulnerabilities remain in the public
advisory channel; VEX augments rather than replaces it.

On a Linux x86-64 machine with Python 3.11+, Git and network access:

```sh
python -m venv .venv-security
. .venv-security/bin/activate
python -m pip install bandit==1.9.4
python scripts/install_security_tools.py --directory /tmp/autopwn-security-tools
python scripts/security_policy.py --repo . --output /tmp/autopwn-security-reports --osv /tmp/autopwn-security-tools/osv-scanner
```

Exit 0 and `no blocking findings` mean the configured thresholds passed. Inspect
`sca.json`, `sast.json` and `policy-result.json`; scanner errors are failures.
The scanner installer verifies pinned upstream binary checksums and does not
execute downloaded install scripts. Run unit tests under
[CONTRIBUTING.md](../.github/CONTRIBUTING.md) as a separate required check.
