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
pip resolution differences from the Poetry environment. That inventory must
name every package `requirements-locked.txt` pins without an environment marker
(the file the image installs from), so a scan that found no Python packages, or
lost one, fails instead of passing on operating-system packages alone.
Operating-system packages inherited from the base image are inventoried in the
signed SBOM and scan reports but do not block a release; a known malicious
package blocks in any ecosystem.

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

Fuzzing: the normal suite runs seeded mutation fuzz tests of the parsers, validators and login
endpoints (`tests/unit/test_fuzz_inputs.py`). In addition, ClusterFuzzLite builds the Atheris harnesses
in `scripts/fuzz/` (Nmap XML parser, dashboard option schema, account validation, update checker input) and fuzzes the code a pull
request changes for a few minutes (`.github/workflows/cflite_pr.yml`, `.clusterfuzzlite/`). A crash or an
undocumented exception fails that job. The fuzz build installs only the hash-pinned `requirements-locked.txt` and uses the
package from the checkout, as the container image does. Seed inputs live in `scripts/fuzz/seeds/`; harness behavior is also
checked in the normal suite (`tests/unit/test_fuzz_harnesses.py`).

The pinned tools that build the release artifacts (`packaging/requirements-build.txt` for
PyInstaller and `packaging/requirements-publish.txt` for the wheel build) are scanned by the
same OSV-Scanner run and block on any known vulnerability or malicious package; their
licenses are not gated because they are not distributed. The standalone binaries carry
an SBOM each, generated from the build environment (installed runtime packages,
PyInstaller, CPython and the python-build-standalone release), which is not a scan of the executable and
omits the native libraries inside the interpreter distribution and the wheels. Every binary is built twice on
its runner (`scripts/build_binary.py --repeat`) and the job fails unless both builds are identical. Each binary embeds `LICENSE`, `NOTICE` and the metadata of every
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
JavaScript/TypeScript and Actions through `codeql.yml`; retain its required checks. CodeQL's
default setup is not used: it never scans a pull request from a fork, so the required checks
could not report on one (see [CodeQL for pull requests from forks](#codeql-for-pull-requests-from-forks)).

**Threshold:** Bandit HIGH findings at any confidence block merge/release.
Medium/low results remain visible in retained reports and require triage within
14 days; target medium remediation within 30 days and low within 90 days. Review
CodeQL security alerts with the same high/critical blocking threshold and
medium/low targets. Medium findings, including those already fixed, remain disclosed in the
[assessment](SECURITY_ASSESSMENT.md) and [advisories](SECURITY_ADVISORIES.md).
Passing automated checks does not remediate findings or prove safety.

The only SAST suppression mechanism is `.security/sast-exceptions.json`: a
reviewed exact finding fingerprint, source-backed non-exploitability reason and
evidence, with a UTC expiry at most 90 days away. There are currently **none**.
False-positive/non-exploitability decisions require independent human review.
Risk acceptance, age of the finding, convenience and a failing test are not valid
suppression reasons. Resolve expired exceptions and reassess when source,
configuration, dependencies or deployment assumptions change. Do not use broad
rule/path exclusions or change severity merely to pass a check.

## Dynamic analysis (OWASP ZAP baseline)

`dynamic-analysis.yml` starts the dashboard from the source under test on loopback
with a throwaway data directory and runs the ZAP baseline scan against it twice:
once without a session (the sign-in surface) and once with the session cookie of the
generated account (the dashboard, its scripts and the read-only API routes). Baseline
mode applies passive rules only and no active attack rules, so the scan complements the
tests and SAST and does not replace them. Its spiders can still submit forms and follow
controls with the session cookie, which is why the scan runs against a throwaway data
directory and why the dashboard's CSRF check, which every non-GET request must pass,
rejects such submissions. Pull
requests and pushes to `main` run it, and `publish-docker.yml` and `publish-pypi.yml`
call it on the release commit, so nothing is pushed or published unless it passed.

Every ZAP alert must be triaged in `.github/zap/rules.tsv`: findings are `FAIL`,
harmless ones are `IGNORE` with a written reason, and an alert with no entry is a
`WARN` that fails the job like any other.

The ZAP image is pinned by digest (`ZAP_IMAGE` in the workflow: the multi-architecture
index digest that `ghcr.io/zaproxy/zaproxy:stable` resolved to), so the same source
gets the same verdict and a new ZAP release cannot change it unreviewed. A pin that
ages can start to raise ZAP's own "ZAP is Out of Date" alert. It has no entry in
`rules.tsv`, so it fails the scan; refresh the pin rather than adding an `IGNORE`
entry, which would let the scanner age unnoticed. To refresh it, resolve the current
index digest with `docker buildx imagetools inspect ghcr.io/zaproxy/zaproxy:stable`,
replace the digest in `ZAP_IMAGE`, run the workflow on the branch and triage any new
alerts in `rules.tsv` before merging. Check the pin before cutting a release after a
long gap, so that the release run is not the first to find a stale scanner.

## VEX feed and local execution

See [VEX policy](../.security/vex/README.md). Non-exploitability is an evidence
claim about an exact product and component version, not a default for an
uninvestigated advisory. A product's own vulnerabilities remain in the public
advisory channel; VEX augments rather than replaces it.

On a Linux x86-64 machine with Python 3.11+, Git and network access:

```sh
python -m venv .venv-security
. .venv-security/bin/activate
python -m pip install --require-hashes --only-binary=:all: --no-deps -r .security/requirements-bandit.txt
python scripts/install_security_tools.py --directory /tmp/autopwn-security-tools
python scripts/security_policy.py --repo . --output /tmp/autopwn-security-reports --osv /tmp/autopwn-security-tools/osv-scanner
```

Exit 0 and `no blocking findings` mean the configured thresholds passed. Inspect
`sca.json`, `sast.json` and `policy-result.json`; scanner errors are failures.
The scanner installer verifies pinned upstream binary checksums and does not
execute downloaded install scripts. Run unit tests under
[CONTRIBUTING.md](../.github/CONTRIBUTING.md) as a separate required check.

## Workflows

Every file in `.github/workflows/` is listed here; a test fails when one is missing
or when this table names a file that does not exist. Third-party actions are pinned
to full commit SHAs, every checkout sets `persist-credentials: false`, and each
workflow declares its permissions at workflow level and a job states its own where it
needs more or less. The third column lists everything beyond read-only contents. The
required status checks are `test`, `Tests (ubuntu-latest)`, `Tests (macos-latest)`,
`Security policy` and `Independent human approval`, plus the CodeQL checks `Analyze (actions)`,
`Analyze (javascript-typescript)`, `Analyze (python)` and `CodeQL`; the workflows behind them have no
`paths:` filter.

| Workflow | Runs on | Permissions beyond read-only contents | What it checks or does |
| --- | --- | --- | --- |
| `poetry-tests.yml` | Pull request and push to `main` | None | Check `test`: lockfile check, Ruff, JavaScript syntax and ESLint, the locked-requirements export, installation of system Nmap and gettext, the translation-catalog drift check, then pytest with 80% branch coverage. |
| `tests.yml` | Pull request and push to `main` and `dev` | None | Checks `Tests (ubuntu-latest)` and `Tests (macos-latest)`: Python 3.10 with `requirements.txt`, an import smoke test and a scan of `127.0.0.1` with Nmap. |
| `codeql.yml` | Pull request and push to `main`, weekly | `security-events: write` in its one job (a pull request run is read-only and does not use it) | Checks `Analyze (actions)`, `Analyze (javascript-typescript)` and `Analyze (python)`: CodeQL with `build-mode: none`, so no code of the pull request runs. A pull request run leaves its SARIF file as an artifact; a push or the weekly run uploads directly. |
| `codeql-upload.yml` | `workflow_run` of `codeql.yml`, from `main` | `security-events: write` in its one job | Uploads a pull request's CodeQL results to code scanning, which produces the `CodeQL` check, including for a fork; checks out no pull request code (see [below](#codeql-for-pull-requests-from-forks)). |
| `install-smoke.yml` | Pull request and push to `main` and `dev` | None | Installs the built wheel into a clean environment and starts it (Ubuntu, macOS and Windows, Python 3.10 and 3.14); archives the commit the way a release does and builds the standalone binaries from that archive through `build-binary.yml`. |
| `build-binary.yml` | Reusable: called by `install-smoke.yml` and `publish-docker.yml` | None | Builds each standalone binary twice on its own runner (Linux amd64 and arm64, Windows amd64, macOS arm64) from the pinned interpreter and hash-pinned requirements, fails unless both builds are identical, smoke-tests it and writes its SBOM. |
| `security.yml` | Pull request and push to `main`; reusable with a release commit | None | Check `Security policy`: `scripts/security_policy.py` (OSV-Scanner SCA of the lockfile and the pinned release build tools, Bandit SAST). The release workflows run it on the exact release commit. |
| `dynamic-analysis.yml` | Pull request and push to `main`, manually; reusable with a release commit | None | OWASP ZAP baseline scan of the running dashboard, unauthenticated and signed in (see [Dynamic analysis](#dynamic-analysis-owasp-zap-baseline)). The release workflows need it before they push or publish anything. |
| `cflite_pr.yml` | Pull requests that change `autopwn_suite/`, `scripts/fuzz/`, `.clusterfuzzlite/`, `requirements-locked.txt` or the workflow itself (a path filter; not a required check) | None (the job token is read-only) | ClusterFuzzLite builds the Atheris harnesses in `scripts/fuzz/` and fuzzes the changed code for 180 seconds. |
| `scorecard.yml` | Weekly, on push to `main` and on branch-protection changes | `security-events: write` and `id-token: write` in its one job | OpenSSF Scorecard analysis; uploads the SARIF results to code scanning and publishes them to the OpenSSF API for the badge. It gates nothing and stores no secret. |
| `human-review.yml` | Pull request | `pull-requests: read` | Check `Independent human approval`: a human other than the author must approve the current revision. |
| `human-review-events.yml` | Pull request review submitted or dismissed | None (`permissions: {}`) | Credential-free notification that a review changed. |
| `human-review-refresh.yml` | `workflow_run` of the notification, from `main` | `actions: write` and `pull-requests: read` in its one job | Reruns the approval check for the pull request's current revision; never checks out pull request code. |
| `publish-docker.yml` | Published release; manually from `main` to recover one | `id-token: write` (sign job), `contents: write` (publish job), Docker Hub secrets (push and sign jobs) | Validates the tag, runs the security and dynamic-analysis workflows and the binary builds, builds and scans each image architecture, pushes, signs with Sigstore (the image signature check is retried for about two minutes in case Docker Hub lists the new signature late; the signing runs once) and uploads the release assets. See [Releasing](RELEASING.md). |
| `publish-pypi.yml` | Published release; manually from `main`, which runs the gates and the build but cannot publish (the `pypi` environment admits only `v*` tags) | `id-token: write` in the publish job, which runs in the `pypi` environment | The same validation and gates, two identical builds of the wheel and source distribution, a clean-install smoke test, then PyPI trusted publishing with attestations. See [Releasing](RELEASING.md). |
| `backfill-release-signatures.yml` | Manually from `main` | `id-token: write` (sign job), `contents: write` (publish job), Docker Hub secrets (sign job) | Signs an existing release and its original image digest without rebuilding anything (the image signature check is retried for about two minutes, as in `publish-docker.yml`). See [Releasing](RELEASING.md#authenticity-backfill-for-an-existing-release). |

### CodeQL for pull requests from forks

GitHub's default setup for code scanning documents that it scans pull requests "excluding pull
requests from forks", so with it a fork's pull request never gets the required `Analyze (...)` and
`CodeQL` checks. `codeql.yml` and `codeql-upload.yml` replace it and keep the same job names and
categories (`/language:<name>`), so the required checks and the alert history are unchanged.

1. `codeql.yml` analyzes the merge of the pull request with `main`. A fork's token is read-only, so
   the run only analyzes (`upload: never`), writes the post-processed SARIF file and the analyzed commit
   to an artifact per language and finishes.
2. `codeql-upload.yml` starts from `main` when that run completes. For each language it downloads the
   artifact, accepts exactly the two expected files, requires a SARIF 2.1.0 log of the CodeQL tool with
   that language's category, finds the pull request through the GitHub API (open, targets `main`, same
   head commit and branch, and a test merge commit equal to the analyzed commit) and uploads the file
   to `refs/pull/<number>/merge`. The number, the commit and the category come from the API and
   fixed values, never from the artifact. It checks out no pull request code, and a result for a
   pull request that has since changed is not uploaded.

The upload job holds `security-events: write`, so it treats the artifact as data and nothing else. A pull
request can change `codeql.yml` itself and so produce a clean-looking file: as for every other check,
the independent human review of the change is the control. `tests/unit/test_codeql_workflows.py` runs
the handler's script with GitHub API responses and checks the names, pins and permissions.
