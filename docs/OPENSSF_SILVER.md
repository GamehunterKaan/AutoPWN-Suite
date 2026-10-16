# OpenSSF Best Practices: Silver preparation

Prepared 2026-10-16 for project 15518
(<https://www.bestpractices.dev/en/projects/15518/silver>). This is the metal-series
Silver checklist, separate from the OpenSSF Baseline levels. It records proposed
answers with evidence and lists what only the maintainer can complete. **No answer
has been submitted automatically.**

Silver includes every Passing criterion, so the
[Passing preparation](OPENSSF_PASSING.md) must be completed first
(`achieve_passing`).

## How to read this document

- **Met** — current repository content supports the answer.
- **Met after release** — true in the repository but not in a published release;
  answer once the next release ships, or cite the main-branch file.
- **Maintainer action** — a human, account or organizational step is required; the
  repository cannot establish it.
- **Unmet (justified)** — a SHOULD/SUGGESTED criterion that the project does not meet;
  the justification is honest and may be entered as the answer text.
- **N/A** — criterion does not apply; the stated condition must hold.

Evidence links use the `main` branch, so they only work after these changes are
merged. Optional criteria are never silently promoted to mandatory ones, and no MUST
criterion is waived.

## Readiness summary

Mandatory (MUST) criteria that are **not yet fully closed**:

1. **`achieve_passing`** — the Passing answers have no pending item
   ([OPENSSF_PASSING.md](OPENSSF_PASSING.md)), but they still have to be entered and the badge reach 100%.
2. **`access_continuity`** — the owner attests a GitHub successor arrangement is in place. That covers
   issues and accepting changes. **Releasing container images also depends on Docker Hub**, and no
   Docker Hub or DNS arrangement is recorded ([CONTINUITY.md](CONTINUITY.md)). Do not answer Met for the
   whole criterion until either that is arranged or the owner is comfortable that a source-only release
   (GitHub, Sigstore keyless) counts as "release versions of software" for this project.
3. **`dependency_monitoring`** — monitoring is active and every image advisory has now been triaged
   ([IMAGE_ADVISORY_TRIAGE.md](IMAGE_ADVISORY_TRIAGE.md)): all 80 are Debian OS packages, none in a Python
   dependency. 42 are shown not installed or not executed by the application (tier A, candidates for reviewed
   VEX). **38 are linked into Nmap or Python and remain open (tier B)**, 13 of them rated `unimportant` or
   resolved by Debian. The criterion asks to "fix exploitable vulnerabilities or verify them as unexploitable",
   so a strict reading is not satisfied until tier B is verified, fixed or reduced.
4. **Release.** Login, TLS verification by default and loopback binding satisfy `implement_secure_design`,
   `crypto_certificate_verification`, `crypto_verification_private` and `crypto_credential_agility` only once
   a release containing them exists. **A new release will fail the project's own image-scan gate** until the
   findings above are fixed or covered by reviewed OpenVEX statements (see the triage document).

Resolved since the first draft: `regression_tests_added50` (see [REGRESSION_LEDGER.md](REGRESSION_LEDGER.md):
5 of 5 defect fixes in the window added tests) and `vulnerability_report_credit` (N/A, maintainer decision).

Everything else below is supported by repository content, with the exceptions called out in the table.

## Verification performed locally

Run on 2026-10-16 against the working tree (not CI):

- Python tests, Ruff (`E,W,F,B,I`) and ESLint: see "Latest local results" at the end.
- A real `docker build` of the pinned, hash-locked image completed and two builds
  using `SOURCE_DATE_EPOCH` and `rewrite-timestamp` produced identical image tarballs
  (amd64 only; arm64, other machines and other days were not tested).
- The installer and uninstaller were exercised with `DESTDIR`, `PREFIX`, `BINDIR`
  and `APPDIR` in a Linux (WSL) environment.
- A live smoke test of first-launch login, password change and `--web-reset-account`.

## Proposed answers

Base URL for evidence: <https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/>.

### Basics

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `achieve_passing` | MUST | **Maintainer action** | Passing badge must be at 100% first. | [OPENSSF_PASSING.md](OPENSSF_PASSING.md) |
| `contribution_requirements` | MUST | **Met** | Contribution instructions name required tests, documentation, DCO sign-off, legal rights and the enforced [coding standards](CODING_STANDARDS.md). | `.github/CONTRIBUTING.md` |
| `dco` | SHOULD | **Met** | Contributors certify the Developer Certificate of Origin with `Signed-off-by` (`git commit -s`). Enforcement is by review; no automated check exists. | `.github/CONTRIBUTING.md` |
| `governance` | MUST | **Met** | Decision-making and roles are documented. | `GOVERNANCE.md` |
| `code_of_conduct` | MUST | **Met** | Contributor Covenant in a standard location. | `.github/CODE_OF_CONDUCT.md` |
| `roles_responsibilities` | MUST | **Met** | Maintainer, release manager, owner and security-contact roles and their holders are public. | `GOVERNANCE.md` |
| `access_continuity` | MUST | **Maintainer action** | GitHub successor arrangement attested by the owner (issues and change acceptance). Container releases depend on Docker Hub, and no Docker Hub or DNS arrangement is recorded; answer Met only after that gap is closed or consciously accepted. | `docs/CONTINUITY.md` |
| `bus_factor` | SHOULD | **Unmet (justified)** | Bus factor is 1 today; the continuity plan states what is needed to reach 2. | `docs/CONTINUITY.md` |
| `documentation_roadmap` | MUST | **Met** | Twelve-month roadmap with intended work and explicit non-goals. | `docs/ROADMAP.md` |
| `documentation_architecture` | MUST | **Met** | Architecture, actors, components and data flows documented. | `docs/ARCHITECTURE.md` |
| `documentation_security` | MUST | **Met** | What users can and cannot expect for security is documented. | `SECURITY.md`, `docs/ASSURANCE_CASE.md` |
| `documentation_quick_start` | MUST | **Met** | README quick start for source and container use. | `README.md` |
| `documentation_current` | MUST | **Met** | Documentation updated for login, TLS defaults, credential files and build changes; keep it in sync at each release. | `CHANGELOG.md`, `docs/` |
| `documentation_achievements` | MUST | **Met** | README links the Best Practices badge and project health; add the Passing and Silver badge links within 48 hours of attainment. | `README.md` |
| `accessibility_best_practices` | SHOULD | **Unmet (justified)** | Source-level review found gaps (custom tabs not keyboard-operable, unlabeled form fields, low-contrast text, no live regions); they are listed with planned fixes. No conformance claim is made. | `docs/ACCESSIBILITY.md` |
| `internationalization` | SHOULD | **Unmet (justified)** | English-only; strings are hard-coded. A staged plan and contributor rules exist. | `docs/INTERNATIONALIZATION.md` |
| `sites_password_security` | MUST | **N/A** | The project's websites, repository and download locations are hosted by GitHub and Docker Hub and store no project-managed passwords. (The scanner's own dashboard stores a scrypt-hashed password but is software the project ships, not a project site.) | `modules/web_auth.py` |

### Change control

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `maintenance_or_update` | MUST | **Met** | The latest stable release is supported and upgrade paths are documented. | `SUPPORT.md`, `CHANGELOG.md` |

### Reporting

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `report_tracker` | MUST | **Met** | GitHub Issues track individual issues. | [Issues](https://github.com/GamehunterKaan/AutoPWN-Suite/issues) |
| `vulnerability_report_credit` | MUST | **N/A** | The maintainer confirmed that no vulnerability report was resolved in the last 12 months. The repository's private and published advisory lists are empty, and Dependabot reports no alerts. | `SECURITY.md` |
| `vulnerability_response_process` | MUST | **Met** | Documented acknowledgement, assessment, update, fix and disclosure process with time targets. | `SECURITY.md` |

### Quality

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `coding_standards` | MUST | **Met** | PEP 8 (Ruff-enforced) for Python and an explicit ESLint rule set for the dashboard JavaScript; contributions must comply. | `docs/CODING_STANDARDS.md`, `pyproject.toml`, `eslint.config.mjs` |
| `coding_standards_enforced` | MUST | **Met** | Ruff and ESLint run in the required `poetry-tests` job. | `.github/workflows/poetry-tests.yml` |
| `build_standard_variables` | MUST | **N/A** | The project builds no native binaries; it is Python and JavaScript. | `docs/BUILDING.md` |
| `build_preserve_debug` | SHOULD | **Met** | Source distributions keep readable source; nothing is stripped. | `docs/BUILDING.md` |
| `build_non_recursive` | MUST | **Met** | Poetry packaging has no recursive cross-dependent build hierarchy. | `pyproject.toml` |
| `build_repeatable` | MUST | **Met, with limits** | The container build pins the base image digest, a dated Debian snapshot and hash-locked Python wheels, and sets `SOURCE_DATE_EPOCH`; two local builds produced identical image tarballs. Verified on amd64 only; the Python source itself is interpreted. | `Dockerfile`, `requirements-locked.txt`, `docs/BUILDING.md` |
| `installation_common` | MUST | **Met** | Standard Python package, virtual-environment and container installation with documented uninstall. | `docs/BUILDING.md`, `install.sh`, `uninstall.sh` |
| `installation_standard_variables` | MUST | **Met** | Installer and uninstaller honor `DESTDIR`, `PREFIX`, `BINDIR` and `APPDIR`. | `install.sh`, `uninstall.sh`, `tests/unit/test_install_scripts.py` |
| `installation_development_quick` | MUST | **Met** | `poetry install` provides the application, tests and tools. | `docs/BUILDING.md` |
| `external_dependencies` | MUST | **Met** | Machine-readable manifest, lockfile and hash-locked export. | `pyproject.toml`, `poetry.lock`, `requirements-locked.txt` |
| `dependency_monitoring` | MUST | **Met, with limits (maintainer judgment)** | OSV-Scanner runs on every change, GitHub Dependabot alerts are enabled and report none, and all 80 image advisories are triaged. None is in a Python dependency; 42 are not installed or not executed by the application; 38 remain open in Nmap/Python-linked libraries, 13 of them vendor-rated unimportant or resolved. State these limits in the answer text. | `docs/IMAGE_ADVISORY_TRIAGE.md`, `.github/workflows/security.yml` |
| `updateable_reused_components` | MUST | **Met** | Dependencies come from standard package managers with a lockfile and SBOMs. | `docs/DEPENDENCIES.md` |
| `interfaces_current` | SHOULD | **Met, with limits** | Project-originated deprecation warnings fail the test suite; no separate API-currentness review of all supported Python versions was done. | `pyproject.toml` (`filterwarnings`) |
| `automated_integration_testing` | MUST | **Met** | Tests run on every push and pull request and publish pass/fail results. | `.github/workflows/poetry-tests.yml` |
| `regression_tests_added50` | MUST | **Met** | All 5 product-defect fixes in the last six months (100%) changed automated tests in the same commit; the ledger shows the method and limits. | `docs/REGRESSION_LEDGER.md` |
| `test_statement_coverage80` | MUST | **Met** | Measured Python statement coverage is above 80% (see results below); the suite fails below 80%. JavaScript coverage is not measured. | `pyproject.toml` |
| `test_policy_mandated` | MUST | **Met** | Written policy requires tests for major new functionality and bug fixes. | `.github/CONTRIBUTING.md` |
| `tests_documented_added` | MUST | **Met** | The policy is in the change-proposal instructions. | `.github/CONTRIBUTING.md` |
| `warnings_strict` | MUST | **Met** | Ruff `E,W,F,B,I`, ESLint, `node --check`, and warnings from project code are errors in tests. | `docs/CODING_STANDARDS.md` |

### Security

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `implement_secure_design` | MUST | **Met after release** | Fail-safe defaults (loopback, login, verified TLS), complete mediation and allowlist validation are implemented and argued. | `docs/ASSURANCE_CASE.md` |
| `crypto_weaknesses` | MUST | **Met** | Mechanisms delegate to standard TLS, scrypt and SHA-256/Sigstore; legacy-protocol probing is diagnostic, not a security mechanism. | `modules/web_auth.py`, `docs/OPENSSF_PASSING.md` |
| `crypto_algorithm_agility` | SHOULD | **Unmet (justified)** | Password hashing parameters are embedded in the stored hash, and TLS algorithms are governed by the platform's OpenSSL; there is no operator switch between algorithm families. | `modules/web_auth.py` |
| `crypto_credential_agility` | MUST | **Met after release** | The dashboard account is a separate file, and API keys, SMTP passwords and webhook URLs can come from separate owner-managed files replaced without code changes. | `modules/credential_files.py`, `README.md` |
| `crypto_used_network` | SHOULD | **Met** | Provider, SMTP and web-scan traffic verify TLS by default; the dashboard is loopback-only by default and remote access requires HTTPS. Scanning plain-HTTP targets is scanner functionality the operator selects. | `docs/ASSURANCE_CASE.md` |
| `crypto_tls12` | SHOULD | **Met** | The supported Python TLS stack negotiates TLS 1.2 or later by default. | `docs/OPENSSF_PASSING.md` |
| `crypto_certificate_verification` | MUST | **Met after release** | Web scans, replay and SMTP verify certificates by default; opting out is explicit (`--insecure-tls`) and recorded. | `modules/web/http.py`, `tests/unit/test_web_transport_security.py` |
| `crypto_verification_private` | MUST | **Met after release** | Diagnostic requests carry no ambient or operator credentials, and verification occurs before any request is sent. | `modules/web/transport.py` |
| `signed_releases` | MUST | **Met** | Release assets are signed with Sigstore keyless signing; the verification process and expected identity are documented; no long-lived private key exists. | `docs/RELEASING.md` |
| `version_tags_signed` | SUGGESTED | **Unmet (justified)** | Tags are not cryptographically signed; signed release assets cover distribution. | `docs/RELEASING.md` |
| `input_validation` | MUST | **Met** | Allowlist validation of targets, flags, options, replay plans, account fields and filenames, with tests; argued per boundary. | `docs/ASSURANCE_CASE.md` |
| `hardening` | SHOULD | **Met, with limits** | Cookie flags, CSRF, Origin checks, no-store/no-sniff/no-frame headers, throttling and bounded requests; the container still runs as root. | `docs/ASSURANCE_CASE.md` |
| `assurance_case` | MUST | **Met** | Threat model, trust boundaries, secure-design argument, weakness countermeasures and residual risks. | `docs/ASSURANCE_CASE.md` |

### Analysis

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `static_analysis_common_vulnerabilities` | MUST | **Met** | Bandit and OSV-Scanner run in a required job; CodeQL code scanning is enabled. | `.github/workflows/security.yml` |
| `dynamic_analysis_unsafe` | MUST | **N/A** | The project's own code is Python and JavaScript (memory-safe). Operating-system packages in the container image are third-party. | `docs/ARCHITECTURE.md` |

## Maintainer checklist

- [ ] Merge these changes to `main`; the evidence URLs depend on it.
- [ ] Submit the Passing answers (no item is pending), then enter these Silver answers.
- [ ] Decide how to treat `access_continuity`: arrange Docker Hub access for the successor (or a multi-owner organization) and record it in [CONTINUITY.md](CONTINUITY.md), or accept a source-only release as sufficient.
- [ ] Decide how to treat the 38 open tier B image advisories: verify per interface, reduce Nmap/Python privileges, change the base image, or have the policy owner amend the gate ([triage options](IMAGE_ADVISORY_TRIAGE.md#what-this-means-for-the-next-release)).
- [ ] Have an independent reviewer assess the 42 tier A items and, if they agree, publish OpenVEX statements for them. None exist yet.
- [ ] Cut a release containing login, TLS verification by default and loopback binding, and update `SECURITY.md`/`SUPPORT.md` wording that distinguishes v2.6.0 from unreleased behavior.
- [ ] Consider enabling "require sign-off on web-based commits" in repository settings so the DCO claim is enforced.
- [ ] Add the earned badge links to the README within 48 hours.

## Latest local results

Local run on Windows with Python 3.14 (CI uses 3.10 and 3.11; these numbers are not CI output):

- **Tests:** 1,050 passed, 11 platform-specific skips (Linux/macOS-only and POSIX
  installer tests; the installer tests were run separately under Linux/WSL and passed).
- **Python coverage:** 91.79% statement coverage (5,504 of 5,996) and 87.64% branch
  coverage (2,417 of 2,758); the combined figure reported by `pytest-cov` is 90.48%.
  JavaScript coverage is not measured.
- **Ruff 0.17.1** (`E`, `W`, `F`, `B`, `I`): no findings.
- **ESLint 10.12.0** on `modules/web_ui_static`: no findings.
