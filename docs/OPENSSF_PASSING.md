# OpenSSF Best Practices: Passing preparation

Prepared 2026-10-16. This is the metal-series Passing checklist, separate from OpenSSF Baseline levels. It records evidence-backed answers and maintainer confirmations for project 15518.

These changes are local and uncommitted. Merge the quality gate and this evidence document before using their main-branch URLs as published evidence; no badge answers have been submitted automatically.

## Current readiness

63 proposed Met answers and 4 N/A answers; no item is pending. Several Met answers rest on maintainer attestations and on fixes that are on `main` but unreleased (see below); optional SHOULD/SUGGESTED criteria are not silently promoted to mandatory requirements.

Local verification (unreleased working tree, run on Windows, not CI): `python -m pytest tests/unit -q` reports **1062 passed, 11 platform-specific skips**, **91.93% Python statement coverage** (5,527/6,012) and **87.93% Python branch coverage** (2,425/2,758). The combined coverage figure is 90.67%. No full JavaScript coverage percentage is claimed. `ruff check .`, `node --check` on all four dashboard scripts, ESLint 10.12.0 and `scripts/export_locked_requirements.py --check` passed locally, and source SCA/SAST was not re-run for this update (an earlier local run covered 35 locked dependencies).

## Maintainer confirmations

On 2026-10-16, the primary maintainer confirmed:

- Understanding of secure design, including least privilege, fail-safe defaults, complete mediation and allowlist validation.
- Understanding of common vulnerability classes, including injection, XSS and missing authorization, and ways to mitigate them.
- No vulnerability reports were received in the last six months; internal source-assessment findings are tracked separately.
- GitHub Issues was the only bug/enhancement reporting channel in the last 2-12 months. The public tracker has one bug report in that window (#67), answered by the maintainer, and no enhancement requests.
- The `vulnerabilities_fixed_60_days` requirement is met: no applicable medium-or-higher vulnerability has remained publicly known and unpatched for more than 60 days.
- The `vulnerabilities_critical_fixed` requirement is met: applicable critical vulnerabilities are handled rapidly.
- The dashboard authentication, loopback default and related mitigations close AUTOPWN-SA-2026-001 (recorded in [the advisory](SECURITY_ADVISORIES.md)). The fix is in source but not in a published release.
- The knowledge and process attestations above were re-confirmed by the maintainer after this document was updated.

These are maintainer attestations, not claims that automation can establish a person's knowledge or inspect private history.

## Cryptographic scope

The Python runtime baseline is 3.10+. Its [documented TLS defaults](https://docs.python.org/3.10/library/ssl.html#ssl.SSLContext) use security level 2, minimum TLS 1.2, modern forward-secret AES/ChaCha20 suites, RSA/DH keys of at least 2048 bits and ECC keys of at least 224 bits. Release authenticity uses SHA-256 and Sigstore/Cosign with the expected issuer and signing identity. The application delegates cryptographic primitives and security randomness to these providers.

Legacy-protocol handshakes and inspection of weak/self-signed target certificates are scanner diagnostics. They do not protect project secrets and do not establish a dependency vulnerability as non-exploitable. Local remediation now validates SMTP peer certificates and suppresses ambient credentials in diagnostic probes, and web scan requests (including replay) verify target certificates by default with an explicit, recorded `--insecure-tls` opt-out; none of these changes has shipped in v2.6.0. TLS diagnostics still inspect untrusted certificates without trusting them and send no HTTP request or credentials. Silver's stricter default-verification requirements must be assessed separately.

Unreleased changes add an inbound password store: the dashboard's single administrator account keeps only a salted scrypt hash (`hashlib.scrypt`, 16-byte random salt per account, N=32768, r=8, p=3, constant-time comparison) in `web_ui_auth.json`, and generates passwords, salts, session identifiers and CSRF tokens with Python's `secrets` module (`modules/web_auth.py`, `tests/unit/test_web_auth.py`). Stored outbound SMTP/API credentials are outside the password-hashing criterion; their plaintext limitations, and the `*_FILE` credential-file option that keeps them out of dashboard settings, are documented in [secret management](SECRETS.md).

## Remaining security review

No Passing criterion is pending. Two caveats apply to `static_analysis_fixed`:

- The fixes for AUTOPWN-SA-2026-002 through 005 and the authentication that closes AUTOPWN-SA-2026-001 are on `main` but **not in a published release**; v2.6.0 remains affected. Do not describe any of them as fixed in a published version until the next release ships.
- Residual limits of the authentication remain documented: one shared administrator account, no MFA, plaintext-at-rest settings, and operator-provided HTTPS for remote access.

Dependency monitoring covers the project's Python requirements (see [DEPENDENCIES.md](DEPENDENCIES.md)). Do not invent VEX declarations, remove findings, lower severities, or treat a signature as a safety assessment.

## Proposed answers

| Criterion | Requirement | Answer | Short description | Evidence |
| --- | --- | --- | --- | --- |
| `description_good` | MUST | **Met** | README and the live project homepage describe the scanner and its purpose. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/README.md) |
| `interact` | MUST | **Met** | README/contributor/security links cover obtaining software, reporting issues, and contributing. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/README.md) |
| `contribution` | MUST | **Met** | PR contribution and review procedures are public. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md) |
| `contribution_requirements` | SHOULD | **Met** | Contribution requirements cover tests, docs, legal rights, dependencies, and review. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md) |
| `floss_license` | MUST | **Met** | Project results are licensed Apache-2.0. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/LICENSE) |
| `floss_license_osi` | SUGGESTED | **Met** | Apache-2.0 is an OSI-approved license. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/LICENSE) |
| `license_location` | MUST | **Met** | LICENSE is at the repository root. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/LICENSE) |
| `documentation_basics` | MUST | **Met** | User setup and basic source/container/CLI/dashboard usage are documented. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/README.md) |
| `documentation_interface` | MUST | **Met** | Input/output, CLI, API, configuration, and integration interfaces are documented. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/INTERFACES.md) |
| `sites_https` | MUST | **Met** | The homepage, GitHub repository, and official distribution locations support HTTPS; the homepage returned HTTP 200 over verified HTTPS. | [Evidence](https://kaangultekin.net/projects/autopwn-suite/) |
| `discussion` | MUST | **Met** | GitHub Issues and PR discussions are searchable, URL-addressable, and publicly participatory; GitHub Discussions need not be enabled. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/issues) |
| `english` | SHOULD | **Met** | Documentation and issue/PR discussions use English. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/README.md) |
| `maintained` | MUST | **Met** | The repository is active, unarchived, and has recent merged changes and successful CI. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/commits/main) |
| `repo_public` | MUST | **Met** | The Git repository is publicly readable. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite) |
| `repo_track` | MUST | **Met** | Git history records changes, authors, and dates. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/commits/main) |
| `repo_interim` | MUST | **Met** | Interim branches, commits, and PRs are available between releases. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/pulls?q=is%3Apr) |
| `repo_distributed` | SUGGESTED | **Met** | The project uses Git. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite) |
| `version_unique` | MUST | **Met** | Current release is uniquely identified as v2.6.0. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/releases/tag/v2.6.0) |
| `version_semver` | SUGGESTED | **Met** | Releases use vMAJOR.MINOR.PATCH identifiers and contributor docs describe SemVer. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md) |
| `version_tags` | SUGGESTED | **Met** | The v2.6.0 Git tag identifies released source. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/tree/v2.6.0) |
| `release_notes` | MUST | **Met** | The supported release now has descriptive functional and security notes, not only raw commit-log output. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/releases/tag/v2.6.0) |
| `release_notes_vulns` | MUST | **N/A** | The current release contains no fixes for previously CVE/GHSA-identified project vulnerabilities; the five project findings remain open in v2.6.0, with four local fixes awaiting release. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/CHANGELOG.md) |
| `report_process` | MUST | **Met** | GitHub Issues is the documented bug-report channel. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/SUPPORT.md) |
| `report_tracker` | SHOULD | **Met** | GitHub Issues is active. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/issues) |
| `report_responses` | MUST | **Met** | The sole public bug report created in the 2-12 month window, #67, received a maintainer reply on 2025-12-27 after its 2025-12-26 submission. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/67) |
| `enhancement_responses` | SHOULD | **Met** | No enhancement requests were received in the assessment window; the maintainer confirmed GitHub Issues was the only reporting channel. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `report_archive` | MUST | **Met** | Closed and open issues/comments remain publicly searchable. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/issues?q=is%3Aissue) |
| `vulnerability_report_process` | MUST | **Met** | SECURITY.md publishes the vulnerability-reporting procedure. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/SECURITY.md) |
| `vulnerability_report_private` | MUST | **Met** | GitHub private security advisories are linked for confidential reporting. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/SECURITY.md) |
| `vulnerability_report_response` | MUST | **N/A** | The maintainer confirmed no vulnerability reports were received in the last six months. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `build` | MUST | **Met** | Poetry/source and Docker build procedures are documented and supported by CI. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/BUILDING.md) |
| `build_common_tools` | SUGGESTED | **Met** | Python, pip, Poetry, and Docker are common build tools. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/BUILDING.md) |
| `build_floss_tools` | SHOULD | **Met** | The project can be built with FLOSS Python/Poetry and Linux Docker Engine tools. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/BUILDING.md) |
| `test` | MUST | **Met** | The Apache-2.0 repository includes public Pytest tests and documented invocation. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md#test-policy-and-interpreting-results) |
| `test_invocation` | SHOULD | **Met** | Tests run through standard pytest and poetry run test commands. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/pyproject.toml) |
| `test_most` | SUGGESTED | **Met** | Tests cover major CLI, API, web, offline, daemon, persistence, authentication, and release paths; the full local Python unit run achieved 91.93% statement and 87.93% branch coverage. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md#test-policy-and-interpreting-results) |
| `test_continuous_integration` | SUGGESTED | **Met** | PRs and main pushes run public CI tests. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/workflows/poetry-tests.yml) |
| `test_policy` | MUST | **Met** | The written policy requires tests for major behavior changes. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md#test-policy-and-interpreting-results) |
| `tests_are_added` | MUST | **Met** | Recent major fixes include tests, for example commits 82a26aa, f11ca3e, and 6785056. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/commit/6785056) |
| `tests_documented_added` | SUGGESTED | **Met** | Contribution instructions explicitly document required test additions. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md#test-policy-and-interpreting-results) |
| `warnings` | MUST | **Met** | Pinned Ruff (rules E, W, F, B, I; 200 columns) checks all Python, ESLint and `node --check` check the four frontend scripts, and `export_locked_requirements.py --check` runs in the required `poetry-tests` job; project-originated Deprecation/Future/Syntax warnings are errors under pytest. CodeQL and Bandit provide additional static checks. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/CODING_STANDARDS.md) |
| `warnings_fixed` | MUST | **Met** | All findings in the selected Ruff warning profile were resolved and the four JavaScript syntax checks pass locally; the ESLint rule set is enforced in CI and was not run in the local environment. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/CODING_STANDARDS.md) |
| `warnings_strict` | SUGGESTED | **Met** | The reviewed profile (pycodestyle, Pyflakes, bugbear and import order) fails on every finding, with only the documented per-file exceptions in `pyproject.toml`, and project-originated deprecation/syntax warnings fail the tests. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/pyproject.toml) |
| `know_secure_design` | MUST | **Met** | The primary maintainer confirmed knowledge of secure-design principles on 2026-10-16. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `know_common_errors` | MUST | **Met** | The primary maintainer confirmed knowledge of common vulnerability classes and mitigations on 2026-10-16. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `crypto_published` | MUST | **Met** | Security crypto uses published TLS/hash/signature mechanisms through standard libraries and tools. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/RELEASING.md) |
| `crypto_call` | SHOULD | **Met** | The project calls established cryptographic libraries/tools instead of implementing custom cryptographic primitives. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/DEPENDENCIES.md) |
| `crypto_floss` | MUST | **Met** | Cryptographic functionality is available through FLOSS Python/OpenSSL/cryptography and Cosign tooling. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/DEPENDENCIES.md) |
| `crypto_keylength` | MUST | **Met** | The supported Python 3.10+ TLS defaults prohibit RSA/DH keys below 2048 bits and ECC below 224 bits; security mechanisms use provider defaults and SHA-256 signatures. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#cryptographic-scope) |
| `crypto_working` | MUST | **Met** | No reliance on broken custom cryptography for project security mechanisms was found; legacy TLS scans are diagnostics and SHA-256 binds release artifacts. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/RELEASING.md) |
| `crypto_weaknesses` | SHOULD | **Met** | Security mechanisms use current standard TLS and SHA-256 rather than SHA-1/MD5 as trust mechanisms. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/RELEASING.md) |
| `crypto_pfs` | SHOULD | **Met** | The supported Python TLS defaults use forward-secret AES/ChaCha20 suites; no custom key exchange is implemented. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#cryptographic-scope) |
| `crypto_password_storage` | MUST | **Met** | Unreleased: the dashboard's inbound password is stored only as a salted, iterated scrypt hash (per-user random 16-byte salt, N=32768, r=8, p=3) and compared in constant time; outbound integration credentials are outside this criterion. Becomes published evidence only after the code is merged and released. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/modules/web_auth.py) (tests: `tests/unit/test_web_auth.py`) |
| `crypto_random` | MUST | **Met** | Security randomness is delegated to TLS/signing providers and, for dashboard passwords, salts, session and CSRF tokens, to Python's `secrets` CSPRNG; scanner randomization is not used to generate authentication secrets. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#cryptographic-scope) |
| `delivery_mitm` | MUST | **Met** | Official source/releases/registry delivery uses authenticated HTTPS; current release assets also have verified signatures. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/releases/tag/v2.6.0) |
| `delivery_unsigned` | MUST | **Met** | Release verification uses HTTPS, expected signing identity/issuer, and signed SHA-256 hashes rather than unsigned hashes retrieved over HTTP. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/RELEASING.md#consumer-verification) |
| `vulnerabilities_fixed_60_days` | MUST | **Met** | The maintainer confirmed that no applicable medium-or-higher vulnerability has remained publicly known and unpatched for more than 60 days. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `vulnerabilities_critical_fixed` | SHOULD | **Met** | The maintainer confirmed that applicable critical vulnerabilities are handled rapidly. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/OPENSSF_PASSING.md#maintainer-confirmations) |
| `no_leaked_credentials` | MUST | **Met** | Current secret-scanning alerts are empty and the documented source assessment found no purpose-backed embedded private credentials; no live credentials were tested. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/SECURITY_ASSESSMENT.md) |
| `static_analysis` | MUST | **Met** | CodeQL Python, Actions, and JavaScript analyses passed by 13:41:03Z on 2026-10-15, before v2.6.0 publication at 13:43:39Z; current source SCA/SAST gates are additionally required. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/commit/c24c1d4835fee9e7432c2e4b1527b631d1b8258c/checks) |
| `static_analysis_common_vulnerabilities` | SUGGESTED | **Met** | CodeQL/Bandit include common-vulnerability rules. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/workflows/security.yml) |
| `static_analysis_fixed` | MUST | **Met** | The four medium findings and the dashboard-access finding are fixed in source on `main` (the maintainer closed AUTOPWN-SA-2026-001 on 2026-10-16); the fixes are unreleased, and v2.6.0 remains affected. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/SECURITY_ADVISORIES.md) |
| `static_analysis_often` | SUGGESTED | **Met** | Required security checks run on every PR and main push. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/workflows/security.yml) |
| `dynamic_analysis` | SUGGESTED | **Met** | An OWASP ZAP baseline scan of the running dashboard runs in CI on pull requests and gates image publication, seeded fuzz tests run in the normal suite, and the unit suite executes production Python with 87.93% measured branch coverage (the criterion's 80% option). | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/workflows/dynamic-analysis.yml) |
| `dynamic_analysis_unsafe` | SUGGESTED | **N/A** | Project-authored application source is Python/JavaScript, not a memory-unsafe language; externally maintained native dependencies remain subject to SCA and are not declared non-exploitable. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/DEPENDENCIES.md) |
| `dynamic_analysis_enable_assertions` | SUGGESTED | **Met** | Pytest executes many assertions and parameterized boundary cases in the regular test configuration. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/tree/main/tests) |
| `dynamic_analysis_fixed` | MUST | **N/A** | No confirmed medium-or-higher project vulnerabilities are currently attributed to dynamic analysis; the five published assessment findings were established by static source review. | [Evidence](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/SECURITY_ASSESSMENT.md) |

Original questions and expanded details: [Passing criteria](https://www.bestpractices.dev/en/projects/15518/passing). These are proposed current answers, not a guarantee that the badge has been earned.
