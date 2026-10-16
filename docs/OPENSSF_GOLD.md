# OpenSSF Best Practices: Gold gap analysis

Prepared 2026-10-16 for project 15518. This records the state of each Gold criterion. Several
answers rest on the maintainer's attestation or determination, and the document says so where that
is the case. Gold requires the Silver badge first (`achieve_silver`); see
[OPENSSF_SILVER.md](OPENSSF_SILVER.md). All criteria below are MUST unless marked.

## Summary

| Status | Criteria |
| --- | --- |
| **Met in the repository** | `copyright_per_file`, `license_per_file`, `small_tasks`, `test_statement_coverage90`, `test_branch_coverage80`, `test_invocation`, `test_continuous_integration`, `repo_distributed`, `crypto_tls12`, `code_review_standards`, `two_person_review`, `security_review`, `dynamic_analysis` (workflow not yet run on GitHub) |
| **Met, with limits** | `build_reproducible`, `hardening` |
| **Met by maintainer attestation or determination** | `bus_factor`, `contributors_unassociated`, `require_2FA` |
| **Met once the release ships** | `crypto_used_network` |
| **Maintainer action** | `hardened_site` (website headers), `secure_2FA` (SHOULD) |
| **Unmet (justified)** | `dynamic_analysis_enable_assertions` (SHOULD) |
| **Prerequisite** | `achieve_silver` |

## Criteria

| Criterion | Status | Evidence and what remains |
| --- | --- | --- |
| `achieve_silver` | **Not yet** | Silver has open items; see the Silver document. |
| `bus_factor` | **Met (maintainer attestation)** | The maintainer attests a bus factor of 2 and offers the second maintainer account, which has write access to this repository, as evidence: <https://github.com/autosec-overflow>. The repository cannot verify this attestation, and a written plan alone would not meet the MUST ([CONTINUITY.md](CONTINUITY.md)). |
| `contributors_unassociated` | **Met (maintainer determination)** | The maintainer counts the independent contributor `iaacornus` (about 100 commits, 2022) as a significant, unassociated contributor. The criterion's guidance describes "significant" as non-trivial contributions in the past year, and those commits are older than that, so a reviewer may question this reading. |
| `copyright_per_file` | **Met** | Every tracked and new Python, JavaScript, shell and Docker file carries `Copyright 2022-2026 Kaan Gültekin`, matching [NOTICE](../NOTICE). |
| `license_per_file` | **Met** | The same files carry `SPDX-License-Identifier: Apache-2.0`. |
| `repo_distributed` | **Met** | Git. |
| `small_tasks` | **Met** | Small tasks for new or casual contributors are identified in [CONTRIBUTING.md](../.github/CONTRIBUTING.md#good-first-contributions), each tied to a real file and gap. No GitHub issues are open, which is fine: the criterion asks that the tasks be identified, not that they be open issues. |
| `require_2FA` | **Met (maintainer attestation)** | The maintainer confirms two-factor authentication is required for everyone who can change the repository or reach private vulnerability reports. This cannot be verified from the repository. |
| `secure_2FA` (SHOULD) | **Maintainer action** | Prefer a security key or passkey over SMS or TOTP; record the choice. |
| `code_review_standards` | **Met** | Review requirements, what reviewers check and acceptance rules are in [CONTRIBUTING.md](../.github/CONTRIBUTING.md) and [GOVERNANCE.md](../GOVERNANCE.md). |
| `two_person_review` | **Met** | 8 of the 10 pull requests merged since 2026-04-16 (80%, above the required 50%) have an approval from an account other than the author. Counted by approvals; it does not verify that each approver is human or that all work went through pull requests. |
| `build_reproducible` | **Met, with limits** | The container image was built twice for each of linux/amd64 and linux/arm64 (arm64 under QEMU) from clean checkouts with different file times, with the pinned base image, dated Debian snapshot, hash-locked wheels and `SOURCE_DATE_EPOCH`; each pair produced byte-identical image archives ([BUILDING.md](BUILDING.md)). Not verified: a different machine, day or BuildKit version, native arm64 hardware, and the commit-time epoch the release workflow uses. The Python source itself is interpreted and ships as-is. |
| `test_invocation` | **Met** | `poetry run test` / `pytest`. |
| `test_continuous_integration` | **Met** | Tests run on every push and pull request. |
| `test_statement_coverage90` | **Met (Python)** | 91.79% of Python statements (5,504 of 5,996) in the latest local run. JavaScript coverage is not measured; decide whether the criterion applies to it. |
| `test_branch_coverage80` | **Met (Python)** | 87.64% of Python branches (2,417 of 2,758) in the latest local run. JavaScript is not measured. |
| `crypto_used_network` | **Met after release** | Provider, SMTP and web-scan traffic verify TLS by default and the dashboard is loopback-only by default; plain-HTTP scan targets are chosen by the operator. Unreleased. |
| `crypto_tls12` | **Met** | The supported Python TLS stack negotiates TLS 1.2 or later by default. |
| `hardened_site` | **Maintainer action** | Checked 2026-10-16: `https://kaangultekin.net/projects/autopwn-suite/` returns HTTP 200 with **none** of the hardening headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`). The site is served by GitHub Pages (`Server: GitHub.com`), which cannot set custom response headers, so this needs a proxy or CDN in front of it (for example Cloudflare response-header rules) or a host that supports a headers file. Re-check with `curl -sI` after the change. GitHub controls the headers of the repository and release pages. |
| `security_review` | **Met** | An independent source review of v2.6.0 is recorded in [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) and the [threat model](THREAT_MODEL.md), within the last five years, considering the security requirements and boundaries. The maintainer also attests an independent reviewer for the new authentication code; no report of that review is in the repository. |
| `hardening` | **Met, with limits** | See the [assurance case](ASSURANCE_CASE.md). The container runs as root and Nmap runs with full privileges; least privilege would strengthen this. |
| `dynamic_analysis` | **Met** | An OWASP ZAP baseline scan of the running dashboard (unauthenticated sign-in surface and an authenticated crawl) runs on pull requests and pushes to `main`, and the container publication job depends on it, so a release cannot be pushed without it ([workflow](../.github/workflows/dynamic-analysis.yml), [rules](../.github/zap/rules.tsv)). Seeded fuzz tests ([test_fuzz_inputs.py](../tests/unit/test_fuzz_inputs.py)) also run on every change. The first ZAP run found missing security headers, which were fixed. The workflow was calibrated in a local container; it has **not yet run on a GitHub-hosted runner**. Its Replacer rule and a few informational ZAP alerts are explicitly ignored with written reasons. |
| `dynamic_analysis_enable_assertions` (SHOULD) | **Unmet (justified)** | Production code deliberately avoids `assert` for validation because Python strips assertions under `python -O`. Explicit checks that raise documented errors are used instead and exercised by the test and fuzz suites ([CODING_STANDARDS.md](CODING_STANDARDS.md#assertions-and-input-checking)). |

## Remaining steps

1. Finish Silver and ship the release; `crypto_used_network` and the Silver items that depend on it follow.
2. Add the hardening headers (HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) to
   `kaangultekin.net` for `hardened_site`, then re-check; prefer a security key or passkey for `secure_2FA`.
3. Watch the first GitHub run of the dynamic-analysis workflow and fix any difference from the local calibration.
4. Keep the attested items current: `bus_factor`, `contributors_unassociated` and `require_2FA` are the maintainer's
   statements, not facts the repository can verify, so a reviewer may ask for more detail.
