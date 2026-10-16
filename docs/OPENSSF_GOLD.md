# OpenSSF Best Practices: Gold gap analysis

Prepared 2026-10-16 for project 15518. This is a **gap analysis, not a claim**: Gold is
**not achievable today**. Several Gold criteria need people, accounts or infrastructure
the repository cannot supply. It lists what is done, what only the maintainer can do, and
what is structurally out of reach so the effort can be planned honestly.

Gold requires the Silver badge first (`achieve_silver`), and Silver is not yet complete
([OPENSSF_SILVER.md](OPENSSF_SILVER.md)). All criteria below are MUST unless marked.

## Summary

| Status | Criteria |
| --- | --- |
| **Done in the repository** | `copyright_per_file`, `license_per_file`, `test_statement_coverage90`, `test_branch_coverage80`, `test_invocation`, `test_continuous_integration`, `repo_distributed`, `crypto_tls12`, `code_review_standards` (documented), `two_person_review` (see below) |
| **Done once the release ships** | `crypto_used_network`, `hardening` (with limits) |
| **Maintainer action** | `require_2FA`, `small_tasks`, `hardened_site`, `dynamic_analysis`, `security_review`, `build_reproducible` |
| **Not achievable by repository changes** | `bus_factor` (2 or more), `contributors_unassociated` (two unassociated significant contributors) |
| **Prerequisite** | `achieve_silver` |

## Criteria

| Criterion | Status | Evidence and what remains |
| --- | --- | --- |
| `achieve_silver` | **Not yet** | Silver has open items; see the Silver document. |
| `bus_factor` | **Not met** | Bus factor is 1. A second person must be able to act on the project, and `access_continuity` is the Silver precursor. See [CONTINUITY.md](CONTINUITY.md). A written plan does not meet this MUST. |
| `contributors_unassociated` | **Not met** | Git history in the last year is almost entirely the maintainer plus bots (one other commit). Two significant contributors from unrelated organizations are required. This cannot be produced by editing the repository, and contributions must not be staged to satisfy it. |
| `copyright_per_file` | **Met** | Every tracked and new Python, JavaScript, shell and Docker file carries `Copyright 2022-2026 Kaan Gültekin`, matching [NOTICE](../NOTICE). |
| `license_per_file` | **Met** | The same files carry `SPDX-License-Identifier: Apache-2.0`. |
| `repo_distributed` | **Met** | Git. |
| `small_tasks` | **Maintainer action** | The `good first issue` and `help wanted` labels exist, but no open issue uses them. Create and label a few small, well-described tasks (for example the accessibility items in [ACCESSIBILITY.md](ACCESSIBILITY.md)). |
| `require_2FA` | **Maintainer action** | Cannot be verified from the repository. Confirm two-factor authentication is enforced for everyone with write access, and ideally require it at the repository or organization level. |
| `secure_2FA` (SHOULD) | **Maintainer action** | Prefer a security key or passkey over SMS or TOTP; record the choice. |
| `code_review_standards` | **Met** | Review requirements, what reviewers check and acceptance rules are in [CONTRIBUTING.md](../.github/CONTRIBUTING.md) and [GOVERNANCE.md](../GOVERNANCE.md). |
| `two_person_review` | **Likely met; verify** | 8 of the 10 pull requests merged since 2026-04-16 have an approval from an account other than the author (80%, above the required 50%). This counts approvals only; it does not verify that each reviewer is a human or that all work went through pull requests. |
| `build_reproducible` | **Maintainer action** | The container build is repeatable on amd64 (see [BUILDING.md](BUILDING.md)); arm64 and builds on other machines or days are untested. The Python source is interpreted; decide whether the criterion applies as N/A for source and as the container procedure for images. |
| `test_invocation` | **Met** | `poetry run test` / `pytest`. |
| `test_continuous_integration` | **Met** | Tests run on every push and pull request. |
| `test_statement_coverage90` | **Met (Python)** | 91.79% of Python statements (5,504 of 5,996) in the latest local run. JavaScript coverage is not measured; decide whether the criterion applies to it. |
| `test_branch_coverage80` | **Met (Python)** | 87.64% of Python branches (2,417 of 2,758) in the latest local run. JavaScript is not measured. |
| `crypto_used_network` | **Met after release** | Provider, SMTP and web-scan traffic verify TLS by default and the dashboard is loopback-only by default; plain-HTTP scan targets are chosen by the operator. Unreleased. |
| `crypto_tls12` | **Met** | The supported Python TLS stack negotiates TLS 1.2 or later by default. |
| `hardened_site` | **Maintainer action** | `https://kaangultekin.net/projects/autopwn-suite/` returned HTTP 200 but **none** of the hardening headers checked (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`). Add them with non-permissive values at the web server or CDN, then re-check. GitHub controls the headers of the repository and release pages. |
| `security_review` | **Likely met; confirm** | An independent source review of v2.6.0 is recorded in [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) and the [threat model](THREAT_MODEL.md), considering security requirements and boundaries. It does not cover the unreleased authentication code, which should be reviewed before a Gold claim. |
| `hardening` | **Met, with limits** | See the [assurance case](ASSURANCE_CASE.md). The container runs as root and Nmap runs with full privileges; least privilege would strengthen this. |
| `dynamic_analysis` | **Maintainer action** | A dynamic tool must be applied to each major production release before release. None runs today. Candidates: OWASP ZAP baseline against the dashboard in CI, and a fuzzing run over the Nmap XML and NVD parsers. |
| `dynamic_analysis_enable_assertions` (SHOULD) | **Not met** | The code relies on validation and tests rather than runtime assertions; document an exception or add assertions around parsers. |

## Realistic path

1. Finish Silver and release. Almost everything `Met after release` follows.
2. Do the small maintainer actions: website headers, labeled starter issues, confirm 2FA, add a ZAP baseline job.
3. Treat `bus_factor` and `contributors_unassociated` as long-term goals that depend on growing a community.
   Until they are met the project should not claim Gold. The [roadmap](ROADMAP.md) is the place to track them.
