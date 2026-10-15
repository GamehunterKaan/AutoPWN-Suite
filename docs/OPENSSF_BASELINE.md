# OpenSSF Baseline 3 evidence

This maps the 21 Level 3 controls on
[project 15518](https://www.bestpractices.dev/en/projects/15518/baseline-3) to
implementation and evidence. It does not certify the badge or pre-fill unmet
controls as met. Documentation/workflow changes must merge before main-branch
URLs provide authoritative evidence. Runtime findings remain disclosed and open.

| Control | Evidence and remaining condition |
| --- | --- |
| AC-04.02 | Explicit job permissions in all workflows; read-only builds/scans, no GitHub permissions for registry push, OIDC signing separated from release-write upload. |
| BR-01.04 | Release tag syntax/version/ancestry validated before API/path use in `release_assets.py`; optional security-workflow input must be a 40-character commit SHA; shell inputs passed through quoted environment variables. |
| BR-02.02 | Versioned source/SBOM/VEX filenames, versioned image tags, exact container digest and release ID/asset SHA-256 values in signed manifest. Requires successful release publication for actual asset evidence. |
| BR-07.02 | [Secret management](SECRETS.md): encrypted CI storage, runtime plaintext limitations, access review and 90-day rotation requirements. |
| DO-03.01 | [Release verification](RELEASING.md): Cosign blob/image verification and hash commands. Historical unsigned releases are explicitly identified. |
| DO-03.02 | Same guide pins expected repository/workflow/ref identity and GitHub OIDC issuer; never derive expected identity from downloaded files. |
| DO-04.01 | [SUPPORT.md](../SUPPORT.md): latest stable only, support begins at publication and ends at next stable release, scope and volunteer limitations. |
| DO-05.01 | Same support policy explicitly ends security updates for superseded versions and identifies versions below 2.6.0 as end of life. |
| GV-04.01 | [Governance](../GOVERNANCE.md): identity/history/MFA/task review before sensitive access, minimum role, recorded approval, quarterly review and removal. |
| QA-02.02 | Both compiled Docker architectures receive Syft CycloneDX SBOMs included in signed hashes. **Pending a successful release run and uploaded SBOMs**; workflow configuration alone is insufficient. |
| QA-04.02 | **N/A currently:** one project source repository, documented in Governance. Policy requires any future project source subrepository to meet equally strict applicable controls. External package dependencies are handled through SCA. |
| QA-06.02 | [Contributing](../.github/CONTRIBUTING.md): local commands, CI triggers, test scope, required coverage and interpretation of failures/skips. |
| QA-06.03 | Same guide requires automated tests for new features, major behavior/interface/trust/storage changes and bug regressions, checked by reviewers. |
| QA-07.01 | **Unmet:** the maintainer reviews contributions from other authors, but maintainer-authored changes may merge after automated checks without another person's approval. The independent-human-review status check and mandatory approval requirement have been removed. This external-contribution review practice does not satisfy the control for every change. |
| SA-03.02 | [Threat model and attack surface](THREAT_MODEL.md): source-backed runtime/deployment/CI resources, actors, trust boundaries, scenarios, mitigations and severity calibration. |
| VM-04.02 | [VEX feed](../.security/vex/README.md): reviewed, exact-version non-exploitability statements. Currently no non-affecting dependency advisory has been declared; index is empty rather than fabricated. |
| VM-05.01 | [Security testing policy](SECURITY_TESTING.md): all known applicable vulnerabilities/malware block; Python license allowlist and native distribution obligations; triage/remediation targets. |
| VM-05.02 | Same policy requires resolution before every release; exact-tag source and actual-image checks precede all distribution jobs. |
| VM-05.03 | Required **Security policy** workflow on every PR/main change: OSV known-vulnerability/malware checks, inventory completeness and fail-closed errors; exact reviewed VEX only for non-exploitable findings, never malware. |
| VM-06.01 | Same security policy defines Bandit HIGH blocking threshold at any confidence, medium/low triage targets and evidence-based expiring exceptions. |
| VM-06.02 | Required **Security policy** runs Bandit on every tracked non-test Python file and ignores inline nosec bypasses. Required CodeQL covers Python, JS/TS and Actions too. |

Do not mark release signing or SBOM delivery complete until consumers can download
the attached files, verify the expected signer and check all hashes. Do not use
an owner bypass, bot review or an AI review as evidence of independent human
approval. Required policy checks must be verified on the current PR revision.
