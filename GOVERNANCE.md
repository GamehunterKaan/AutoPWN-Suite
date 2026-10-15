# Project governance and access

AutoPWN Suite is maintained in the single authoritative repository
[GamehunterKaan/AutoPWN-Suite](https://github.com/GamehunterKaan/AutoPWN-Suite).
External packages and the Docker Hub image are dependencies and distribution
channels, not additional project source repositories.

## Members with sensitive access

| Member | Role | Sensitive resources and responsibilities |
| --- | --- | --- |
| [Kaan Gültekin (@GamehunterKaan)](https://github.com/GamehunterKaan) | Owner, maintainer, release manager, security contact | Repository administration and collaborator permissions; branch protection and Actions settings; CI secret administration; Docker Hub publishing credentials; release approval and publication; private vulnerability reports and coordinated disclosure. |

This is the human access inventory as of 2026-10-15. The owner updates it whenever
access changes. Contributors do not gain sensitive access by submitting a pull
request. Invitations and permission changes are manual. Require MFA or a passkey
for accounts with sensitive access, and revoke access that is no longer needed.
Do not list secret values, recovery codes, or private reporting details here.

## Automation identities

GitHub Actions uses short-lived `GITHUB_TOKEN` credentials. The repository default
is read-only, and each workflow declares its permissions. Builds and scans have
read-only access; only signing receives OIDC and only publication receives
release-write permissions. Docker Hub push/sign access uses
the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. An OIDC identity
signs release artifacts through Sigstore; no long-lived signing key is stored.
Dependabot proposes dependency updates; it does not approve or merge them.

## Responsibilities and decisions

- The maintainer triages issues, decides scope, reviews implementation and tests,
  maintains documentation, and approves merges. Contributors propose changes,
  supply tests and documentation, and respond to review.
- The release manager checks the changelog, version, CI results, provenance and
  signatures, and publishes releases. See [Releasing](docs/RELEASING.md).
- The security contact acknowledges and investigates private reports, coordinates
  fixes and disclosure, and publishes advisories under [SECURITY.md](SECURITY.md).
- The owner reviews credential access, rotates compromised credentials, and
  maintains the access list. Secrets belong in GitHub Actions secrets or protected
  local configuration, never in Git.

All changes use pull requests and passing required automated checks before
merging. The maintainer reviews pull requests from other contributors before
merging them. Maintainer-authored changes may merge after the required checks
pass; another person's approval is not required. GitHub's protections apply to
administrators and keep the test/security checks required.

This single-maintainer process does not enforce non-author human approval for
every change and therefore does not meet OpenSSF control OSPS-QA-07.01. Reviewing
other contributors' work does not provide independent review of the maintainer's
own changes. Keep badge answers and the documented process consistent with the
actual GitHub settings.

## Review before granting sensitive access

Before granting write/maintain/admin permissions, merge authority, secret access,
private-advisory access or publishing rights, the owner must review the person's
identity and relevant contribution/review history. Confirm identity through an
established channel, check any claimed trusted-organization affiliation, confirm
MFA/passkey use, and assess security judgment and the specific task requiring
access. An account name, contribution volume or automated approval is not enough.

Record the approver, justification, scope and review/expiry date in the access
request; keep private identity material private. Grant the lowest necessary
role, preferably temporary, and update the public human access inventory above.
New contributors receive no elevated permissions automatically. Review access
quarterly and on role changes; promptly remove unused access and rotate exposed
credentials under [Secrets](docs/SECRETS.md). No collaborator has been added by
this policy change.

The project currently releases from one source repository. Before incorporating
a project-owned source subrepository, document it here and verify that its
review, access, CI, security-testing, disclosure and release controls are at least
as strict as this repository's applicable baseline. Block release if a subproject
does not meet those controls. Third-party packages remain subject to the
dependency and license policy.

Discuss design and scope in repository issues or discussions. The maintainer
resolves disagreements and documents significant decisions in the relevant issue
or pull request. Security-sensitive discussion uses the private reporting channel.
