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
is read-only, and each workflow declares its permissions. The publishing job
explicitly requests release-write and OIDC permissions; Docker Hub access uses
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

Changes normally use pull requests. Automated test/status checks must pass before
merging. An exceptional bypass must be an explicit maintainer decision recorded
in the pull request with its reason and follow-up; silence or an unfinished run is
not approval. GitHub's actual settings, rather than this policy alone, enforce
required checks. The owner must keep those settings aligned with this policy.

Discuss design and scope in repository issues or discussions. The maintainer
resolves disagreements and documents significant decisions in the relevant issue
or pull request. Security-sensitive discussion uses the private reporting channel.
