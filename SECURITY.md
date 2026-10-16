# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in AutoPWN Suite, please report it responsibly to help keep the project and its users safe. Do **not** create a public issue for security concerns. Instead, follow these steps:

1. **Contact the Maintainer Privately:**  
   Use GitHub's [private security advisory](https://github.com/GamehunterKaan/AutoPWN-Suite/security/advisories/new) feature.

2. **Include Details:**  
   - Steps to reproduce the vulnerability  
   - Potential impact  
   - Any suggested fixes or mitigations

3. **Coordinate privately:**
   The security contact is [Kaan Gültekin (@GamehunterKaan)](https://github.com/GamehunterKaan).
   Please include the affected version, deployment prerequisites, reproduction
   steps, expected/observed behavior and impact. Do not include live credentials
   unless essential; use redacted examples. See [Governance](GOVERNANCE.md) for
   roles and sensitive access.

## Coordinated vulnerability disclosure

The maintainer aims to acknowledge a private report within **7 calendar days**,
provide an initial assessment within **14 calendar days**, and update the
reporter at least every **30 calendar days** while a confirmed issue is open.
These are response targets for a volunteer-maintained project, not a guaranteed
fix deadline. If no acknowledgement arrives after 7 days, follow up in the same
private advisory; do not post exploit details in a public issue.

We coordinate validation, remediation, credit and disclosure with the reporter.
The default target is coordinated public disclosure within **90 calendar days**
of the initial report, preferably with a fix or practical mitigation. Extensions
should be agreed and explained privately. Active exploitation or imminent harm
may require earlier publication of protective guidance. Reporters should avoid
accessing other people's data, disrupting services or testing without permission.

## Response process

For a privately reported vulnerability the maintainer follows these steps. Times are
calendar days from the initial report and are targets for a volunteer-maintained
project, not guarantees.

| Step | What happens | Target |
| --- | --- | --- |
| 1. Acknowledge | Confirm receipt in the private advisory. | Within 7 days |
| 2. Assess | Reproduce, determine affected versions and prerequisites, assign severity and decide whether it is a vulnerability. The reporter receives the outcome, or a request for more information. | Within 14 days |
| 3. Fix or mitigate | Develop and test a fix or practical mitigation, with a regression test, in a private branch or advisory workspace where possible. Critical and high severity issues are prioritized; the aim is a fix or mitigation within 30 days of a confirmed report. | Within 90 days, the default disclosure date |
| 4. Release | Publish a stable release containing the fix with release notes under [CHANGELOG.md](CHANGELOG.md) that describe the security impact. | As soon as the fix is verified |
| 5. Disclose | Publish the advisory (see below), with credit, and update [SUPPORT.md](SUPPORT.md) if versions become end of life. | At release or at the agreed date |
| 6. Keep informed | Update the reporter at least every 30 days while a confirmed issue is open, and before any public disclosure. | Every 30 days |

If a report is not a security vulnerability, the maintainer says so and may move it
to a public issue with the reporter's agreement. Reports about unsupported versions
receive the same acknowledgement and assessment, but fixes land only in the latest
stable release ([support lifecycle](SUPPORT.md)).

## Reporter credit

Reporters are **credited by name (or the handle they choose) in the published
GitHub Security Advisory and in the release notes** for the fixing release, unless
they ask to remain anonymous. State your preferred credit text, or that you prefer
anonymity, in the private report; you can change this before publication. The
maintainer does not publish a reporter's private contact details and does not
disclose a reporter's identity without permission. The project offers no monetary
bounty. Credit is given for reports the maintainer confirms as valid and appears in the
affected advisory and release notes; see the
[advisory index](docs/SECURITY_ADVISORIES.md).

Publish confirmed vulnerability information in
[GitHub Security Advisories](https://github.com/GamehunterKaan/AutoPWN-Suite/security/advisories)
and/or the versioned [security advisory index](docs/SECURITY_ADVISORIES.md).
An advisory records affected/assessed versions, prerequisites, impact, mitigation,
fixed version when available, disclosure/update dates and references. Update the
record when a fix is released; do not describe an unresolved issue as fixed.
Do not invent CVE identifiers or claim that an empty advisory list proves safety.

## Security expectations

AutoPWN Suite is an operator-controlled scanner that runs with its user's privileges,
sends network traffic to the targets you choose, and stores integration credentials
you provide. Use it only against systems you are authorized to test. It is not a
multi-tenant service, does not sandbox untrusted users, and does not prove a target is
secure or a finding is exploitable. Verify release signatures before use
([release verification](docs/RELEASING.md)), keep dependencies and Nmap up to date,
and read the [threat model](docs/THREAT_MODEL.md) and
[security assessment](docs/SECURITY_ASSESSMENT.md) for the boundaries and known risks.

## Supported versions and deployment

Security fixes target the latest stable release. Users of older releases should
upgrade unless an advisory specifies a supported backport. Assessments and
advisories explicitly identify the versions they cover.
See [support lifecycle](SUPPORT.md) for scope, duration and end-of-life rules,
[secret management](docs/SECRETS.md) for storage/access/rotation requirements, and
[automated security policy](docs/SECURITY_TESTING.md) for SCA/SAST thresholds and
non-exploitability decisions.

The dashboard is an administrative interface. **v2.6.0 has no built-in login.**
The unreleased development version requires sign-in: on first launch it creates an
`admin` account with a random password shown once in the server terminal, stores
only a scrypt hash, and lets the operator change the credentials under
Settings -> Account or reset them with `python autopwn.py --web-reset-account`.
Remote access requires HTTPS. Regardless of version, restrict access to trusted
operators, bind to loopback when possible, and use authenticated ingress/firewall
controls for remote access. Protect the data directory and backups: settings contain
integration credentials in plaintext JSON. Use a dedicated scanner account and do not
expose the dashboard to the public internet. Do not rely on the login as the only
control for an internet-facing deployment.

See [Security assessment](docs/SECURITY_ASSESSMENT.md) for scope, known risks and
limitations. Private reporting remains available even when an issue has not yet
been published.

Your responsible disclosure is appreciated and helps improve the security of AutoPWN Suite for everyone.
