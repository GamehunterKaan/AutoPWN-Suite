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

Publish confirmed vulnerability information in
[GitHub Security Advisories](https://github.com/GamehunterKaan/AutoPWN-Suite/security/advisories)
and/or the versioned [security advisory index](docs/SECURITY_ADVISORIES.md).
An advisory records affected/assessed versions, prerequisites, impact, mitigation,
fixed version when available, disclosure/update dates and references. Update the
record when a fix is released; do not describe an unresolved issue as fixed.
Do not invent CVE identifiers or claim that an empty advisory list proves safety.

## Supported versions and deployment

Security fixes target the latest stable release. Users of older releases should
upgrade unless an advisory specifies a supported backport. Assessments and
advisories explicitly identify the versions they cover.

The dashboard is an administrative interface with no built-in login. Restrict
access to trusted operators, bind to loopback when possible, and use authenticated
ingress/firewall controls for remote access. Protect the data directory and
backups: settings contain integration credentials in JSON. Use a dedicated
scanner account and do not expose the dashboard to the public internet.

See [Security assessment](docs/SECURITY_ASSESSMENT.md) for scope, known risks and
limitations. Private reporting remains available even when an issue has not yet
been published.

Your responsible disclosure is appreciated and helps improve the security of AutoPWN Suite for everyone.
