# Roadmap

This roadmap covers **Q4 2026 through Q4 2027** (five calendar quarters, 2026-10-01
to 2027-12-31) and was last reviewed on 2026-10-19. It states what the maintainer
intends to work on and what the project deliberately will not do. AutoPWN Suite is
a volunteer-maintained project: items are **intentions, not commitments or delivery
dates**, and they may move, shrink or be dropped as security reports, contributor
availability and upstream changes dictate. Security fixes always take priority over
roadmap features. The maintainer reviews this file at least once per quarter and
whenever a stable release is published; completed or abandoned items are recorded in
[CHANGELOG.md](../CHANGELOG.md) or noted here rather than silently deleted.

Sources for this plan: the open items in
[Security advisories](SECURITY_ADVISORIES.md), the known gaps in the
[threat model](THREAT_MODEL.md) and [secret management](SECRETS.md), the
OpenSSF Best Practices criteria, and the `Unreleased` section of the changelog. Contributions are welcome
for any item; see [CONTRIBUTING.md](../.github/CONTRIBUTING.md) and check the non-goals
below before starting large work.

## Where the project is today

- **v2.8.1** (2026-10-24) is the supported stable release ([support policy](../SUPPORT.md)).
- v2.7.0 (2026-10-19) added the PyPI package and the standalone binaries; v2.8.0 (2026-10-21) added Turkish
  localization, `--check-update` and `--apply-update`, and vulnerability categories in the dashboard;
  v2.8.1 adds the dashboard's update check and self-update (Settings), and makes `--apply-update` move
  only forward.
- v2.6.1 (2026-10-16) shipped fixes for AUTOPWN-SA-2026-002 through 005, a
  required dashboard login, signed-release tooling and expanded documentation.
  v2.6.0 and earlier do not have these changes.
- Known open items: the project has a single maintainer
  ([continuity plan](CONTINUITY.md)); integration credentials are stored in plaintext
  in `web_ui_settings.json`; and there are accessibility and internationalization
  gaps ([accessibility](ACCESSIBILITY.md), [internationalization](INTERNATIONALIZATION.md)).

## Planned work by quarter

### Q4 2026 (October-December): harden the release path

- Done: v2.6.1 (2026-10-16) shipped the dashboard login and the
  AUTOPWN-SA-2026-002..005 fixes, followed by v2.7.0 (2026-10-19); the release notes
  are in [CHANGELOG.md](../CHANGELOG.md) ([release procedure](RELEASING.md)).
- At each stable release, update [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md), the threat model,
  interface and support documents so they match the released behavior (the dashboard
  login changes the original AUTOPWN-SA-2026-001 conditions), and update
  [SUPPORT.md](../SUPPORT.md) with the new supported version and end-of-life range.
- Confirm that GitHub repository settings (required checks, non-author review,
  administrator enforcement, secret scanning, push protection) match
  [GOVERNANCE.md](../GOVERNANCE.md), and record the quarterly access review.
- Work toward the OpenSSF Best Practices Passing, then Silver, badge for
  [project 15518](https://www.bestpractices.dev/projects/15518) using the evidence
  documents; do not claim a level until the badge application shows it.
- Appoint and document a backup maintainer or designated reviewer
  ([continuity](CONTINUITY.md)).

### Q1 2027 (January-March): dashboard security and accessibility

- Review the new dashboard session handling end to end (cookie flags, session
  expiry and revocation, logout, brute-force throttling, CSRF exposure of state-changing
  routes, and the same-origin `Origin` checks noted in
  [ARCHITECTURE.md](ARCHITECTURE.md)) and fix what the review finds, with
  regression tests.
- Reduce the plaintext-secret exposure documented in [SECRETS.md](SECRETS.md): the dashboard
  now creates its files with mode `0600` on POSIX, so evaluate tightening what that leaves
  (an existing data directory keeps its mode; files from earlier releases are restricted when the dashboard starts) and an option to supply
  integration secrets through environment variables or a file outside the data
  directory instead of the JSON settings.
- Address the high-impact items in the [accessibility plan](ACCESSIBILITY.md): keyboard-operable
  tabs and toggles, programmatic labels for all form fields, visible focus indicators
  and text contrast.

### Q2 2027 (April-June): maintainability and internationalization groundwork

- English and a machine-translated Turkish interface are shipped. Have a native
  Turkish speaker review the fuzzy-marked catalog and the dashboard dictionary,
  starting with security-meaning strings, per the
  [internationalization plan](INTERNATIONALIZATION.md), and keep new messages
  translatable.
- Decide whether to continue supporting Python 3.10, whose upstream end-of-life is
  scheduled for October 2026, and update `pyproject.toml`, CI, documentation and
  [SUPPORT.md](../SUPPORT.md) together if support is dropped. Evaluate adding the
  next Python release to the CI matrix.
- Continue dependency refreshes through Dependabot-proposed updates reviewed under
  [dependency management](DEPENDENCIES.md) and the [security testing policy](SECURITY_TESTING.md).

### Q3 2027 (July-September): scanner quality

- Improve CVE matching accuracy and local vulnerability database workflows
  (see the [offline database](../README.md#offline-vulnerability-database) section),
  tracking false-positive reports in issues.
- Extend web-check coverage conservatively. New checks must stay within the existing
  request budgets, same-origin and no-ambient-credential rules, and report candidates
  or observations rather than claiming proof of exploitation.
- Review the list of supported Nmap scan techniques and NSE interactions against
  current Nmap releases.

### Q4 2027 (October-December): consolidation

- Re-run the source [security assessment](SECURITY_ASSESSMENT.md) against
  the then-current release and publish updated advisories and threat-model entries.
- Review the whole roadmap, publish the next 12-month roadmap, and review the
  bus-factor and succession arrangements in [CONTINUITY.md](CONTINUITY.md).
- If at least one additional trusted contributor has joined, evaluate sharing
  release-manager duties under the access-review rules in [GOVERNANCE.md](../GOVERNANCE.md).

## Explicit non-goals

The project will **not** pursue the following during this period, so contributors
need not propose them:

- **A multi-tenant or hosted scanning service.** The dashboard is an
  operator-controlled administrative tool with one account model; per-user
  tenancy, public-internet hosting and SaaS operation are out of scope
  ([architecture](ARCHITECTURE.md)).
- **Long-term-support branches or backports.** Only the latest stable release is
  supported ([SUPPORT.md](../SUPPORT.md)); fixes land in the next stable release.
- **Replacing Nmap with a built-in scanning engine.** The project continues to
  run the system Nmap executable and parse its XML.
- **A complete DAST/web penetration-testing platform.** Web checks stay bounded,
  budgeted and conservative, and report candidates for human review.
- **Support for scanning without authorization,** stealth/persistence tooling,
  malware development, or features whose primary purpose is attacking systems the
  operator does not control.
- **Guaranteed vulnerability-free output or safety clearance.** CVE matching is
  keyword and version based; a clean result does not prove a target is secure.
- **Native desktop or mobile applications, and a proprietary or paid tier.**
- **Adding a language without a named reviewer who reads it**
  ([plan](INTERNATIONALIZATION.md)), and **guaranteeing full WCAG conformance
  within this period** ([accessibility](ACCESSIBILITY.md) lists a prioritized
  improvement plan, not a conformance claim).

## Changing the roadmap

Open an issue to propose an addition, a re-prioritization or a non-goal change.
The maintainer decides, records significant decisions in the issue or pull
request ([governance](../GOVERNANCE.md)), and updates this document in the same
change that alters direction. Security-sensitive suggestions use the private
channel in [SECURITY.md](../SECURITY.md).
