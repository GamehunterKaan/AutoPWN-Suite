# Security assessment — 2026-10-15

## Scope and method

Assessed AutoPWN Suite **v2.6.0**, commit
`c24c1d4835fee9e7432c2e4b1527b631d1b8258c`, using an independent static baseline
audit, a separate architecture review, focused runtime/provider/CI investigation,
and parent validation of every reported source-to-consumer path. Supporting
reviews covered tests, fixtures, manifests, lock records, HTML/CSS and data
corpora. All **115 tracked textual files** in that snapshot were reviewed;
seven graphical assets were excluded from executable/source analysis.

The Codex Security record is `647ab48c-923c-40bc-9372-e2decc955e06`.
Its generated report, threat model, findings and coverage were retained in the
local Codex Security workbench. This repository document summarizes the results
for users without depending on access to the maintainer's local filesystem.
Subsequent Baseline 2 documentation and release automation are separate changes
and are not retroactively represented as reviewed v2.6.0 runtime code.

No external target was attacked, no deployment or private credential file was
accessed, and no credential was used. Application tests/exploits were not run as
part of this static assessment. Installed Python/Requests source was inspected
to verify SMTP default certificate behavior and ambient authentication semantics.
No current third-party vulnerability-database audit was performed. This is a
project security assessment, not a certification that the software is defect-free.

## Threats and priorities

Protected assets are the scanner account's host/network authority, integration
credentials, scan observations, persistent administration state, operator browser
and release integrity. Attackers considered include untrusted scanned services,
untrusted clients able to reach a dashboard, and active network intermediaries.
Trusted operator CLI/configuration privileges were not treated as an attacker
capability gain. Actual deployment/firewall/ACL protections remain unverified.

| Issue | Likelihood prerequisites | Impact | Priority and mitigation |
| --- | --- | --- | --- |
| Unauthenticated dashboard administration | Untrusted client can reach the listener; v2.6.0 defaults bind all interfaces. | Read results/integration settings, change jobs/settings and invoke scanner-native capabilities, including Nmap output-file options. | Medium; restrict ingress, bind loopback and use authenticated access. v2.6.0 has no application authentication; see the v2.6.1 mitigation below. |
| Stored HTML/script injection through profile description | Attacker can save a profile that an operator later views. | Script runs in the dashboard browser origin. | Medium; restrict profile writers and use isolated operator access until rendering is fixed. |
| SMTP peer certificate not validated | Email configured and an active intermediary/forged SMTP endpoint is possible. | SMTP credentials and scan reports may be disclosed. | Medium; disable email or use a separately authenticated protected transport pending a validating TLS-context fix. |
| Ambient `.netrc` credentials in core web probes | Scanner account has a matching/default credential entry. | Credentials may be sent without explicit per-scan consent, including HTTP or unchecked HTTPS. | Medium; use a dedicated account without such credentials until all probe paths suppress ambient authentication. |
| Slow streaming defeats total request duration/Stop | Selected hostile target trickles data before inactivity timeouts. | Retained scan workers and occupied verification slots. | Medium; isolate scan processes and impose external time limits pending bounded transport reads. |

These are **five confirmed source-backed issues**, all still open in the assessed
release. Conditional reachability/credential/active-interception prerequisites
limit severity; high impact alone was not treated as proof of high likelihood.
The [advisory index](SECURITY_ADVISORIES.md) records affected versions, source
locations, mitigations and fix status. No runtime fix is claimed for that released snapshot.

### Local remediation update — 2026-10-16

v2.6.1 fixes findings AUTOPWN-SA-2026-002 through 005:
profile HTML escaping, validating SMTP TLS contexts, anonymous diagnostic HTTP,
and deadline/cancellation-aware response transport shared with portable replay.
Focused tests include malicious saved metadata, real loopback SMTP certificates,
synthetic `.netrc` entries and slow HTTP/HTTPS headers/chunks/bodies/trailers.
These changes are not present in v2.6.0 and do not rewrite the original assessment.
Finding 001 was left unchanged at the maintainer's earlier request for
trusted-operator use; later changes in v2.6.1 address it, as described next.
See the [advisory index](SECURITY_ADVISORIES.md) for current status and fixed versions.

### Dashboard authentication and secure defaults (v2.6.1)

After the update above, further changes in v2.6.1 (also absent from v2.6.0) add a
sign-in requirement for the dashboard and change several defaults: a single
administrator account stored as a scrypt hash, server-side revocable 8-hour
sessions, CSRF tokens, same-origin checks, failed-login rate limiting, HTTPS
required for non-loopback clients, and a `127.0.0.1` default bind; web scan
requests verify target certificates by default (`--insecure-tls` opts out); and
NVD/SMTP/webhook secrets can be read from `*_FILE` credential files. Finding 001
is therefore **fixed in v2.6.1** (the maintainer decided on 2026-10-16 that these
changes close it); v2.6.0 remains affected. Residual limits are one shared
administrator account without MFA,
plaintext-at-rest settings unless credential files are used, and operator-provided
HTTPS for remote access. This code is not covered by the original independent
assessment. The original v2.6.0 assessment above is not rewritten.

## Controls checked and candidate dispositions

- Nmap uses an argv list and `shell=False`, rejects option-prefixed targets and
  scanner-owned XML-output replacement, and cleans up its owned process.
  Powerful custom Nmap options are trusted operator functionality. Their
  unauthorized use belongs to dashboard administration exposure, not a separate
  shell-injection or arbitrary-content RCE finding.
- Web redirects are checked before following and remain on the permitted origin,
  apart from documented initial same-host HTTP-to-HTTPS discovery. Arbitrary
  operator-selected targets are intrinsic scanning behavior, not a separate
  generic SSRF finding.
- Recorded-plan replay accepts no client-supplied code/plan, validates methods,
  origins and headers, disables ambient session environment and clears cookies.
  These stronger controls do not extend automatically to other HTTP consumers.
- Local CVE lookup uses read-only snapshots, escaped search patterns and bound
  SQL parameters. Feed updates validate structure, hashes/sizes and staging
  completion before replacement. Integrity metadata shares the provider's HTTPS
  trust boundary; it is not an independent feed signature.
- Exploit reference downloads construct numeric provider URLs and sanitize
  filenames/path components. They save bytes without an execution step.
- PoC generation quotes/serializes data rather than evaluating submitted code.
  Downloading a PoC does not itself execute it or verify full exploit impact.
- PR tests have read-only workflow permissions and no publishing credentials.
  Privileged release/dispatch workflows are separate from PR execution.
- No purpose-backed embedded private key or credential was found in reviewed
  tracked text. Synthetic test values were assessed in context; real credential
  validity and image contents were not tested.

## Follow-up and reassessment

Prioritize the administrative boundary and browser rendering, then credential
transport/probe isolation and bounded request duration. Fixes need focused
regressions and updated advisory status. Reassess after authentication, outbound
HTTP, subprocess, persistent-storage or release-pipeline changes, and before
releases with new interfaces. The maintainer owns tracking under
[GOVERNANCE.md](../GOVERNANCE.md) and coordinates reports under
[SECURITY.md](../SECURITY.md).
