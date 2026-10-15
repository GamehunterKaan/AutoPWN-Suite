# Changelog

Release notes describe functional changes and security-relevant behavior.
Confirmed vulnerabilities and mitigation status are tracked separately in
[Security advisories](docs/SECURITY_ADVISORIES.md). The entries below backfill
existing release summaries; they do not retroactively claim artifact signing.

## [Unreleased]

### Functional changes

- Document project governance, dependency selection, source builds, architecture,
  all external interfaces, release operations and security-assessment results.
- Prepare official source archives from reviewed version tags and publish
  descriptive version notes alongside a signed release manifest.

### Security changes

- Add a reviewed authenticity-backfill workflow that signs original release
  bytes and publishes current SBOMs/findings without rebuilding or replacing
  images; new-release and rebuild security gates remain mandatory.
- Add keyless Cosign signing and verification for release manifests and exact
  container digests, using restricted release-job permissions and pinned actions.
- Define coordinated disclosure response targets and a predictable public
  vulnerability-information channel.
- Require CI results through repository branch settings; these settings must be
  verified separately from the documentation/workflow change.
- Add fail-closed OSV/Bandit policy checks, version-specific VEX handling,
  dependency license review, and independent human approval enforcement.
- Build and inspect each container architecture before publication, attach
  CycloneDX SBOMs, and bind SBOM/VEX hashes into the signed release manifest.
- Publish a threat model, credential access/rotation policy, support lifecycle
  and end-of-life rules. Separate build, registry, signing and upload privileges.
- The assessment identifies existing runtime issues; this infrastructure change
  does not claim to fix them. See the assessment and advisory status.

## [2.6.0] - 2026-10-15

### Functional changes

- Add a dedicated web-security dashboard, website-only scans, selectable checks,
  evidence details, PoC downloads, explicit verification and report exports.
- Resume incomplete/stopped scans while retaining completed checks, findings,
  discovery and successful CVE work. Save independent web pacing and coverage
  controls in profiles and schedules.
- Replace the Python Nmap wrapper with the native XML/subprocess adapter shared
  by CLI, Python API and dashboard, including progress, cancellation and cleanup.
- Preserve timed-out hosts and failed crawl pages as incomplete so Resume can
  retry them; retain redirect evidence and replay the final scoped URLs.

### Security changes

- Replay uses stored same-origin evidence plans, rejects missing redacted input,
  limits concurrency and remains disabled in offline mode.
- Resume returns stable public validation errors rather than raw exceptions;
  findings capture diagnostic metadata with sensitive URL fields redacted.
- Document intentional legacy-TLS diagnostic handshakes and distinguish
  candidate findings from confirmed exploit impact.
- Existing risks discovered after release are listed in the security advisory
  index; this release must not be described as free of known vulnerabilities.

[Merged changes and validation](https://github.com/GamehunterKaan/AutoPWN-Suite/pull/81).

## [2.5.0] - 2026-10-09

### Functional changes

- Add an explicit portable NVD database download, status, offline lookup and
  database export/transfer workflow.
- Add live scan progress and cancellation through the dashboard and Nmap adapter.

### Security changes

- Explicit offline mode disables internet integrations while retaining requested
  target scans, and prevents automatic dependency/database downloads.
- Validate NVD feed records, decompressed hashes/sizes and readiness before
  atomically replacing the usable local database.

[Merged changes](https://github.com/GamehunterKaan/AutoPWN-Suite/pull/79).
