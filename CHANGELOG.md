# Changelog

Release notes describe functional changes and security-relevant behavior.
Confirmed vulnerabilities and mitigation status are tracked separately in
[Security advisories](docs/SECURITY_ADVISORIES.md). The entries below backfill
existing release summaries; they do not retroactively claim artifact signing.

## [Unreleased]

## [2.7.0] - 2026-10-19

### Functional changes

- Add installation methods besides a source checkout and Docker. The package is published to
  PyPI, so `pipx install autopwn-suite` (or `uv tool install autopwn-suite`) installs the
  `autopwn-suite` command. Each release also carries standalone single-file binaries for Linux
  (amd64 and arm64), Windows (amd64) and macOS (arm64) that need no Python installation. Nmap is
  still required for network scans and is not bundled; the CLI still offers to install it.
- **Breaking:** the code now lives in the `autopwn_suite` package instead of the top-level
  `modules`, `api` and `autopwn` modules. Use `from autopwn_suite import AutoScanner` (the
  repository-root `api.py` and `autopwn.py` remain as launchers for source checkouts, so
  `python autopwn.py` and `from api import AutoScanner` keep working there). Imports of
  `modules.*` must be changed to `autopwn_suite.*`. `python -m autopwn_suite` also works.
- **Breaking:** the dashboard account, settings, profiles, schedules and the local CVE database
  now default to a per-user directory (`~/.local/share/autopwn-suite`,
  `%LOCALAPPDATA%\autopwn-suite` or `~/Library/Application Support/autopwn-suite`) instead of
  the package directory. `AUTOPWN_DATA_DIR` still overrides it, so the supplied Compose
  deployment is unchanged. Existing files are not migrated: move `web_ui_*.json` and
  `vulnerabilities.sqlite3` from the old `modules/` directory (for installs made with
  `install.sh`, `/opt/autopwn-suite/modules/`), or set `AUTOPWN_DATA_DIR` to that directory.
  The root-owned daemon uses the root account's directory unless `AUTOPWN_DATA_DIR` is set.
- `install.sh` now creates the virtual environment, installs the dependencies and installs the
  package from the checkout instead of copying the source tree to `/opt/autopwn-suite`, and
  `$BINDIR/autopwn-suite` is a link to the command in that environment rather than a wrapper
  script. `PREFIX`, `BINDIR`, `APPDIR`, `DESTDIR`, `PYTHON` and `REQUIREMENTS_FILE` keep working;
  with `DESTDIR` the source is staged in `$APPDIR/src`.
- `--daemon-install` no longer copies source files or builds its own virtual environment. The
  systemd unit starts the installation that ran it (`python -m autopwn_suite`, or the standalone
  binary) with the configuration kept in `/opt/autopwn-suite/autopwn-daemon.conf`; run it from an
  installed copy. It now refuses to install unless that installation is root-owned (see Security
  changes), so a pipx or user-owned virtual environment is rejected. A daemon installed by 2.6.x or
  earlier keeps running its own copy of the old source until you run `sudo autopwn-suite --daemon-install`
  once more (it asks for the configuration again) and restart the service; `install.sh` now warns when
  it finds such a service (`SYSTEMDDIR` names the directory it checks).
- Remove the `test` and `tests` Poetry scripts, which a published package would have installed as
  commands on every user's PATH. Run the tests with `poetry run pytest`.
- Build the wheel and the standalone binaries on every pull request and run an install smoke test
  (`scripts/smoke_install.py`) on Linux, macOS and Windows.
- Link the documents and screenshots in `README.md` with absolute GitHub URLs. PyPI shows the README
  as the project description and cannot resolve relative paths, and a published description cannot be
  edited.
- Interactive confirmations accept "no" and "yes" (any case, surrounding spaces ignored) and ask
  again after an unrecognized answer, instead of treating everything except a bare "n" as yes. The
  Nmap install prompt now shows `[Y/n]`.
- Service banners, NVD descriptions and Exploit-DB metadata that look like Rich markup (for example
  `[/bold]`) are printed literally instead of aborting the CLI scan or failing the dashboard job.
- A host that hits `--host-timeout` is reported as timed out with incomplete port coverage by the
  CLI log and the Python API (`timedout: True` on that host's result) instead of looking like a host
  with no open ports.
- Dashboard scans (and profiles and schedules) run without root no longer make Nmap quit with
  "requires root privileges": raw-socket scan techniques and `-O` are dropped with a log warning
  and Nmap's unprivileged connect scan is used.
- Online NVD lookups are cached for one hour instead of for the life of the process, so long-running
  dashboards and scheduled scans see newly published CVEs. The cache is thread-safe.
- With `--vuln-source auto`, the requested email or webhook report is still sent when NVD is
  unavailable and the scan falls back to the local database. `--offline` and `--vuln-source
  offline` still send none.
- On Windows the CLI no longer fails with `UnicodeEncodeError` when its output is redirected or
  piped; redirected output is written as UTF-8. This matters for the `pipx` and `pip` installs.
- `--create-config` and `--daemon-install` no longer crash when a password, API key or URL contains
  `%`.
- Directory and exposed-file discovery also runs under the path you asked for when the target
  redirects elsewhere (for example `/` to `/index.php` or `/en/`), so root files such as `/.env`
  and `/.git/HEAD` are no longer skipped. A landing page that is a file (`/index.php`) scopes
  discovery to its directory. A deliberate sub-path target such as `http://host/app/` still scopes
  discovery to `/app/`.
- The dashboard shows an invalid or rejected scan target, a failed Start Scan request and a failed
  Stop in a toast as well as in the Terminal tab.
- The dashboard no longer shows every log line twice on page load and again after each reconnect:
  `GET /api/events` sends only entries added after the connection opens (history is on
  `GET /api/log`) and the terminal keeps the newest 2000 lines. Lines logged while the stream is
  disconnected are not replayed; reload the page to see them.
- `install.sh` checks that `PYTHON` is 3.10 or newer and can create virtual environments before it
  changes anything, sets the existing environment aside while the new one is built, and restores it
  if the build fails or the script is interrupted, so a failed upgrade (no network, no matching
  wheel, no `python3-venv`) leaves the working installation and its command link in place.
- `install.sh` no longer aborts, or leaves a nested copy, when `DESTDIR` is inside the checkout (for
  example `DESTDIR="$PWD/pkgroot"` or `debian/tmp`); that directory is left out of the staged source.
- The Docker documentation says that a port published from Docker's bridge network reaches the
  dashboard from the bridge gateway, not from loopback, so signing in over plain HTTP needs
  `--network host` with `AUTOPWN_WEB_HOST=127.0.0.1` (as `docker-compose.yml` does) or a TLS
  reverse proxy that keeps `Host` with `AUTOPWN_WEB_SECURE_COOKIE=1`.

### Security changes

- Stop writing the webhook URL, which is a credential, into logs and reports when a delivery fails
  (AUTOPWN-SA-2026-006, affects v2.6.0 and v2.6.1). The CLI console and saved reports, the dashboard log
  history (`/api/log`, `/api/events`) and the server log now carry only the exception class and HTTP
  status instead of the `requests` message that quotes the full URL. Rotate a webhook URL that has
  appeared in a log or report.
- Require `cryptography>=50.0.0` (it was `>=46.0.0`): earlier releases have known vulnerabilities,
  including the OpenSSL bundled in older wheels, and a plain `pip install` of the package or
  `requirements.txt` could keep an old copy. The locked version was already 50.0.2.
- Keep dashboard credentials and the CVE database out of the installed package directory, which is
  shared or read-only for a system installation and is discarded by single-file binaries. The
  per-user data directory is created readable only by its owner where the platform supports it.
- `install.sh` warns when a root daemon installed by an earlier release still runs its old copied
  source, which would otherwise keep running without the fixes in this release.
- `--daemon-install` refuses to create a root systemd service from an interpreter, package directory
  or `/opt/autopwn-suite` that an unprivileged user could modify (anything not owned by root, or
  writable by group or others, including every parent directory and symlink target). Without this a
  user-owned installation would let that user run code as root at the next service start.
- Install `install.sh` dependencies without a second copy of the application source under `/opt`,
  and keep `REQUIREMENTS_FILE=requirements-locked.txt` for hash-verified installs.
- Build the standalone binaries reproducibly. `scripts/build_binary.py` uses the CPython that
  `packaging/build-python.json` pins by SHA-256 (a self-contained python-build-standalone archive, so no
  library of the build machine is bundled), installs the hash-pinned dependencies (`requirements-locked.txt` and
  the universal, hash-pinned `packaging/requirements-build.txt`, with fixed wheel platform tags so the machine's
  glibc cannot change which build of a package is used) into a virtual environment of it and runs
  PyInstaller with `PYTHONHASHSEED=1` and the commit time as `SOURCE_DATE_EPOCH`. Pull requests and releases
  build every binary twice on its runner and fail unless both builds are byte-identical, so anyone can rebuild
  a binary from the release source and compare its SHA-256 with `SHA256SUMS`. Every binary is smoke-tested on
  the runner that built it and published only through the signed release workflow. The release manifest
  binds the binaries, `SHA256SUMS` and one CycloneDX SBOM per binary; `SHA256SUMS` also has its own
  Sigstore signature. Each SBOM is generated from that platform's build environment (installed
  packages, PyInstaller, CPython and its python-build-standalone release) rather than by scanning the
  executable. The binaries are not code-signed for Windows or macOS.
- Publish a signed SLSA v1 provenance attestation (`autopwn-suite-vVERSION.intoto.jsonl`) with each
  release; its subject is the release manifest, which binds every release file. It is self-attested by
  the release workflow, not produced by an isolated builder.
- Run ClusterFuzzLite (Atheris) fuzzing of the Nmap XML parser, the dashboard option schema and the
  account validation on pull requests that change the code (`fuzz/`, `.clusterfuzzlite/`).
- Publish the PyPI package through trusted publishing (no stored token) with PEP 740 attestations,
  after the same security and dynamic-analysis workflows as the container release. The wheel and
  source distribution are built twice from a pinned backend (`poetry-core==2.5.0`) and hash-pinned
  tools and are published only if both builds are byte-identical.
- Give the container build the release commit time as `SOURCE_DATE_EPOCH` (the validation job computed it but
  never exported it, so the build received an empty value), push the image only after the standalone binaries
  have been built so that a failed binary build leaves no unsigned image or moved `latest` tag, and extract the
  release source archive on Windows with a destination path that GNU tar can read. Pull requests now build the
  binaries from a `git archive` of the commit through the same source-archive handoff as the release.
- Install the policy's static-analysis tool (`bandit`) from a hash-pinned requirements file, and scan
  the pinned release build tools (PyInstaller, the wheel build tools and bandit) for known
  vulnerabilities in the security policy, and bundle `LICENSE`, `NOTICE` and the metadata of every
  packaged dependency in the standalone binaries.
- Bound the regular expressions that read target response bodies. A target controls every body and
  `re` holds the interpreter lock while it matches, so a hostile body (for example `/.env` with
  100,000 newlines, or a page repeating `microsoft odbc `) could freeze a scan, its Stop button and
  the whole dashboard for minutes. The checks now use bounded gaps and read a capped part of the
  body, and a test feeds 100 KB to 1 MB hostile bodies to each of them.
- `FLASK_DEBUG` in the environment no longer enables the Werkzeug debugger: with it set, the
  interactive `/console` and the debugger resources were reachable without sign-in, so every
  dashboard route requires sign-in again.
- The daemon configuration (SMTP password, NVD key, webhook URL) is created and installed with mode
  0600 instead of 0644, so other local users cannot read it (POSIX; Windows has no POSIX modes).
- A failed webhook delivery logs only the HTTP status and a failed dashboard email only the exception
  class: webhook response bodies (which can echo the secret URL path or carry terminal escape
  sequences) and SMTP error text no longer reach the console, the daemon log or the dashboard log.
- The sudo Nmap install offer and the exploit download can no longer be accepted by an answer such as
  "no" or "nope".
- Four silent gaps in coverage or reporting are closed: a host that timed out reported as clean, stale cached NVD
  results in long-lived scans, root-level files skipped behind a redirecting front page, and notifications
  dropped after an NVD fallback. A hostile banner can no longer crash a scan through Rich markup.
- The loopback and Origin checks are unchanged; the Docker documentation now states that
  publishing to loopback keeps the port off the network but does not make a bridge-published port
  loopback for sign-in.

## [2.6.1] - 2026-10-16

### Functional changes

- **Breaking:** require sign-in for the web dashboard. A single administrator account is
  kept in `web_ui_auth.json` (username and scrypt password hash). A random `admin`
  password is generated and printed once on first launch; change it in Settings
  (Account, which needs the current password) or regenerate it with
  `--web-reset-account`, which also invalidates every session. Existing API clients
  and scripts must sign in (`/api/auth/login`) and send the session CSRF token on
  non-GET requests.
- **Breaking:** the dashboard now listens on `127.0.0.1` by default (previously
  `0.0.0.0`). The supplied `docker-compose.yml` sets `AUTOPWN_WEB_HOST=127.0.0.1`;
  the Docker image still sets `0.0.0.0` inside the container, so publish its port to
  loopback only (`-p 127.0.0.1:8080:8080`). Remote access needs an explicit
  `--web-host`/`AUTOPWN_WEB_HOST` and HTTPS: clients that are not loopback are
  refused over plain HTTP, or set `AUTOPWN_WEB_SECURE_COOKIE=1` behind a
  TLS-terminating reverse proxy.
- **Breaking:** web scan requests now verify target TLS certificates by default.
  Scans of targets with self-signed or otherwise untrusted certificates need the new
  `--insecure-tls` option (INI `insecure_tls`, or the dashboard's "Accept untrusted
  certificates" checkbox, web option `verify_tls`). The choice is recorded with each
  finding and honored by generated Python and curl PoCs and by replay.
- Read the NVD key, SMTP password and webhook URL from files named by
  `AUTOPWN_NIST_API_KEY_FILE`, `AUTOPWN_SMTP_PASSWORD_FILE` and
  `AUTOPWN_WEBHOOK_URL_FILE` (one line, at most 4096 bytes), at use time so
  rotation needs no restart. `api.txt` remains supported.
- Make the container build repeatable: the Dockerfile pins the base image digest and a
  Debian snapshot and installs hash-pinned `requirements-locked.txt` (generated from
  `poetry.lock` by `scripts/export_locked_requirements.py`), and honors
  `SOURCE_DATE_EPOCH`. `install.sh` and `uninstall.sh` honor `PREFIX`, `BINDIR`,
  `APPDIR` and `DESTDIR` for packagers; defaults are unchanged.
- Add a pinned Python lint gate (Ruff rules E, W, F, B, I at 200 columns), ESLint and
  JavaScript syntax checks and the locked-requirements check to the required Poetry
  CI job; project-originated Deprecation, Future and Syntax warnings are errors
  under pytest. See [coding standards](docs/CODING_STANDARDS.md), with local commands
  and Passing badge evidence documented.
- Consolidate release notes, SBOMs and security reports into one verified ZIP,
  keeping new release publications to five files including source and signatures.
- Refresh the original independent-human approval checks after review changes,
  avoiding duplicate approval checks and stale failures after approval.
- Document project governance, dependency selection, source builds, architecture,
  all external interfaces, release operations and security-assessment results.
- Add documents for the [roadmap](docs/ROADMAP.md), [continuity](docs/CONTINUITY.md),
  [accessibility](docs/ACCESSIBILITY.md), [internationalization](docs/INTERNATIONALIZATION.md),
  [coding standards](docs/CODING_STANDARDS.md), the assurance case
  (`docs/ASSURANCE_CASE.md`) and the [regression-test ledger](docs/REGRESSION_LEDGER.md).
- Add an SPDX license identifier and copyright notice to every source file.
- Add an OWASP ZAP baseline scan of the running dashboard (unauthenticated and authenticated passes) that
  runs on pull requests and gates image publication, plus seeded fuzz tests for the parsers, validators
  and login endpoints. The first ZAP run found missing security headers, now fixed.
- Limit the blocking vulnerability gate to Python requirements. Operating-system packages in
  the base image are still inventoried and reported but no longer block a release; known
  malicious packages still block in any ecosystem.
- Prepare official source archives from reviewed version tags and publish
  descriptive version notes alongside a signed release manifest.

### Security changes

- Fix profile metadata HTML injection, enforce certificate/hostname validation
  for SMTP TLS, suppress ambient credentials in all diagnostic web requests,
  and interrupt slow HTTP/HTTPS responses on deadline or scan Stop. Evidence
  replay uses the same bounded transport, including standalone downloads.
  These fixes address AUTOPWN-SA-2026-002 through 005; dashboard access is covered by
  the next entries.
- Fix AUTOPWN-SA-2026-001 (unauthenticated dashboard administration) with
  a loopback default bind, sign-in on every route by default,
  scrypt password hashing, server-side revocable 8-hour sessions in an `HttpOnly`,
  `SameSite=Strict` cookie, per-session CSRF tokens on non-GET requests, same-origin
  `Origin` checks (CORS is no longer enabled), failed-login rate limiting with
  bounded hashing capacity, HTTPS required for non-loopback clients, and no-store,
  nosniff, frame-deny, Content-Security-Policy (strict on the sign-in page; same-origin with
  inline code still allowed on the dashboard), Permissions-Policy and cross-origin isolation
  response headers, with the server version no longer disclosed. Residual limits are one shared administrator account, no MFA,
  plaintext-at-rest settings and operator-provided HTTPS for remote access.
  The maintainer decided on 2026-10-16 that this closes the advisory; v2.6.0 and
  earlier remain affected.
- Verify target certificates by default for core, crawl, directory, probe and
  evidence-replay web requests, which previously accepted any certificate. TLS
  diagnostics still inspect untrusted certificates and legacy protocols without
  trusting them and send no HTTP request or credentials.
- Credential files keep NVD, SMTP and webhook secrets out of the dashboard's
  `web_ui_settings.json`, which otherwise stores them in plaintext.
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
- The assessment identifies existing runtime issues. The infrastructure changes do
  not themselves fix them; local fixes and mitigations (none released) are listed
  above. See the assessment and advisory status.

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
