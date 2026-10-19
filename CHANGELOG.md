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
- The dashboard shows every log line exactly once, also across a page load and a reconnect. Log
  entries carry an increasing id; `GET /api/events` resumes after the id in `Last-Event-ID` (a browser
  reconnect) or in the `after` query parameter (the first connection, after `GET /api/log`), and without
  a resume point it still sends only entries added after the connection opens. The terminal keeps the
  newest 2000 lines. The page reopens the stream, with a pause that grows from 1 to 30 seconds, after the
  browser gave up on it following an HTTP error such as a proxy restart.
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
- IPv6 targets are scanned: Nmap's `-6` is added when every target is an IPv6 address or prefix, instead
  of reporting an up host as offline or finding no hosts. One Nmap run cannot scan both address families,
  so a mixed list must be split, and as root an evade-mode scan (`-f`) of IPv6 targets stops with Nmap's
  own error.
- Generated report file names contain only letters, digits, `.`, `_` and `-` (other characters of the
  target become `_`, at most 100 characters), so scans of `192.168.*.*`, IPv6 addresses or `host:port`
  targets can save their report on Windows.
- Noise mode ends each host's Nmap process when the noise duration passes or the scan is interrupted (it
  used to leave `nmap -A -T 5` running) and samples at most 32 live hosts, with a log warning on a larger
  network.
- A missing or unreadable `-c` config file, a declined Nmap install and a failed `winget` install exit with
  status 1 instead of 0. The Nmap install offer runs `brew install nmap` without `sudo` on macOS, reports a
  missing `sudo` instead of a traceback, never prompts under `-y` and stops with status 1 when the
  installation fails. `--version` and `--help` no longer crash when the per-user data directory cannot be
  created, and `--web-port` and `AUTOPWN_WEB_PORT` are validated (1 to 65535) with a usage error instead of
  a traceback.
- `api.txt` and the `AUTOPWN_*_FILE` credential files ignore a leading UTF-8 byte order mark (written by
  Windows PowerShell), and `api.txt` ignores spaces around the key. In the Python API an `AutoScanner`
  `nmap_args` list keeps every item as one Nmap argument, so values with spaces or Windows paths are not
  split.
- The dashboard rejects Nmap options that name an output, input or data file (`-oN`, `-oG`, `-oS`, `-oM`,
  `-oX`, `-oA`, `-o`, `-m`, `-iL`, `-i`, `--excludefile`, `--datadir`, `--servicedb`, `--versiondb`,
  `--stylesheet`, `--resume` and `--append-output`) with HTTP 400 in any spelling, abbreviation or
  short-option cluster. Single-dash spellings of long options that start with `o`, `i` or `m`, such as
  `-max-retries`, are refused too: write long options with `--`. A profile or schedule stored with such an
  option has to be edited before it can be changed: until then `PUT /api/profiles/<id>` answers 400, and a
  schedule that uses it is disabled when it next comes due (enable it again after the edit).
- When NVD lookups fail and no local vulnerability database is ready, the scan stops with exit status 1 and
  a message that names both failures. A scan that stops on a runtime error during lookup or host discovery
  (for example a failed Nmap host discovery) saves the output recorded so far instead of discarding it,
  and the reason is still the exit message on stderr; a failed Nmap port scan still ends the scan without
  saving. A saved partial report goes to the usual output file, so it replaces an earlier report with the
  same name.
- Vulnerability database updates retry each feed request up to three times on network errors, 429 and 5xx
  answers instead of discarding the whole download, and skip a newest-year feed that NVD has not published
  yet (404) when that year was never indexed: the last message names the year, and the database lacks that
  year's CVEs until a later update indexes them. An update removes the staging file and SQLite journal that
  an earlier, hard-killed update of the same database left behind (staging files of earlier releases have a
  different name and have to be deleted by hand), including for a database whose file name is not valid
  UTF-8 on POSIX.
- On Windows, an update that cannot replace the mirror because a running scan or another program has it
  open stops before downloading when a scan is already running, keeps the previous database and asks you to
  close running scans (the dashboard no longer blames the connection). A scan that opens the database during
  the download blocks the final replace, which is retried for a few seconds before the download is
  discarded. A read-only database file is reported the same way and the message asks you to make it
  writable. `--vuln-db` and the dashboard also accept a database on a UNC (network share) path.
- A CVE that NVD scores with CVSS v4 reports the exploitability sub-score of the newest older CVSS version
  that has one instead of 0.0 (each keeps its own scale: up to 3.9 for v3, up to 10.0 for v2); 0.0 now
  means that no sub-score is available.
- A vulnerability database copied from another machine with malformed or oversized records makes the lookup
  fail with "database coverage is incomplete" instead of crashing the scan.
- A daemon whose host discovery finds nothing waits for its next scan interval (and sends no empty report
  and writes no empty output file) instead of exiting, which made systemd restart it and repeat the
  discovery every five seconds.
- `--daemon-install` and `--create-config` ask again for a scan speed outside 0-5, a negative scan interval
  or host timeout, an email port outside 1-65535, an output type other than html, txt or svg (in any letter
  case) and an empty webhook URL, instead of writing a configuration that makes the daemon exit and restart
  every five seconds. `--daemon-install` checks that the installation is usable before it asks its
  questions (a source checkout started with `python autopwn.py` and pipx environments are refused; the
  README no longer recommends pipx for the daemon) and restarts the service when it runs again, so a new
  configuration, or a release 2.6 daemon, moves onto the installed program.
- `--daemon-uninstall` stops and disables the service and removes its unit file and
  `/opt/autopwn-suite/autopwn-daemon.conf` (as root on Linux; it exits 1 otherwise or when a file cannot be
  removed); before it only printed the banner. The program, the log file and other files in
  `/opt/autopwn-suite` stay. `uninstall.sh` no longer stops at a failing `systemctl daemon-reload` (no
  running systemd, as in a container).
- `install.sh` run as root hands the application directory to root (also when an earlier run as a normal
  user created it), so `--daemon-install` accepts it; run as a normal user it says that the installation
  belongs to that user. A second run as a normal user no longer fails at the command link when `BINDIR`
  belongs to root.
- The standalone Linux binary starts Nmap, `ip`, `systemctl` and the package manager that installs Nmap
  with the library path it was launched with, not the one that points into its unpacked bundle, so they load
  the system's libraries. The container exits on SIGTERM, so `docker stop` and `docker compose down` return
  at once instead of after Docker's ten second kill timeout.
- A completed dashboard scan releases its Nmap results and lookup caches (a /24 scanned with `-sV -O` held
  about 15 MB per job, up to 100 finished jobs); stopped, partial and failed scans keep them for Resume.
  `GET /api/scans` no longer answers HTTP 500 when a scan thread updates the job configuration at the same
  moment, and `HEAD /api/events` no longer leaves an event-stream subscriber behind.
- A dashboard scan that falls back to the local database because NVD is unreachable still runs its web
  checks, sends its email and webhook notifications and allows Verify evidence; only an offline mode you
  chose (CLI `--offline`, the Settings toggle or the scan's own offline source) skips them.
- Schedules: a schedule does not start a new scan while the one it started last is still running or
  stopping (it logs one skip). Editing a profile disables the schedules that no longer fit it, and a due
  schedule that fails validation is disabled and logged once, in the dashboard log and as a one-line
  server-log warning with the schedule id, instead of failing every minute; `PUT /api/schedules/<id>` with
  `{"enabled": false}` switches any schedule off. A daily or weekly schedule whose time was missed by a
  restart, suspend or slow check still runs once when the check comes within an hour of that time, but not
  for a time that passed before the schedule was created, enabled again or retimed. In offline mode a
  scheduled scan with web checks is skipped with one log line (as a manual start is refused with 409)
  instead of finishing as an empty "completed" scan. A hand-edited schedule time that cannot be converted to
  UTC is ignored.
- A profiles or schedules file the dashboard cannot load is logged and kept as `<name>.corrupt-<timestamp>`
  (one copy of an identical file) instead of being overwritten by the next save, and one invalid entry no
  longer discards the valid ones. On Windows `--web-reset-account` and account changes retry for about a
  second when the running dashboard has the account file open instead of failing with `PermissionError`.
  The README says that a TLS reverse proxy must pass the `Host` header through, or sign-in is refused as
  cross-origin.
- Sign-in: a lone-surrogate username is rejected with 401 like any wrong username instead of failing with
  HTTP 500, and a request body of deeply nested JSON is handled as malformed JSON by every dashboard route
  instead of failing with HTTP 500.
- Web checks no longer stall on hostile targets: the reflected-XSS check and the downloadable PoC's HTML
  parser read deeply nested pages in time proportional to their size, directory-listing detection reads
  only the start of the first few headings, response-body comparisons (boolean SQL injection, directory
  discovery, the PoC) compare a shorter prefix of a hostile body of many different characters (ordinary
  pages are compared exactly as before), and recording findings no longer copies all the earlier ones for
  each new one. The crawler's resume checkpoint keeps at most 10,001 links per crawled page, in crawl order
  and without links it would never follow, and at most 4 million characters of links in all (a page past
  that is crawled but read again on a resume). The crawler does not follow a link or form URL longer
  than 8,192 characters (a server rejects it anyway), takes no links from a page whose `<base href>` is that
  long, and keeps at most 4 million characters of links per page; a page that exceeds one of these is
  reported as partly crawled. It analyses at most 100 forms, 2,000 form controls and 200,000 elements per
  page (reported as partly analysed, like a reached crawl limit), because a page of thousands of unclosed
  `<form>` or `<select>` tags made its form analysis quadratic and a long `<base href>` multiplied the
  length of every link. The Java stack-trace signature reads at most 1,000 characters before a frame and
  100 characters of a frame's file name; with an unbounded frame a 100 KB error page stalled a scan for
  over a minute.
- The dashboard's scan and profile forms no longer have an "Extra Nmap Flags" field; the scan technique and the ports
  are checked against fixed lists (see the Security notes), and the README no longer lists SCTP among the dashboard's
  scan techniques, which are the nine the forms offer.
- The Settings account form in the dashboard looks like the other forms: the username field is a dark input instead of a
  white box, the fields and the Update account button are spaced like the other Settings sections, the new and confirm
  password fields stack whenever the column is too narrow for both, and fields filled in by the browser keep the dark
  theme on the dashboard and on the sign-in page.
- Web scan log lines and coverage notes replace every query value of a URL with `REDACTED` and drop its userinfo
  and fragment (findings still redact credential-named parameters only, so that PoCs can be replayed), and the
  crawler logs a fixed message instead of the request exception. Text that a scanned host or a data provider
  controls is printed, saved and returned as one line without control, bidirectional or zero-width characters
  (a URL keeps them as percent-encoding, so a replay sends the request the scan sent). Query
  parameters that only contain "auth" or "pass" inside another word, such as `author`, `bypass` and
  `passenger`, are no longer redacted, so findings on them can be replayed as PoCs; credential names such as
  `auth`, `password`, `passwd`, `userpass`, `token` and `session` still are.
- A target host that cannot be IDNA-encoded (an empty or over-63-character label such as `example..test`)
  is reported as an unreachable web endpoint instead of aborting the scan, and web requests no longer fail
  with "filedescriptor out of range in select()" on Linux and macOS when more than 1,024 descriptors are
  open.
- The dashboard shows a vulnerability's severity as one of critical, high, medium, low or unknown (anything
  else is shown as unknown; the host badge and the severity filters follow the same mapping), and a missing
  severity no longer blanks the vulnerability table. A failed request while the dashboard loads no longer
  blanks the Settings forms: each section loads on its own, and the Save buttons for the NVD key, email and
  webhook stay disabled, with a notice, until the stored settings were read, so a later Save cannot replace
  the stored webhook URL, SMTP password or NVD key with empty values.
- Dashboard interaction: a double click on Start Scan starts one scan and the button keeps keyboard focus
  afterwards; live scan updates no longer rebuild the scan cards, so focus on Stop, Resume or Export
  survives and clicks on Stop are not lost; a faded toast no longer blocks clicks in the bottom-right
  corner; toasts are announced to screen readers through a polite live region; a start request answered
  with something other than JSON (for example an HTML 500 from a proxy) reports `Failed to start scan
  (HTTP <status>)` instead of "Cannot reach server". On windows narrower than 760 px the host detail panel
  is shown under the main area and selecting a host scrolls it into view. The Terminal tab keeps the
  reader's place when they scroll up, and its scan filter lists every scan, including scheduled ones. The
  dashboard polls scans and hosts every 1.5 s only while a scan is running, every 10 s otherwise and not at
  all in a hidden tab, and at once when the tab is shown again, a scan is started or a scheduled scan
  fires.
- Releasing: dispatching `publish-docker.yml`, `publish-pypi.yml` or the signature backfill by hand for a
  tag before v2.7.0 stops before anything is signed or published, with a message that names the missing
  build requirements file (only v2.7.0 and later can be dispatched). The PyPI workflow expects the PEP 440
  file names for a prerelease tag (`v2.8.0-rc.1` builds `2.8.0rc1`), and re-running the failed jobs of a
  release's `publish-pypi.yml` run skips files already on PyPI, so a partial upload can be completed (a run
  dispatched from `main` runs the gates and the build but cannot publish: the `pypi` environment admits
  only `v*` tags). `docs/RELEASING.md` lists the three signer identities (release run, recovery from
  `main`, authenticity backfill), `docs/SECURITY_TESTING.md` has a table of every workflow and describes
  the OWASP ZAP baseline scan and how to refresh its pinned image, and `GOVERNANCE.md` and `docs/SECRETS.md`
  record the identity and token handling of the Scorecard workflow.

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
- A failed webhook delivery logs only the HTTP status and a failed dashboard email only the exception
  class: webhook response bodies (which can echo the secret URL path or carry terminal escape
  sequences) and SMTP error text no longer reach the console, the daemon log or the dashboard log.
- Four silent gaps in coverage or reporting are closed: a host that timed out reported as clean, stale cached NVD
  results in long-lived scans, root-level files skipped behind a redirecting front page, and notifications
  dropped after an NVD fallback. A hostile banner can no longer crash a scan through Rich markup.
- The loopback and Origin checks are unchanged; the Docker documentation now states that
  publishing to loopback keeps the port off the network but does not make a bridge-published port
  loopback for sign-in.
- AUTOPWN-SA-2026-007: The dashboard writes its settings, profiles and schedules files owner-only (mode 0600
  on POSIX) instead of with the process umask, which exposed the SMTP password, NVD key and webhook URL in
  the settings file to other local users (affects v2.6.0 and v2.6.1). When it starts it also restricts such
  a file that an earlier release left readable, removes the leftover temporary file of an interrupted save
  and logs one fixed line, so an upgraded installation needs no chmod; the copy it keeps of a profiles or
  schedules file it cannot load is created owner-only too.
- AUTOPWN-SA-2026-008: A failed test email or scan-notification email writes only the exception class, not
  the SMTP server's reply with its host and account names, to the dashboard process's log output and the
  dashboard log (affects v2.6.0 and v2.6.1).
- AUTOPWN-SA-2026-009: A sign-in with a lone-surrogate username is an ordinary failed sign-in (HTTP 401) that
  counts toward the throttle, instead of an uncounted HTTP 500 that let one client keep both hashing slots
  busy and block other sign-ins (affects v2.6.1), and a request body of deeply nested JSON is handled as
  malformed JSON instead of ending in HTTP 500 on every dashboard JSON route (affects v2.6.0 and v2.6.1).
- AUTOPWN-SA-2026-010: Stops `FLASK_DEBUG` from enabling Werkzeug's debugger and the unauthenticated
  `/console` in the dashboard.
- AUTOPWN-SA-2026-011: A hostile web target can no longer stall a scan, or the whole dashboard where a regular
  expression held the interpreter lock, with a crafted response body: the regular expressions over bodies
  (including the Java stack-trace signature), deeply nested HTML, difflib body comparisons, recording
  findings, the crawler's form analysis and very long links are bounded, and the crawl checkpoint no longer
  grows with the links or the pages crawled (affects v2.6.0 and v2.6.1). The HTML parser of the standard
  library is still slow on some inputs in older Python releases; run a current patch release.
- AUTOPWN-SA-2026-012: The dashboard now shows a vulnerability's severity only as critical, high, medium,
  low or unknown and escapes its CVSS score, because an attacker-chosen severity from a poisoned NVD answer
  or a copied vulnerability database could run script in the dashboard origin (affects v2.6.0 and v2.6.1).
- AUTOPWN-SA-2026-013: The daemon installer creates the configuration that the wizard writes
  (--create-config and --daemon-install) and its installed copy owner-only from their first byte, through a
  temporary 0600 file that replaces the final name in one step, so a local user polling the directory during
  a first --daemon-install can no longer read the SMTP password, NVD key or webhook URL (affects v2.6.0 and
  v2.6.1). An older readable copy is replaced instead of being written into, a symlink planted at the file
  name is not written through, and the install directory is created with mode 0755 (never wider; an umask of
  000 used to give 0777).
- AUTOPWN-SA-2026-014: The web dashboard no longer accepts Nmap options at all. The "Extra Nmap Flags" boxes
  are gone from the scan and profile forms, a scan, profile or schedule request with a non-empty nmap_flags
  is refused with HTTP 400, scan_technique must be one of the techniques the forms offer, and ports must be
  port numbers from 1 to 65535, ranges and comma lists, so the Nmap file options and the NSE options
  (--script, --script-args, --script-args-file) can no longer reach Nmap from the dashboard, and a target
  that starts with a dash is refused as well (affects v2.6.0 and v2.6.1). A profile or schedule that an
  earlier release saved with Nmap options is kept but never used: a copy of the file is set aside at
  startup, and a schedule that uses the profile is disabled with a log line that names the reason, either
  when it next comes due or when the profile is saved again. Saving the profile removes the options (even
  when the request does not mention nmap_flags) and turns off the enabled schedules that use it, because
  they would otherwise run without those options; enable each schedule again by hand. The command line
  (--nmap-flags) and the Python API (nmap_args) keep their trusted Nmap options.
- AUTOPWN-SA-2026-015: Do not follow redirects when posting the CLI webhook report or the dashboard webhook
  events: a 307 or 308 re-sent the report or event to the origin named in Location, and any redirect answer
  is now a failed delivery.
- AUTOPWN-SA-2026-016: Text that a scanned host or a data provider controls (web finding text, log lines and
  coverage notes, response headers kept with a finding, Nmap banners, hostnames, script output and failure
  messages, certificate names, NVD and local-database descriptions, Exploit-DB details and file names) is
  now one line without control, bidirectional or zero-width characters wherever it is printed, saved,
  returned or sent, so a hostile target can no longer forge a result line (a folded Location header used to)
  or drive the terminal, and the txt, svg and html reports, the webhook and email reports, the dashboard job
  log and the API results carry the same text. A URL that a host controls (a crawled link, a redirect)
  cannot lose those characters, because replay and the PoCs must send the same request: it keeps them as the
  percent-encoding that the HTTP client sends, in the finding, its recorded requests, observations and
  target and in the generated curl and Python PoCs (affects v2.6.0 and v2.6.1; fixed). NSE script output and
  the OS fingerprint keep their newlines, the zero-width joiner and non-joiner and the Mongolian vowel
  separator are removed from scanned text, and a lone surrogate in provider text no longer ends a scan with
  a UnicodeEncodeError.
- AUTOPWN-SA-2026-017: Web scan diagnostics now replace every query value of a URL with REDACTED whatever
  the parameter is called, and drop its userinfo and fragment, for any case of the scheme and for a target
  typed without a scheme; a target is redacted as one string, so an apostrophe, a quote, an angle bracket or
  a Unicode space inside a URL can no longer leave a later part of its query visible. This covers the line
  that announces a web scan, log lines, coverage notes, the target shown in dashboard job records, exports,
  history, webhook events and emails, the CLI parameter summary and generated report file names; the target
  the scan runs and resumes with is unchanged. The dashboard's server log, job log and job error now name
  the class of an unexpected exception instead of quoting its text (a failed scan shows "Unexpected error
  (<class>)"). Findings still redact only credential-named parameters so that proof-of-concept replays keep
  working, now with a longer list of credential names (code, key, sig, sid, otp, pw, pwd, ticket, nonce,
  bearer, cookie and others), so a secret in a parameter with another name, in a URL path or nested inside
  another parameter's value is still shown in a finding. A raw space in a link of a page is written as %20
  when the scan reads it (the request on the wire is the same), so it no longer ends the URL in a log line
  and leaves the rest of its query visible.
- AUTOPWN-SA-2026-018: Inflate the stored records of a copied vulnerability database within size limits and
  check their types, so a hostile or damaged mirror ends the lookup as incomplete instead of using unbounded
  memory or crashing the scan (affects v2.6.0 and v2.6.1; NaN and Infinity scores and lone-surrogate text
  are still accepted).
- AUTOPWN-SA-2026-019: Rich markup in a service banner, NVD record or Exploit-DB record no longer aborts a
  CLI or daemon scan run or fails a dashboard job, because that text is now printed as text and not parsed
  as markup (affects v2.6.0 and v2.6.1).
- AUTOPWN-SA-2026-020: The interactive confirmations and the Nmap install offer declined only on a bare "n",
  so "no", "nope" or a padded "n" still ran the refused step, including the exploit download and the sudo
  Nmap install; an unrecognized answer is now asked again instead of being taken as yes.
- AUTOPWN-SA-2026-021: The dashboard sign-in challenge is now a signed cookie that the server does not
  store, so a flood of requests to the sign-in page, from one address or many, can no longer evict the
  operator's pending sign-in or use memory (affects v2.6.1); the per-address cap of 16 and the limit of 128
  pending challenges are gone, and a restart of the dashboard or a change of the account ends the sign-in
  challenges that are open, so the page asks for a new one.
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
