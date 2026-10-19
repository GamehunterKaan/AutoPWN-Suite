# External software interfaces

This describes the CLI, Python API, HTTP API, configuration, persistent
formats and outbound integrations of the current source tree. Items marked
*since v2.6.1* are not in v2.6.0. [Architecture](ARCHITECTURE.md) explains the
actors and trust boundaries. These interfaces are operator/admin capabilities,
not isolated accounts or a public multi-tenant service.

## CLI

Run `autopwn-suite --help` (or `python autopwn.py --help` from a source checkout) for the generated option
reference, types and defaults. `autopwn-suite` is also available after the Linux
installer links it. Arguments are parsed in `autopwn_suite/utils.py`.

| Options | Input and effect |
| --- | --- |
| `-h/--help`, `-v/--version` | Print usage or version and exit. |
| `-nc/--no-color` | Disable colored terminal output. |
| `-y/--yes-please` | Answer ordinary scanning confirmations automatically; it is not authorization to test another party's systems. |
| `-c/--config`, `--create-config` | Read an INI file or interactively create configuration. Present INI values are applied after argument parsing and overwrite matching parsed settings. A created file has mode `0600` from its first byte (POSIX), because it can hold the SMTP password, NVD key or webhook URL: it is written to a new temporary file beside it that replaces the final name in one step, so an existing file is replaced, never written into. |
| `--daemon-install`, `--daemon-uninstall` | Install/remove the Linux root systemd scanner service; privileged filesystem/service side effects. Installing asks for the configuration, writes `/opt/autopwn-suite/autopwn-daemon.conf` (created owner-only the same way, so no other user can read it while it is installed, and a copy that was readable is replaced) and the unit, then enables and restarts the service. Removing, as root on Linux, stops and disables the service and deletes the unit and that configuration; the program, `/var/log/autopwn-daemon.log` and other files in `/opt/autopwn-suite` stay. Removing exits with status 1 when it is not run as root on Linux or cannot delete one of those files. |
| `-t/--target`, `-hf/--host-file` | Target IP/hostname/range/CIDR or newline-separated target file; explicit target takes precedence over the host file. When every target is an IPv6 literal or prefix, Nmap's `-6` is added; one Nmap run cannot scan both address families, so a mixed list must be split. Nmap does not support fragmentation (`-f`) with IPv6, so as root an evade-mode scan of IPv6 targets stops with Nmap's error. |
| `-sd/--skip-discovery`, `-st/--scan-type` | Skip discovery, or choose `arp`/`ping` discovery. Privileges limit available techniques. |
| `-nf/--nmap-flags` | Trusted operator Nmap arguments; pass a single argument such as `-nf="-p 80,443"`. These expose native Nmap capabilities, not a restricted remote job language. The scanner owns the XML output, so `-oX`, `-oA`, `--resume` and `--append-output` are refused whatever their spelling (`--oX`, an abbreviation such as `--appe`). |
| `-s/--speed`, `-ht/--host-timeout` | Nmap speed 0–5 (default 3) and per-host timeout in seconds (default 240). |
| `-a/--api` | Optional NVD API key. Keep it out of committed files and shell history where possible. When omitted, `AUTOPWN_NIST_API_KEY_FILE` (since v2.6.1) names a one-line key file that is read at use time, before `api.txt`. |
| `-m/--mode`, `-nt/--noise-timeout` | `normal`, `evade`, or `noise`; optional noise duration. Raw-packet features depend on host privileges. Noise mode runs one Nmap per live host for at most 32 hosts, and ends those Nmap processes when the duration passes or the scan is interrupted. |
| `-sed/--skip-exploit-download` | Suppress optional exploit reference downloads. Downloading does not execute the files. |
| `--offline`, `--vuln-source`, `--vuln-db` | Force offline integration policy; select `auto`/`online`/`offline` CVE source; choose SQLite database path. Offline mode still sends requested Nmap target traffic. |
| `--update-vuln-db`, `--vuln-db-status` | Explicitly update the official local NVD mirror or print database readiness/freshness and exit. |
| `-o/--output`, `-of/--output-folder`, `-ot/--output-type` | Explicit output path or generated file under an output directory; `html`, `txt`, or `svg`. Output defaults to `outputs/` relative to the working directory. A generated name is the date and the target with every character other than letters, digits, `.`, `_` and `-` replaced by `_` (at most 100 characters), so `192.168.*.*` or an IPv6 address also saves on Windows. |
| `-rp/--report`, `-rpw/--report-webhook` | Select `email`/`webhook` notification and webhook destination. When no destination is given, `AUTOPWN_WEBHOOK_URL_FILE` (since v2.6.1) names a one-line file holding it, before the interactive prompt. |
| `-rpe/--report-email`, `-rpep/--report-email-password` | SMTP username and password. When no password is given, `AUTOPWN_SMTP_PASSWORD_FILE` (since v2.6.1) names a one-line password file, before the interactive prompt. |
| `-rpet/--report-email-to`, `-rpef/--report-email-from` | Report recipient and From address. |
| `-rpes/--report-email-server`, `-rpesp/--report-email-server-port` | SMTP host and port; 465 selects implicit TLS, other ports use STARTTLS. Both validate the certificate chain and hostname before authentication; invalid certificates fail delivery. |
| `--insecure-tls` | Since v2.6.1. Do not verify TLS certificates of scanned websites (INI `insecure_tls`). By default web scan requests verify target certificates, so scans of self-signed targets need this option; use it only for targets you trust. TLS diagnostics are unaffected. |
| `--web`, `--web-host`, `--web-port` | Start the dashboard; default listener `127.0.0.1:8080` (since v2.6.1; v2.6.0 defaulted to `0.0.0.0`). `--web-host 0.0.0.0` listens on all interfaces, and non-loopback clients then require HTTPS. |
| `--web-reset-account` | Since v2.6.1. Reset the dashboard account to `admin` with a new random password, print it once, invalidate existing sessions and exit. Run it on the server with the same `AUTOPWN_DATA_DIR`. |

The CLI prints progress, discoveries and candidate findings and writes the
selected report. Normal completion returns process status zero; unhandled/startup
failures return nonzero. Inspect output/coverage as well as process status:
unreachable targets and budget limits are not proof of a clean scan.

## Python API

From a source checkout:

```python
from autopwn_suite import AutoScanner

scanner = AutoScanner()
results = scanner.scan("127.0.0.1", scan_vulns=False)
scanner.save_to_file("scan.json")
```

`AutoScanner.scan(target, host_timeout=None, scan_speed=None, apiKey=None,
os_scan=False, scan_vulns=True, nmap_args=None, debug=False, *, offline=False,
vulnerability_source="auto", vuln_db=None)` is synchronous. `target` is a string
or list of target strings; `nmap_args` is operator-selected Nmap arguments, either a string split
like a POSIX shell line or a list whose items each stay one argument (pass a list for a value with spaces or
a Windows path).
It returns a mapping keyed by resolved host addresses. Each host contains `ports`
(TCP port mapping), optional `udp_ports`, optional OS data and `vulns` grouped
by product/CVE. A host that hit `host_timeout` also has `timedout: True` (the key
is absent otherwise) and the call logs a warning: its ports and vulnerabilities
are incomplete. Vulnerability records include description, severity, score,
reference URL, exploitability, data source and database update time. Severity and
score come from the newest CVSS version NVD lists; exploitability is the sub-score of
the newest version that has one. CVSS v4 has none, so a record scored only with v4 reports 0.0,
which means that no sub-score is available, not that the CVE is not exploitable. An older
version's sub-score keeps its own scale (0 to 3.9 for CVSS v3, up to 10.0 for v2), which can
differ from the scale of the version that supplies the severity. Vulnerability
records are version-based candidates. Failures may raise scanner/database exceptions;
callers must handle them and protect output paths and sensitive results.
`save_to_file(filename="autopwn.json")` overwrites the selected file with JSON.

The web-check module additionally exposes
`autopwn_suite.web.webvuln.webvuln(target, log, console)`, returning structured finding
dictionaries. Targets may be hostname, host:port, IPv6 or an HTTP(S) URL. Findings
include type, URL, parameter, severity/confidence, evidence, reproduction plan,
timestamps and remediation/impact context. See the README for check semantics.
Other implementation helpers are internal and are not a compatibility promise.

## HTTP API

Base URL is the configured dashboard listener. v2.6.0 has no built-in
authentication; the entire API needed trusted access or protected ingress. Since v2.6.1,
every route except the sign-in page and its assets
(`/login`, `/login.js`, `/login.css`, `/favicon.ico`) and `/api/auth/login`
requires an authenticated session: the `HttpOnly`, `SameSite=Strict`
`autopwn_session` cookie (8 hours, server-side, revocable). Non-GET requests also
need the session's `X-CSRF-Token` header, and a present `Origin` header must
match the request origin. Peers that are not loopback must use HTTPS (or the
operator sets `AUTOPWN_WEB_SECURE_COOKIE=1` behind a TLS-terminating proxy); other
requests get 403. The peer is the address the connection comes from: a port published
from a Docker bridge network (even `-p 127.0.0.1:8080:8080`) reaches the dashboard from
the bridge gateway, which is not loopback, so plain-HTTP sign-in there needs host
networking with `AUTOPWN_WEB_HOST=127.0.0.1` (as `docker-compose.yml` uses). With
`AUTOPWN_WEB_SECURE_COOKIE=1` the `Origin` check expects `https` and the request's
`Host`, so the proxy must keep `Host` and the browser must reach it over HTTPS. Unauthenticated API requests get 401, and an unreadable account
file gets 503. The account is one shared administrator, so any signed-in
client still has the full API authority below.
POST/PUT inputs use `Content-Type: application/json` and JSON objects. Responses
are JSON except static files, SSE and downloads. Errors normally use
`{"error":"message"}` with 400 (invalid input), 401 (not signed in), 403
(CSRF/origin/HTTPS/credential refusal), 404 (missing resource), 409
(state/offline conflict), 429 (too many sign-in attempts) or 500 (operation
failure). POST creation returns 201 where noted; asynchronous verification/database
updates return 202.

| Method and path | Input | Output / effect |
| --- | --- | --- |
| `GET /`, `/favicon.ico`, static assets | Asset path | HTML, JavaScript, CSS or icon; static assets are served from the application static directory. |
| `GET /api/version` | None | `{version}`. |
| `GET /login`, `/login.js`, `/login.css` | None | Since v2.6.1. Sign-in page assets, public. |
| `GET /api/auth/login` | None | Since v2.6.1. Starts a sign-in challenge: `{csrf_token}` and a 5-minute `autopwn_login` cookie (`HttpOnly`, `SameSite=Strict`). Since v2.7.0 the challenge is stateless: the cookie holds an expiry and an HMAC-SHA256 signature over the expiry, the CSRF token and the account revision, made with a random key that lives only in the running dashboard process, and the server stores nothing. No number of these requests, from any number of addresses (or one shared proxy or Docker bridge address), can evict another client's pending challenge or use memory; a flood costs only the work of answering it. A restart of the dashboard (a new key) or a change or reset of the account ends the challenges that are open, and the sign-in page then asks for a new one. v2.6.1 kept 128 pending challenges on the server, and a flood could evict the operator's (AUTOPWN-SA-2026-021). |
| `POST /api/auth/login` | `{username,password}` plus the challenge `X-CSRF-Token` | Since v2.6.1. `{username,csrf_token}` and the session cookie; 401 for wrong credentials, 429 when rate limited, 403 "Sign-in expired" when the challenge cookie is missing, expired, altered, from another run of the dashboard or does not match the `X-CSRF-Token`. A successful sign-in issues a new random session cookie and clears the challenge cookie, but the challenge is not single-use: it carries no authority (any client can request one), so a replayed one only permits another sign-in attempt, which the failed-sign-in throttle counts. |
| `GET /api/auth/session` | None | Since v2.6.1. `{username,csrf_token}` for the current session. |
| `POST /api/auth/logout` | None | Since v2.6.1. `{ok}`; revokes the session. |
| `PUT /api/auth/account` | `{username,current_password,new_password}` (new password optional, 15-128 characters) | Since v2.6.1. Changes the username/password after verifying the current password; returns a fresh session and signs out others; 403 for a wrong current password. |
| `GET /api/scans` | None | Array of job summaries including config, status, timestamps, counts, hosts, progress, web findings/coverage. |
| `GET /api/scans/<scan_id>` | Job ID | One job summary; 404 if absent. |
| `GET /api/scans/<scan_id>/download` | Job ID | JSON attachment with complete serializable job/results. Private resume checkpoints are excluded. |
| `POST /api/scan/start` | `target`, scan configuration, optional `api_key` | `{ok,scan_id,message}`; launches background work. |
| `POST /api/scan/stop` | `{scan_id}` | `{ok}`; requests cancellation of a running/stopping job. |
| `POST /api/scans/<scan_id>/resume` | Optional `{web_options:{...}}` | `{ok,scan_id,resume_count}`; only incomplete/stopped/error jobs, retaining target and selected checks. |
| `GET /api/web/catalog` | None | Check descriptions, normalized default controls, numeric bounds, effective offline state. |
| `GET /api/web/findings` | None | All retained web finding summaries. |
| `GET /api/web/findings/<scan_id>/<finding_id>` | IDs | Full finding, evidence and verification history. |
| `GET /api/web/findings/<scan_id>/<finding_id>/poc` | `format=python|curl|html|json` | Attachment; browser HTML only for supported XSS/CORS findings. No replay occurs. |
| `POST /api/web/findings/<scan_id>/<finding_id>/verify` | Empty object `{}` | 202 `{ok,status}`; replay only the stored validated plan. No custom request plan/code is accepted. |
| `GET /api/vulnerability-database` | None | Readiness, path, record count, update timestamp/size/error, update progress and offline lock/preference. |
| `POST /api/vulnerability-database/update` | Empty object | 202 `{ok}`; starts explicit online feed update, or 409 when offline/already updating. |
| `GET /api/vulnerability-database/download` | None | SQLite attachment when ready; otherwise 409. |
| `GET /api/hosts` | None | Latest observed host records, with latest-attempt information where applicable. |
| `GET /api/log` | None | Retained log/event entries (the newest 5000), oldest first. Each has an `id` that increases with every entry and keeps increasing across dashboard restarts; the `id` of the last entry is the position to resume the event stream after (use 0 when the list is empty). |
| `GET /api/events` | SSE connection; optional `after=<id>` query parameter | `text/event-stream` with JSON event data and heartbeat comments. Retained log entries carry their `id` as the SSE `id:` field; live progress events have none. Without a resume point only entries added after the connection opens are sent. With `after=<id>` (for the first connection after reading `GET /api/log`) or the `Last-Event-ID` header (sent by the browser when it reconnects; it wins over `after`), the retained entries newer than that id are sent first, then the live ones, so nothing is lost or repeated. The value must be 1 to 18 ASCII digits, otherwise it is ignored; an id this process never issued sends everything retained. The stream ends when the session is signed out. Disconnect to unsubscribe. |
| `GET /api/settings` | None | Stored settings object; SMTP password is masked, but this is still sensitive configuration (a stored NVD key and webhook URL are returned as saved). Values supplied by `*_FILE` credential files are not included. |
| `PUT /api/settings` | Partial settings object | `{ok}`; merges/persists configuration. Masked SMTP password sentinel preserves the stored password. Account or credential keys are refused (400); use `PUT /api/auth/account`. |
| `POST /api/settings/test_email` | Empty object | `{ok}` after configured test mail, or error. Disabled offline. |
| `POST /api/settings/test_webhook` | Empty object | `{ok,status_code}` after configured test POST, or error. Disabled offline. |
| `GET /api/profiles` | None | Profile array: `id,name,description,created_at,config`. |
| `POST /api/profiles` | `name`, optional `description`, scan configuration | 201 created profile; persists it. |
| `PUT /api/profiles/<pid>` | Partial name/description/configuration | Updated profile; 404 if missing. Disables enabled schedules that no longer validate against the edited profile (a CIDR target on a web-only profile). |
| `DELETE /api/profiles/<pid>` | None | `{ok}`; disables dependent schedules. |
| `GET /api/schedules` | None | Saved schedule array. |
| `POST /api/schedules` | Schedule object | 201 created schedule; referenced profile must exist. |
| `PUT /api/schedules/<sid>` | Partial schedule object | Updated schedule. The merged record must validate, except that `{"enabled": false}` alone always applies. |
| `DELETE /api/schedules/<sid>` | None | `{ok}`; removes saved schedule and in-memory last-run state. |

### Scan and web controls

Configuration fields are `mode` (normal/evade/noise), `speed` (0–5), `scan_type`
(arp/ping/null), `scan_technique`, `ports`, `version_intensity` (0–9/null),
`os_detection`, `nmap_flags`, `host_timeout` (positive seconds), `scan_ports`,
`scan_vulns`, `skip_discovery`, `scan_web`, `vulnerability_source` and
`web_options`. The three Nmap fields (`scan_technique`, `ports`, `nmap_flags`) are rejected with HTTP 400
when they name a file: output options (`-oN`, `-oG`, `-oS`, `-oM`, `-oX`, `-oA`, `-o`, `-m`, however
spelled or clustered, as in `-6o`), `-iL`, `--excludefile`, `--datadir`, `--servicedb`, `--versiondb`,
`--stylesheet`, `--resume` and `--append-output`. A single-dash spelling of a long option that starts with
`o`, `i` or `m` (`-max-retries`) is refused as well; write long options with `--`. A profile saved earlier with such an option is held to the same rule: `PUT /api/profiles/<pid>` answers 400 for any change until `nmap_flags` is edited to drop the option, and a schedule that uses it is disabled when it next comes due (enable it again after the edit). Boolean fields require JSON booleans. Web-only mode sets
`scan_ports:false,scan_web:true` and disables discovery/CVE lookup. Noise mode
falls back to normal in the dashboard. Job statuses are `running`, `stopping`,
`completed`, `partial`, `stopped` or `error`; progress can have a null percentage.

`web_options.checks` maps catalog check names to booleans. Other controls are
`speed`, `min_delay_ms`, `timeout`, `request_budget`, `max_pages`, `max_urls`,
`max_depth`, `max_endpoints`, `max_parameters`, and `max_response_kb`. Since v2.6.1
the controls also include boolean `verify_tls` (default `true`): target certificates
are verified unless it is `false` ("Accept untrusted certificates" in the
dashboard), and the value is recorded with each finding's reproduction.
Use `/api/web/catalog` for authoritative current defaults/bounds. Results report
coverage limitations; HTTP timeout bounds active network I/O through headers and
body, and Stop interrupts active reads. OS DNS resolution is outside this bound.
Diagnostic probes/replay do not import `.netrc`, environment proxies or ambient
credentials. Each response is isolated from cookies set by previous responses.

### Settings and schedules

Settings contain `nist_api_key`, boolean `offline_mode`, and `email`/`webhook`
objects. Since v2.6.1, `AUTOPWN_NIST_API_KEY_FILE`,
`AUTOPWN_SMTP_PASSWORD_FILE` and `AUTOPWN_WEBHOOK_URL_FILE` override the
corresponding stored values at use time and are never written to the settings
file. Email keys are `enabled,smtp_host,smtp_port,username,password,from_addr,
to_addr,on_complete,on_error,on_vuln_found`. Webhook keys are
`enabled,url,on_complete,on_error,on_vuln_found`. Treat all notification
destinations and credentials as privileged configuration.
Private SMTP certificate authorities must be trusted by the platform or supplied
through Python's `SSL_CERT_FILE`/`SSL_CERT_DIR` trust configuration.

Schedule keys are `name,target,profile_id,enabled,type,interval_value,
interval_unit,time_utc,weekday`. Types are `interval`, `daily`, `weekly`;
interval units are minutes/hours/days, with a positive value; time is `HH:MM`
UTC and weekday is 0–6 (Monday–Sunday). Saved records add `id,created_at,last_run`
and, once a schedule has been enabled again or had its type, time or weekday
changed, `armed_at` (set by the dashboard; a value in a request is ignored).
Schedules use the selected profile when firing and must satisfy offline policy: in
offline mode a due schedule whose profile has web checks is skipped with one log
line (a manual start answers 409) and is tried again at its next interval or time.
The scheduler checks once a minute. A daily or weekly schedule whose time was
missed (a restart, a suspend or a slow check) still runs once when the check
comes within an hour of that time (a later check skips that day or week, without
a log line), and never for a time that passed before the
schedule was created, enabled again or retimed. A schedule does not start a scan
while the scan it started last is still running or stopping; it logs one skip. An
interval schedule starts when that scan ends; a daily or weekly schedule only if
that happens within the one-hour catch-up window of its time, otherwise it waits
for its next time.
A due schedule that fails validation (for example a hand-edited file) is disabled
and logged once instead of failing every minute; enable it again after fixing it.
Each such disabling, and one caused by a profile edit, is also written to the server
log as a fixed-text warning with the schedule ID (no exception text).

## Files, configuration and integrations

- Environment: `AUTOPWN_WEB_HOST` (default `127.0.0.1`), `AUTOPWN_WEB_PORT` (default 8080;
  like `--web-port`, a number from 1 to 65535, otherwise the command exits with a usage error),
  `AUTOPWN_DATA_DIR`, and (since v2.6.1) `AUTOPWN_WEB_SECURE_COOKIE=1` for a
  TLS-terminating proxy plus `AUTOPWN_NIST_API_KEY_FILE`,
  `AUTOPWN_SMTP_PASSWORD_FILE` and `AUTOPWN_WEBHOOK_URL_FILE`, each naming a
  one-line UTF-8 file of at most 4096 bytes. See [Secrets](SECRETS.md).
  `--vuln-db` selects an explicit database separately. INI configuration sections
  are `AUTOPWN`, `REPORT` and `WEBUI`; use `--create-config` and
  the parser in `autopwn_suite/utils.py` for the accepted keys. Do not commit generated
  configuration or key files `api.txt`/`lapi.txt`.
- JSON state files contain settings and dictionaries of profiles/schedules keyed
  by their IDs. Since v2.6.1 the dashboard also keeps `web_ui_auth.json` (plaintext
  username, scrypt password hash and a revision) beside them; do not edit it by
  hand, use the account settings or `--web-reset-account`. They are implementation-managed state, not a stable migration
  API. A profiles or schedules file that cannot be parsed is logged and renamed to
  `<name>.corrupt-<UTC timestamp>` before the dashboard starts without it, and a
  file with some non-object entries loads the valid ones, logs the count and keeps
  a copy of the original the same way (once: a restart with an identical copy
  already kept does not add another), so the next save never destroys the only copy. SQLite schema/readiness is versioned internally. Export before moving
  versions; never edit an active database directly.
- Nmap receives argv and returns XML/progress. Online NVD receives service
  keywords and optional API key over HTTPS; Exploit-DB supplies references and
  optional downloaded bytes. Explicit NVD mirror maintenance uses annual
  JSON/gzip feeds with metadata checksums.
- Web checks send bounded HTTP probes and TLS diagnostic handshakes to selected
  targets. Releases since v2.6.1 verify target certificates for the HTTP probes and
  replay unless `verify_tls` is false; diagnostic handshakes deliberately inspect
  untrusted certificates and legacy protocols without trusting them. Server replay
  is explicit. Generated Python/curl/HTML/JSON PoCs are
  downloads; running one is a separate operator action.
- CLI webhook delivery sends its report payload to the configured URL only (a redirect
  response is a failed delivery and is not followed); dashboard webhook delivery
  sends JSON scan/test events and treats a redirect the same way. SMTP delivers MIME scan reports/test messages to
  configured recipients. Inspect `autopwn_suite/report.py` and dashboard notification
  functions for payload details; only send to destinations you control/trust.
- Distribution interfaces are GitHub releases (source archives and standalone binaries),
  the PyPI package `autopwn-suite` and the Docker Hub image.
  [Releasing](RELEASING.md) defines signed artifact formats and verification.
  Authenticity backfills add an original OCI image-index snapshot plus per-platform
  CycloneDX SBOMs, OSV `results`/`packages` reports, policy results containing
  `version`, `packages` and `violations`, and backfill records identifying exact
  source/image/platform digests and assessment time. The signed manifest marks
  these as `authenticity_backfill` with `rebuilt` and `security_clearance` both
  false; these fields do not declare dependency findings fixed or non-exploitable.
  New publications bundle these supporting files and release notes in one
  `autopwn-suite-vVERSION-security.zip`. The manifest's `assets` hashes the downloadable
  source archives, standalone binaries, `SHA256SUMS` and that ZIP; `supporting_archive.name` and `supporting_archive.files`
  identify the ZIP and each member's `name`/`sha256`. Existing separate-file
  releases keep their original manifest and assets.
