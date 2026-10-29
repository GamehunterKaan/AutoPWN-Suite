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
| `-t/--target`, `-hf/--host-file` | Target IP/hostname/range/CIDR or newline-separated target file; explicit target takes precedence over the host file. The parameter summary the scan prints (`Target : ...`) shows a URL target with every query value, and a query part without `=`, replaced by `REDACTED` and its userinfo and fragment dropped; the scan itself uses the target as typed. When every target is an IPv6 literal or prefix, Nmap's `-6` is added; one Nmap run cannot scan both address families, so a mixed list must be split. Nmap does not support fragmentation (`-f`) with IPv6, so as root an evade-mode scan of IPv6 targets stops with Nmap's error. |
| `-sd/--skip-discovery`, `-st/--scan-type` | Skip discovery, or choose `arp`/`ping` discovery. Privileges limit available techniques. |
| `-nf/--nmap-flags` | Trusted operator Nmap arguments; pass a single argument such as `-nf="-p 80,443"`. These expose native Nmap capabilities, not a restricted remote job language. The scanner owns the XML output, so `-oX`, `-oA`, `--resume` and `--append-output` are refused whatever their spelling (`--oX`, an abbreviation such as `--appe`). |
| `-s/--speed`, `-ht/--host-timeout` | Nmap speed 0–5 (default 3) and per-host timeout in seconds (default 240). |
| `-a/--api` | Optional NVD API key. Keep it out of committed files and shell history where possible. When omitted, `AUTOPWN_NIST_API_KEY_FILE` (since v2.6.1) names a one-line key file that is read at use time, before `api.txt`. |
| `-m/--mode`, `-nt/--noise-timeout` | `normal`, `evade`, or `noise`; optional noise duration. Raw-packet features depend on host privileges. Noise mode runs one Nmap per live host for at most 32 hosts, and ends those Nmap processes when the duration passes or the scan is interrupted. |
| `-sed/--skip-exploit-download` | Suppress optional exploit reference downloads. Downloading does not execute the files. |
| `--offline`, `--vuln-source`, `--vuln-db` | Force offline integration policy; select `auto`/`online`/`offline` CVE source; choose SQLite database path. Offline mode still sends requested Nmap target traffic. |
| `--update-vuln-db`, `--vuln-db-status` | Explicitly update the official local NVD mirror or print database readiness/freshness and exit. |
| `--check-update`, `--apply-update`, `--update-channel`, `--update-branch`, `--update-repo` | Check GitHub for a newer release tag (`--update-channel release`, the default) or for the latest commit on `--update-branch` (`commit`, branch `main` by default) and exit, or fast-forward this git checkout to it and exit. The repository is `GamehunterKaan/AutoPWN-Suite` unless `--update-repo OWNER/REPO` or `AUTOPWN_UPDATE_REPO` names another; an explicit `--update-channel` is remembered in `update_channel.txt` in the data directory. Both refuse with `--offline` or `--vuln-source offline` and never run during a scan. `--apply-update` works only in a git checkout of this project (git's top-level directory must be the one that holds the `autopwn_suite` package, so an installed package, a standalone binary and a copy inside another repository are refused), with a clean working tree, and only fast-forwards; it verifies no signature. `--update-repo` must be `OWNER/REPO` and `--update-branch` a plain git branch name that does not start with `-`; anything else, and a release tag that is not a plain name, ends the command with status 1. Text that GitHub returns is printed without control characters. When nothing is newer, `--apply-update` changes nothing and prints `Already up to date`; it never moves the checkout back (on a detached HEAD it checks out the release tag only when HEAD precedes it and refuses a HEAD that diverged from it), and the commit check counts a checkout that already contains the branch's latest commit as up to date. When the update changes `pyproject.toml`, `poetry.lock`, `requirements.txt` or `requirements-locked.txt`, the message also says to install the dependencies again before restarting. The dashboard offers the same check and update (`/api/update` below). |
| `-o/--output`, `-of/--output-folder`, `-ot/--output-type` | Explicit output path or generated file under an output directory; `html`, `txt`, or `svg`. Output defaults to `outputs/` relative to the working directory. A generated name is the date and the target with every character other than letters, digits, `.`, `_` and `-` replaced by `_` (at most 100 characters), so `192.168.*.*` or an IPv6 address also saves on Windows. The query values of a URL target are redacted first. |
| `-rp/--report`, `-rpw/--report-webhook` | Select `email`/`webhook` notification and webhook destination. When no destination is given, `AUTOPWN_WEBHOOK_URL_FILE` (since v2.6.1) names a one-line file holding it, before the interactive prompt. |
| `-rpe/--report-email`, `-rpep/--report-email-password` | SMTP username and password. When no password is given, `AUTOPWN_SMTP_PASSWORD_FILE` (since v2.6.1) names a one-line password file, before the interactive prompt. |
| `-rpet/--report-email-to`, `-rpef/--report-email-from` | Report recipient and From address. |
| `-rpes/--report-email-server`, `-rpesp/--report-email-server-port` | SMTP host and port; 465 selects implicit TLS, other ports use STARTTLS. Both validate the certificate chain and hostname before authentication; invalid certificates fail delivery. |
| `--insecure-tls` | Since v2.6.1. Do not verify TLS certificates of scanned websites (INI `insecure_tls`). By default web scan requests verify target certificates, so scans of self-signed targets need this option; use it only for targets you trust. TLS diagnostics are unaffected. |
| `--lang {en,tr}`, `--language` | Language of CLI, daemon-installer and report text. An explicit choice is remembered in `language.txt` in the data directory; without it the language follows `AUTOPWN_LANG`, then the remembered choice, then the system locale (`LC_ALL`, `LC_MESSAGES`, `LANG`), then English. A message without a translation is shown in English, and scanned data (CVE text, banners, exploit titles) is never translated. |
| `--web`, `--web-host`, `--web-port` | Start the dashboard; default listener `127.0.0.1:8080` (since v2.6.1; v2.6.0 defaulted to `0.0.0.0`). `--web-host 0.0.0.0` listens on all interfaces, and non-loopback clients then require HTTPS. On POSIX the dashboard first restricts to mode `0600` any existing settings, profiles, schedules or account file in the data directory that group or others can read, and removes old temporary files of an interrupted save; it logs one fixed line when it changed something, or when it could not, and starts either way. |
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
records are version-based candidates: since v2.9.0 the product is searched and a CVE is kept when NVD's
applicability (its CPE configurations) marks the detected release of the application vulnerable, or, when that
applicability says nothing about versions (not analyzed, or only "every version"), when its description names the
release other than as the one that fixed it; a CVE whose description says the detected release, or an earlier
build of it, fixed that product is not kept (a release that starts a range, belongs to another product or is
followed by a vendor's build is not read as the fix). A version with fewer numbers than the product's releases
(Apache's `2.4`) is kept only for CVEs that affect every release it may be. `Vulnerability.affected` holds the
record's vulnerable CPE matches as (part, vendor, product, version, update, start including, start excluding,
end including, end excluding) tuples. Failures may raise scanner/database exceptions;
callers must handle them and protect output paths and sensitive results.
Text from the scanned host or the vulnerability source (service, product, version, OS and vendor
names, hostnames, CVE identifiers, descriptions and severities) is one line without control, bidirectional
or zero-width characters: a tab, a line feed and the Unicode line and paragraph separators become a space and
every other such character is removed (the response headers that a dashboard replay records are the exception: they are kept as received and only shown escaped). The output of an NSE script (`script`, and the text of its elements) and the OS fingerprint (`osfingerprint`) keep their line feeds and nothing else. A URL in a web finding (its `url`, the requests and observations of its reproduction plan, its `target`) keeps those characters as the percent-encoding that the HTTP client sends, for example `%1B` for ESC, so a replay or a PoC sends the request that the scan sent.
`save_to_file(filename="autopwn.json")` overwrites the selected file with JSON.

The web-check module additionally exposes
`autopwn_suite.web.webvuln.webvuln(target, log, console)`, returning structured finding
dictionaries. Targets may be hostname, host:port, IPv6 or an HTTP(S) URL. Findings
include type, URL, parameter, severity/confidence, evidence, reproduction plan,
timestamps and remediation/impact context. See the README for check semantics. The log lines, the coverage `issues` and the `target` of the `on_complete` summary, and the announcement line printed to `console`, redact every query value, userinfo and fragment of a URL (`redact_text` in `autopwn_suite/web/runtime.py`, and `redact_target` for a string that is one target); a finding redacts only the values of credential-named parameters (see Redaction under Scan and web controls).
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
updates return 202. Responses the dashboard can localize also carry a stable
machine-readable `"code"` (for example `{"error":"...","code":"invalid_scan_config"}`);
the English `"error"` or `"message"` text is unchanged.

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
| `GET /api/scans` | None | Array of job summaries including config, status, timestamps, counts, hosts, progress, web findings/coverage. The `target` and `config.target` of a URL target show every query value as `REDACTED` and no userinfo or fragment (see Redaction under Scan and web controls); the target the scan runs and resumes with is stored as typed. |
| `GET /api/scans/<scan_id>` | Job ID | One job summary, with the target redacted as above; 404 if absent. |
| `GET /api/scans/<scan_id>/download` | Job ID | JSON attachment with complete serializable job/results, with the target redacted as above. Private resume checkpoints are excluded. |
| `POST /api/scan/start` | `target`, scan configuration, optional `api_key` | `{ok,scan_id,message}`; launches background work. 400 for a non-empty `nmap_flags` or a technique or ports outside the structured fields (see Scan and web controls). The message shows the target redacted as above. 409 `update_in_progress` while an update is applied and `update_restart_required` once the checkout's commit differs from the one the dashboard started with, until it is restarted. |
| `POST /api/scan/stop` | `{scan_id}` | `{ok}`; requests cancellation of a running/stopping job. |
| `POST /api/scans/<scan_id>/resume` | Optional `{web_options:{...}}` | `{ok,scan_id,resume_count}`; only incomplete/stopped/error jobs, retaining target and selected checks. 409 `update_in_progress` while an update is applied and `update_restart_required` once the checkout's commit differs from the one the dashboard started with, until it is restarted. |
| `GET /api/web/catalog` | None | Check descriptions, normalized default controls, numeric bounds, effective offline state. |
| `GET /api/web/findings` | None | All retained web finding summaries. |
| `GET /api/web/findings/<scan_id>/<finding_id>` | IDs | Full finding, evidence and verification history. |
| `GET /api/web/findings/<scan_id>/<finding_id>/poc` | `format=python|curl|html|json` | Attachment; browser HTML only for supported XSS/CORS findings. No replay occurs. |
| `POST /api/web/findings/<scan_id>/<finding_id>/verify` | Empty object `{}` | 202 `{ok,status}`; replay only the stored validated plan. No custom request plan/code is accepted. 409 `update_in_progress` while an update is applied and `update_restart_required` once the checkout's commit differs from the one the dashboard started with, until it is restarted. |
| `GET /api/vulnerability-database` | None | Readiness, path, record count, update timestamp/size/error, update progress and offline lock/preference. |
| `POST /api/vulnerability-database/update` | Empty object | 202 `{ok}`; starts explicit online feed update, or 409 when offline/already updating. |
| `GET /api/vulnerability-database/download` | None | SQLite attachment when ready; otherwise 409. |
| `GET /api/update` | None | Since v2.8.1. The saved update channel (`release` or `commit`), the update repository, the running version, whether this copy is a git checkout (`checkout`), whether automatic checks are on (`auto_check`) and one is due (`check_due`: on, and the last check is 6 hours old by the server's clock), the offline state, the last check (`checked_at`, `status`, or a fixed `error` with `error_code`), the last applied `result` and `restart_required`, which is true when the checkout's commit differs from the one the dashboard started with (an update from the dashboard, `--apply-update` or git). Contacts neither GitHub nor git beyond reading the checkout's `HEAD`. The page calls it when it opens and every minute and checks when `check_due` is true. |
| `POST /api/update/check` | Optional `{channel}`: `release` or `commit`; optional `{automatic: true}` for a check the page starts on its own | Since v2.8.1. Checks GitHub now, as `--check-update` does, and returns the `GET /api/update` object. An automatic check is refused (409) when `update_auto_check` is off (`update_auto_check_off`) or the last check is less than 6 hours old by the server's clock (`update_not_due`). An explicit channel is remembered in `update_channel.txt`. The repository is `AUTOPWN_UPDATE_REPO` or the default and the commit channel follows `main`; the request cannot name either. 400 `invalid_update_channel`; 409 `update_offline` in offline mode and `update_already_running` while another check or update runs. A check that fails (GitHub unreachable, rate limited) is 200 with `error_code` and fixed text. |
| `POST /api/update/apply` | Optional `{channel}`: `release` or `commit` | Since v2.8.1. Updates this git checkout as `--apply-update` does and returns the `GET /api/update` object with `result` (`previous`, `new`, `ref`, `changed`, `dependencies_changed`) and `restart_required`. `automatic` is refused (400). 409 `update_offline`; `update_blocked_scans`, `update_blocked_verifications` or `update_blocked_db_update` while that work runs; `update_already_running`; and, with fixed text, a refused or failed update (`update_not_checkout`, `update_dirty_worktree`, `update_diverged`, `update_detached_head`, `update_fetch_failed`, `update_unreachable` and the other `update_*` codes). The running dashboard keeps the code it loaded until it is restarted. |
| `GET /api/hosts` | None | Latest observed host records, with latest-attempt information where applicable. |
| `GET /api/log` | None | Retained log/event entries (the newest 5000), oldest first. Each has an `id` that increases with every entry and keeps increasing across dashboard restarts; the `id` of the last entry is the position to resume the event stream after (use 0 when the list is empty). |
| `GET /api/events` | SSE connection; optional `after=<id>` query parameter | `text/event-stream` with JSON event data and heartbeat comments. Retained log entries carry their `id` as the SSE `id:` field; live progress events have none. Without a resume point only entries added after the connection opens are sent. With `after=<id>` (for the first connection after reading `GET /api/log`) or the `Last-Event-ID` header (sent by the browser when it reconnects; it wins over `after`), the retained entries newer than that id are sent first, then the live ones, so nothing is lost or repeated. The value must be 1 to 18 ASCII digits, otherwise it is ignored; an id this process never issued sends everything retained. The stream ends when the session is signed out. Disconnect to unsubscribe. |
| `GET /api/settings` | None | Stored settings object; SMTP password is masked, but this is still sensitive configuration (a stored NVD key and webhook URL are returned as saved). Values supplied by `*_FILE` credential files are not included. |
| `PUT /api/settings` | Partial settings object | `{ok}`; merges/persists configuration. Masked SMTP password sentinel preserves the stored password. Account or credential keys are refused (400); use `PUT /api/auth/account`. Turning on `offline_mode` is refused (409) while an update check or update runs (`offline_blocked_app_update`), as it is during online scans, notifications and a database download. Since v2.8.1, `update_auto_check` (boolean, default `true`) turns the page's automatic update checks on or off; any other value is refused (400 `invalid_update_auto_check_type`). |
| `POST /api/settings/test_email` | Empty object | `{ok}` after configured test mail, or error. Disabled offline. |
| `POST /api/settings/test_webhook` | Empty object | `{ok,status_code}` after configured test POST, or error. Disabled offline. |
| `GET /api/profiles` | None | Profile array: `id,name,description,created_at,config`. |
| `POST /api/profiles` | `name`, optional `description`, scan configuration | 201 created profile; persists it. 400 for a non-empty `nmap_flags`. |
| `PUT /api/profiles/<pid>` | Partial name/description/configuration | Updated profile; 404 if missing. Disables enabled schedules that no longer validate against the edited profile (a CIDR target on a web-only profile). 400 for a non-empty `nmap_flags`; saving replaces any Nmap options an earlier release stored. |
| `DELETE /api/profiles/<pid>` | None | `{ok}`; disables dependent schedules. |
| `GET /api/schedules` | None | Saved schedule array. |
| `POST /api/schedules` | Schedule object | 201 created schedule; referenced profile must exist. A schedule carries no Nmap options: 400 for a non-empty `nmap_flags`. |
| `PUT /api/schedules/<sid>` | Partial schedule object | Updated schedule. The merged record must validate, except that `{"enabled": false}` alone always applies. |
| `DELETE /api/schedules/<sid>` | None | `{ok}`; removes saved schedule and in-memory last-run state. |

### Scan and web controls

Configuration fields are `mode` (normal/evade/noise), `speed` (0–5), `scan_type`
(arp/ping/null), `scan_technique`, `ports`, `version_intensity` (0–9/null),
`os_detection`, `nmap_flags`, `host_timeout` (positive seconds), `scan_ports`,
`scan_vulns`, `skip_discovery`, `scan_web`, `vulnerability_source` and
`web_options`. Since v2.7.0 the dashboard has no free-text Nmap options: a scan, profile or schedule
request whose `nmap_flags` is not empty is refused with HTTP 400 and the fixed message `Nmap options
are not accepted; use the scan technique, ports and detection settings`, whatever the option (file
options such as `-oN` and `-iL`, NSE options such as `--script` and `--script-args`, or any other); an
absent, empty or blank one is what defaults and earlier clients send and is stored as `""`. The Nmap
arguments are built only from the structured fields, which are checked against fixed lists: `scan_technique`
is `""` (Nmap's default) or one of the techniques the Scan Technique list offers (`-sS`, `-sT`, `-sA`,
`-sW`, `-sM`, `-sU`, `-sN`, `-sF`, `-sX`); `ports` is empty or a comma list of port numbers 1–65535 and
ranges `first-last` (first at most last) such as `22,80,1-1000`, at most 2048 characters, without
spaces inside, `T:`/`U:` prefixes or `-` shorthand; `version_intensity` is an integer 0–9; the numeric
fields are integers. A value outside these lists is refused with
400, so no field can carry an Nmap option or a second argument, and a target whose parts start with `-`
is refused as well. In a job's `config`, `nmap_flags` is the argument string the dashboard built from
those fields. A profile or schedule saved by an earlier release that holds Nmap options, or a technique
or ports outside the lists above, is kept as it was and never used: at startup a copy of the file is
set aside as `<name>.corrupt-<UTC timestamp>` (one copy of an identical file), a schedule that uses it is
disabled when it next comes due with one log line that names the reason, and nothing scans with it.
`PUT /api/profiles/<pid>` (the form's Save) replaces the stored options, so saving the profile again
removes them, even when the request does not mention `nmap_flags`; the enabled schedules that use the
profile are disabled at that point, with a log line and a dashboard note, because they would run without
the options they had, and each is enabled again by hand. Boolean fields require JSON booleans. Web-only mode sets
`scan_ports:false,scan_web:true` and disables discovery/CVE lookup. Noise mode
falls back to normal in the dashboard. Job statuses are `running`, `stopping`,
`completed`, `partial`, `stopped` or `error`; progress can have a null percentage.

Each CVE finding that a dashboard scan saves (the `vulns` of a host in `/api/scans`, `/api/hosts` and the job
download) has `categories`: a list of the fixed IDs `rce`, `privilege_escalation`, `injection`, `xss`,
`auth_bypass`, `info_disclosure`, `dos`, `memory_corruption` and `other`, in that order. A CVE can have several
(`other` only alone). They come from the CWE weaknesses of the NVD record, online or from the local database, and
only when none of them maps to a category from keywords in the description
(`autopwn_suite/vulnerability_categories.py`, rules in `autopwn_suite/data/vulnerability_categories.json`). The
Vulnerabilities tab counts them as filter chips, shows them in a Category column and puts them in its PDF export. A
scan saved before this field existed has no `categories`; its findings appear only under "All". The Python
library's `scan()` results, the command line and the saved reports do not carry categories.

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

Redaction: a web scan shows a URL in two ways. In a finding (`url`, `evidence`, the recorded requests and `Location` headers) a query value is replaced by `REDACTED` when its parameter name looks like a credential: a name containing `auth`, `pass` (not `passage`, `passport` and similar words), `secret`, `token`, `session`, `jwt`, `signature`, `csrf`, `credential`, `bearer`, `pwd`, `cookie` or `hmac`, an `api`, `access`, `private`, `app`, `client`, `consumer`, `license`, `encryption`, `signing`, `master`, `service`, `ssh` or `developer` key, `verifier`, `samlresponse` or `relaystate`, the names `key` and `code` (an OAuth callback carries a credential in `code`; `sort_key`, `country_code` and `zipcode` stay), the words `sig`, `sid`, `otp`, `cred`, `pw`, `ticket` and `nonce` alone or inside a longer name (`x_sig`, `login_ticket`; `design` and `tickets` stay), and the verification codes (`reset_code`, `mfa_code`). The other values stay, because a replay needs them, so a secret in a parameter with any other name (`ref`, `s`), in the URL path, or nested inside the value of another parameter (`redirect_uri=https%3A%2F%2Fapp%2Fcb%3Fcode%3Dabc`, `next=http://h/?token=abc`: only the outer name is read) is shown there; userinfo and fragment are dropped. Everywhere else, namely the console announcement, log lines and the log history, the `issues` and `target` of the web coverage, the `target` and `config.target` of a job, a finding's `endpoint` and the target of its reproduction plan (a replay reads only its origin), and the webhook, email and report text, every query value is replaced by `REDACTED` whatever the parameter is called, the parameter names stay (`?id=REDACTED&x=REDACTED`), and userinfo, fragments and `;name=value` path parameter values are dropped or replaced. This holds for any case of the scheme and for a target typed without one (`host:80?x=y`, `[::1]:80/?x=y`). A target the dashboard or the CLI echoes (job record, answer, webhook, email, scheduler line, parameter summary, report file name) is redacted as one string by `redact_target`: a quote, an angle bracket, any kind of space or a Unicode space (U+00A0, U+2028, U+3000) inside it cannot end it early, and a query part without `=` (`host/verify?3f9a7c`) goes whole. In a log line or a coverage note (`redact_text`) a URL starts at its scheme (or at a word holding `?`, `@` or `#`) and runs to the next space, tab or line break, with only the sentence punctuation behind it left out; a part without `=` goes whole in a URL and stays in a word without a scheme, so that prose such as `what?` is kept. Only a secret in the URL path, in a query part without `=` inside a word without a scheme, or after a raw space inside a URL that a log line, a coverage note or a finding's evidence quotes (a browser would send `%20`, and a link in a page is written that way when the scan reads it, so this needs a URL that was typed with a space or a redirect that carries one) stays visible, and a password with an unescaped `/`, `?` or `#` in the userinfo of a URL is cut where a URL parser cuts it, so the part before that character stays visible. Redaction changes what is shown and exported, never what the scan uses: the dashboard keeps the target as typed to run, resume and re-run the scan. The dashboard's job log, the job's `error` and its server log carry the class of an exception, never its text (`Unexpected error (RuntimeError)`), because a request error quotes the URL it sent.

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
for its next time. While an update is applied, and until the dashboard restarts after its checkout's commit changed,
no schedule starts a scan and none is marked as run; one line is logged for each hold. An interval schedule then runs at once; a daily or weekly one runs only when that happens within an hour of its time, otherwise at its next time.
A due schedule that fails validation (for example a hand-edited file) is disabled
and logged once instead of failing every minute; enable it again after fixing it.
Each such disabling, and one caused by a profile edit, is also written to the server
log as a fixed-text warning with the schedule ID (no exception text).

## Files, configuration and integrations

- Environment: `AUTOPWN_WEB_HOST` (default `127.0.0.1`), `AUTOPWN_WEB_PORT` (default 8080;
  like `--web-port`, a number from 1 to 65535, otherwise the command exits with a usage error),
  `AUTOPWN_DATA_DIR`, `AUTOPWN_UPDATE_REPO` (the GitHub repository for `--check-update`,
  `--apply-update` and the dashboard's update check and apply; default `GamehunterKaan/AutoPWN-Suite`), `AUTOPWN_LANG` (`en` or `tr`, the interface
  language when `--lang` is not given), and (since v2.6.1)
  `AUTOPWN_WEB_SECURE_COOKIE=1` for a
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
  already kept does not add another). A file that parses but holds a profile or
  schedule that this release refuses (Nmap options saved by an earlier release, or
  a technique or ports outside the lists in the scan section) keeps every entry and is
  copied the same way. The next save never destroys the only copy. SQLite schema/readiness is versioned internally. Export before moving
  versions; never edit an active database directly.
- Nmap receives argv and returns XML/progress. Online NVD receives the product
  names of detected services (without their versions) and optional API key over HTTPS; Exploit-DB supplies references and
  optional downloaded bytes. Explicit NVD mirror maintenance uses annual
  JSON/gzip feeds with metadata checksums.
- `--check-update` and `--apply-update` send GET requests to `api.github.com`; `--apply-update` also runs
  `git fetch` from `https://github.com/OWNER/REPO.git` and a fast-forward-only `git merge` (or `git checkout`
  of the release tag on a detached HEAD) in the checkout, as argument lists without a shell. The only state
  they keep is `update_channel.txt` (one word, `release` or `commit`) in the data directory. The dashboard's
  `POST /api/update/check` and `POST /api/update/apply` do the same; it keeps the last result in memory only.
- Localization is local and fetches nothing. `--lang` writes `language.txt` (`en` or `tr`) in the data
  directory; any other content is ignored. The dashboard keeps its language in the browser's
  `localStorage` (`apwn_lang`) and sends it as the `X-App-Language` request header, which the server does
  not act on. Notification e-mails and webhook texts use the `language` key of the dashboard settings
  (`en` or `tr`; empty or any other value means the language the server resolved at start).
- Web checks send bounded HTTP probes and TLS diagnostic handshakes to selected
  targets. Releases since v2.6.1 verify target certificates for the HTTP probes and
  replay unless `verify_tls` is false; diagnostic handshakes deliberately inspect
  untrusted certificates and legacy protocols without trusting them. Server replay
  is explicit. Generated Python/curl/HTML/JSON PoCs are
  downloads; running one is a separate operator action.
- CLI webhook delivery sends its report payload to the configured URL only (a redirect
  response is a failed delivery and is not followed); dashboard webhook delivery
  sends JSON scan/test events and treats a redirect the same way; its event and the email subject and report show a URL target redacted as above. SMTP delivers MIME scan reports/test messages to
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
