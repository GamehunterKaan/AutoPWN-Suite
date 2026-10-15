# External software interfaces

This describes the v2.6.0 CLI, Python API, HTTP API, configuration, persistent
formats and outbound integrations. [Architecture](ARCHITECTURE.md) explains the
actors and trust boundaries. These interfaces are operator/admin capabilities,
not isolated accounts or a public multi-tenant service.

## CLI

Run `python autopwn.py --help` from a source checkout for the generated option
reference, types and defaults. `autopwn-suite` is also available after the Linux
installer creates its wrapper. Arguments are parsed in `modules/utils.py`.

| Options | Input and effect |
| --- | --- |
| `-h/--help`, `-v/--version` | Print usage or version and exit. |
| `-nc/--no-color` | Disable colored terminal output. |
| `-y/--yes-please` | Answer ordinary scanning confirmations automatically; it is not authorization to test another party's systems. |
| `-c/--config`, `--create-config` | Read an INI file or interactively create configuration. Present INI values are applied after argument parsing and overwrite matching parsed settings. |
| `--daemon-install`, `--daemon-uninstall` | Install/remove the Linux root systemd scanner service; privileged filesystem/service side effects. |
| `-t/--target`, `-hf/--host-file` | Target IP/hostname/range/CIDR or newline-separated target file; explicit target takes precedence over the host file. |
| `-sd/--skip-discovery`, `-st/--scan-type` | Skip discovery, or choose `arp`/`ping` discovery. Privileges limit available techniques. |
| `-nf/--nmap-flags` | Trusted operator Nmap arguments; pass a single argument such as `-nf="-p 80,443"`. These expose native Nmap capabilities, not a restricted remote job language. |
| `-s/--speed`, `-ht/--host-timeout` | Nmap speed 0–5 (default 3) and per-host timeout in seconds (default 240). |
| `-a/--api` | Optional NVD API key. Keep it out of committed files and shell history where possible. |
| `-m/--mode`, `-nt/--noise-timeout` | `normal`, `evade`, or `noise`; optional noise duration. Raw-packet features depend on host privileges. |
| `-sed/--skip-exploit-download` | Suppress optional exploit reference downloads. Downloading does not execute the files. |
| `--offline`, `--vuln-source`, `--vuln-db` | Force offline integration policy; select `auto`/`online`/`offline` CVE source; choose SQLite database path. Offline mode still sends requested Nmap target traffic. |
| `--update-vuln-db`, `--vuln-db-status` | Explicitly update the official local NVD mirror or print database readiness/freshness and exit. |
| `-o/--output`, `-of/--output-folder`, `-ot/--output-type` | Explicit output path or generated file under an output directory; `html`, `txt`, or `svg`. Output defaults to `outputs/` relative to the working directory. |
| `-rp/--report`, `-rpw/--report-webhook` | Select `email`/`webhook` notification and webhook destination. |
| `-rpe/--report-email`, `-rpep/--report-email-password` | SMTP username and password. |
| `-rpet/--report-email-to`, `-rpef/--report-email-from` | Report recipient and From address. |
| `-rpes/--report-email-server`, `-rpesp/--report-email-server-port` | SMTP host and port; 465 selects implicit TLS, other ports use STARTTLS. See known certificate-validation limitations in the advisory index. |
| `--web`, `--web-host`, `--web-port` | Start the dashboard; default listener `0.0.0.0:8080`. Use `--web-host 127.0.0.1` for local access. |

The CLI prints progress, discoveries and candidate findings and writes the
selected report. Normal completion returns process status zero; unhandled/startup
failures return nonzero. Inspect output/coverage as well as process status:
unreachable targets and budget limits are not proof of a clean scan.

## Python API

From a source checkout:

```python
from api import AutoScanner

scanner = AutoScanner()
results = scanner.scan("127.0.0.1", scan_vulns=False)
scanner.save_to_file("scan.json")
```

`AutoScanner.scan(target, host_timeout=None, scan_speed=None, apiKey=None,
os_scan=False, scan_vulns=True, nmap_args=None, debug=False, *, offline=False,
vulnerability_source="auto", vuln_db=None)` is synchronous. `target` is a string
or list of target strings; `nmap_args` is operator-selected Nmap arguments.
It returns a mapping keyed by resolved host addresses. Each host contains `ports`
(TCP port mapping), optional `udp_ports`, optional OS data and `vulns` grouped
by product/CVE. Vulnerability records include description, severity, score,
reference URL, exploitability, data source and database update time. They are
version-based candidates. Failures may raise scanner/database exceptions;
callers must handle them and protect output paths and sensitive results.
`save_to_file(filename="autopwn.json")` overwrites the selected file with JSON.

The web-check module additionally exposes
`modules.web.webvuln.webvuln(target, log, console)`, returning structured finding
dictionaries. Targets may be hostname, host:port, IPv6 or an HTTP(S) URL. Findings
include type, URL, parameter, severity/confidence, evidence, reproduction plan,
timestamps and remediation/impact context. See the README for check semantics.
Other implementation helpers are internal and are not a compatibility promise.

## HTTP API

Base URL is the configured dashboard listener. The current server has no built-in
authentication; the entire API needs trusted access or protected ingress.
POST/PUT inputs use `Content-Type: application/json` and JSON objects. Responses
are JSON except static files, SSE and downloads. Errors normally use
`{"error":"message"}` with 400 (invalid input), 404 (missing resource), 409
(state/offline conflict), or 500 (operation failure). POST creation returns 201
where noted; asynchronous verification/database updates return 202.

| Method and path | Input | Output / effect |
| --- | --- | --- |
| `GET /`, `/favicon.ico`, static assets | Asset path | HTML, JavaScript, CSS or icon; static assets are served from the application static directory. |
| `GET /api/version` | None | `{version}`. |
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
| `GET /api/log` | None | Retained log/event entries. |
| `GET /api/events` | SSE connection | `text/event-stream` with JSON event data and heartbeat comments. Disconnect to unsubscribe. |
| `GET /api/settings` | None | Settings object; SMTP password is masked, but this is still sensitive configuration. |
| `PUT /api/settings` | Partial settings object | `{ok}`; merges/persists configuration. Masked SMTP password sentinel preserves the stored password. |
| `POST /api/settings/test_email` | Empty object | `{ok}` after configured test mail, or error. Disabled offline. |
| `POST /api/settings/test_webhook` | Empty object | `{ok,status_code}` after configured test POST, or error. Disabled offline. |
| `GET /api/profiles` | None | Profile array: `id,name,description,created_at,config`. |
| `POST /api/profiles` | `name`, optional `description`, scan configuration | 201 created profile; persists it. |
| `PUT /api/profiles/<pid>` | Partial name/description/configuration | Updated profile; 404 if missing. |
| `DELETE /api/profiles/<pid>` | None | `{ok}`; disables dependent schedules. |
| `GET /api/schedules` | None | Saved schedule array. |
| `POST /api/schedules` | Schedule object | 201 created schedule; referenced profile must exist. |
| `PUT /api/schedules/<sid>` | Partial schedule object | Updated schedule. |
| `DELETE /api/schedules/<sid>` | None | `{ok}`; removes saved schedule and in-memory last-run state. |

### Scan and web controls

Configuration fields are `mode` (normal/evade/noise), `speed` (0–5), `scan_type`
(arp/ping/null), `scan_technique`, `ports`, `version_intensity` (0–9/null),
`os_detection`, `nmap_flags`, `host_timeout` (positive seconds), `scan_ports`,
`scan_vulns`, `skip_discovery`, `scan_web`, `vulnerability_source` and
`web_options`. Boolean fields require JSON booleans. Web-only mode sets
`scan_ports:false,scan_web:true` and disables discovery/CVE lookup. Noise mode
falls back to normal in the dashboard. Job statuses are `running`, `stopping`,
`completed`, `partial`, `stopped` or `error`; progress can have a null percentage.

`web_options.checks` maps catalog check names to booleans. Other controls are
`speed`, `min_delay_ms`, `timeout`, `request_budget`, `max_pages`, `max_urls`,
`max_depth`, `max_endpoints`, `max_parameters`, and `max_response_kb`.
Use `/api/web/catalog` for authoritative current defaults/bounds. Results report
coverage limitations; HTTP timeout currently bounds socket inactivity rather
than total wall-clock duration (see advisories).

### Settings and schedules

Settings contain `nist_api_key`, boolean `offline_mode`, and `email`/`webhook`
objects. Email keys are `enabled,smtp_host,smtp_port,username,password,from_addr,
to_addr,on_complete,on_error,on_vuln_found`. Webhook keys are
`enabled,url,on_complete,on_error,on_vuln_found`. Treat all notification
destinations and credentials as privileged configuration.

Schedule keys are `name,target,profile_id,enabled,type,interval_value,
interval_unit,time_utc,weekday`. Types are `interval`, `daily`, `weekly`;
interval units are minutes/hours/days, with a positive value; time is `HH:MM`
UTC and weekday is 0–6 (Monday–Sunday). Saved records add `id,created_at,last_run`.
Schedules use the selected profile when firing and must satisfy offline policy.

## Files, configuration and integrations

- Environment: `AUTOPWN_WEB_HOST`, `AUTOPWN_WEB_PORT`, `AUTOPWN_DATA_DIR`.
  `--vuln-db` selects an explicit database separately. INI configuration sections
  are `AUTOPWN`, `REPORT` and `WEBUI`; use `--create-config` and
  the parser in `modules/utils.py` for the accepted keys. Do not commit generated
  configuration or key files `api.txt`/`lapi.txt`.
- JSON state files contain settings and dictionaries of profiles/schedules keyed
  by their IDs. They are implementation-managed state, not a stable migration
  API. SQLite schema/readiness is versioned internally. Export before moving
  versions; never edit an active database directly.
- Nmap receives argv and returns XML/progress. Online NVD receives service
  keywords and optional API key over HTTPS; Exploit-DB supplies references and
  optional downloaded bytes. Explicit NVD mirror maintenance uses annual
  JSON/gzip feeds with metadata checksums.
- Web checks send bounded HTTP probes and TLS diagnostic handshakes to selected
  targets. Server replay is explicit. Generated Python/curl/HTML/JSON PoCs are
  downloads; running one is a separate operator action.
- CLI webhook delivery sends its report payload; dashboard webhook delivery
  sends JSON scan/test events. SMTP delivers MIME scan reports/test messages to
  configured recipients. Inspect `modules/report.py` and dashboard notification
  functions for payload details; only send to destinations you control/trust.
- Distribution interfaces are GitHub releases/source and the Docker Hub image.
  [Releasing](RELEASING.md) defines signed artifact formats and verification.
  Authenticity backfills add an original OCI image-index snapshot plus per-platform
  CycloneDX SBOMs, OSV `results`/`packages` reports, policy results containing
  `version`, `packages` and `violations`, and backfill records identifying exact
  source/image/platform digests and assessment time. The signed manifest marks
  these as `authenticity_backfill` with `rebuilt` and `security_clearance` both
  false; these fields do not declare dependency findings fixed or non-exploitable.
