# Security advisories

This is the project's predictable public vulnerability-information channel,
alongside [GitHub Security Advisories](https://github.com/GamehunterKaan/AutoPWN-Suite/security/advisories).
Use [private reporting](../SECURITY.md) for new issues and coordinated disclosure.
Local `AUTOPWN-SA-*` identifiers below are project tracking identifiers, **not
CVE or GHSA identifiers**. These entries summarize the 2026-10-15 source
assessment. They do not claim that any remediation has shipped.

## AUTOPWN-SA-2026-001 — Unauthenticated dashboard administration

- Assessed affected version: **2.6.0** (`c24c1d4`). Earlier versions not assessed.
- Status: **open**. Fixed version: none identified.
- CWE-306; medium under conditional network exposure.
- Prerequisite: an untrusted client can reach the dashboard. The default listener
  is `0.0.0.0:8080`; the localhost display does not restrict network binding.
- Impact: read network observations/integration configuration, modify persistent
  jobs/settings and invoke scanner capabilities as its process identity. Custom
  Nmap options retain native functionality, including output-file writes.
- Mitigation: restrict network access to trusted operators, explicitly bind
  loopback where possible, and put remote access behind authenticated ingress.
  Do not expose it to the public internet. Treat all API access as administrative.
- Source: `modules/web_ui.py` application construction and administrative routes;
  `modules/nmap_progress.py` native option processing.

## AUTOPWN-SA-2026-002 — Stored script injection in profile descriptions

- Assessed affected version: **2.6.0**. Earlier versions not assessed.
- Status: **open**. Fixed version: none identified.
- CWE-79; medium, requiring profile modification and an operator page view.
- Impact: saved descriptions are inserted as HTML in the dashboard, allowing
  script execution in its origin when a profile list is rendered.
- Mitigation: restrict profile writers and dashboard access; use an isolated
  browser context. A code fix must render descriptions as text/escaped content.
- Source: profile POST/PUT handlers in `modules/web_ui.py` and `renderProfiles`
  in `modules/web_ui_static/app.js`.

## AUTOPWN-SA-2026-003 — SMTP server certificates are not validated

- Assessed affected version: **2.6.0**. Earlier versions not assessed.
- Status: **open**. Fixed version: none identified.
- CWE-295; medium, requiring an active network intermediary or forged endpoint.
- Impact: implicit-TLS/STARTTLS connections use an unverified standard-library
  default before SMTP login, permitting disclosure of credentials/report data.
- Mitigation: disable email notifications or use a separately authenticated
  protected transport. Merely selecting port 465/STARTTLS is not a fix.
- Source: email delivery in `modules/report.py` and `_smtp_connection` in
  `modules/web_ui.py`. A fix must supply a validating SSL context on both paths.

## AUTOPWN-SA-2026-004 — Ambient credentials in core web requests

- Assessed affected version: **2.6.0**. Earlier versions not assessed.
- Status: **open**. Fixed version: none identified.
- CWE-522; medium, requiring a matching/default `.netrc` credential entry in the
  scanner account. No real credential files were accessed during assessment.
- Impact: core discovery/crawl/injection/directory HTTP paths may implicitly
  transmit account credentials to the selected target. Initial HTTP discovery
  and unchecked target TLS can expose them to an intermediary as well.
- Mitigation: use a dedicated scanner account with no ambient `.netrc`
  credentials. Stronger anonymity in additional diagnostic probes and replay
  does not currently protect every core request.
- Source: `modules/web/http.py`, `webvuln.py` and `dirbust.py` request consumers.

## AUTOPWN-SA-2026-005 — Unbounded slow HTTP response duration

- Assessed affected version: **2.6.0**. Earlier versions not assessed.
- Status: **open**. Fixed version: none identified.
- CWE-400; medium, requiring a hostile selected HTTP target.
- Impact: trickled response bytes can retain scan/verification workers despite
  configured inactivity timeouts and an operator Stop request. Response byte
  limits do not enforce a wall-clock deadline or immediate cancellation.
- Mitigation: isolate scanning from other services and enforce process-level
  time limits. Terminating the dashboard loses in-memory jobs/checkpoints, so
  export needed results first. A code fix needs deadline-aware transport reads.
- Source: `bounded_request` in `modules/web/http.py` and streaming replay in
  `modules/web/poc_runtime.py`.

## Record maintenance

Assessment date and last update for these entries: **2026-10-15**. Publication
occurs when this document is merged into the public repository. Update affected
and fixed versions, mitigations and references as validation or fixes progress.
See [assessment scope and limitations](SECURITY_ASSESSMENT.md); this list does
not assert that unlisted versions or configurations are safe.
