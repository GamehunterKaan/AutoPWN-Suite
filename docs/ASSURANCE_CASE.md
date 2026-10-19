# Security assurance case

This document argues why AutoPWN Suite's security requirements are met, and says
where they are **not** met or not yet shipped. It supports the OpenSSF Best Practices
`assurance_case` criterion and complements, rather than replaces, the
[threat model](THREAT_MODEL.md), [security assessment](SECURITY_ASSESSMENT.md),
[advisories](SECURITY_ADVISORIES.md) and [security policy](../SECURITY.md).

**Status of the evidence.** Statements about login, TLS verification by default,
loopback binding and credential files describe changes first released in v2.6.1
(v2.6.0 and earlier lack them). An argument is not a
guarantee: every row names the evidence a reviewer can inspect, and the final
section lists known counter-evidence.

## 1. Scope and top-level claim

AutoPWN Suite is a **trusted-operator** vulnerability scanner. An operator who can
run it already has the authority of the account it runs as. It processes untrusted
data (scan targets, web responses, vulnerability feeds, exploit downloads) and, in
dashboard mode, serves an administrative web interface.

**Top-level claim (G0):** *When deployed as documented, an untrusted scan target, an
untrusted network client of the dashboard, or an untrusted vulnerability-data
provider cannot gain the operator's authority, read operator credentials, or
silently alter scan results through the project's own defects, and published
releases are attributable to the project's build.*

### Security requirements

| ID | Requirement |
| --- | --- |
| SR1 | Untrusted input never becomes a command, query, path or markup that executes with scanner authority. |
| SR2 | Only authenticated operators can use the dashboard; requests cannot be forged from another origin. |
| SR3 | Credentials are not sent to unverified peers or to scan targets and are kept apart from ordinary data. |
| SR4 | Network and resource use is bounded (time, bytes, requests, origins). |
| SR5 | Scanner-side TLS trust decisions are verified by default; weakening them is explicit and recorded. |
| SR6 | A user can verify that released artifacts came from the project's build. |
| SR7 | Failures are visible and fail closed (no silent default credentials, no silent partial results). |

## 2. Threat model summary and trust boundaries

The full model is in [THREAT_MODEL.md](THREAT_MODEL.md). Actors: the **operator**
(trusted), **scan targets** (untrusted; control responses, HTML, redirects,
certificates, timing), a **dashboard network client** (untrusted until it
authenticates), **external providers** such as NVD and exploit sources (untrusted
data over HTTPS), a **local intermediary** on the network path, and a **contributor**
(can propose code but holds no publishing credentials).

| ID | Trust boundary | Crossing data | Principal controls |
| --- | --- | --- | --- |
| TB1 | Scan target to scanner | Banners, HTTP responses, certificates, XML from Nmap | Bounded transport, origin scoping, output escaping, anonymous diagnostics |
| TB2 | Browser/network to dashboard | HTTP requests, cookies | Login, CSRF, origin checks, loopback default, HTTPS for remote clients |
| TB3 | Operator input to subprocess | Targets, Nmap flags | Allowlist regexes, argument vectors, no shell |
| TB4 | Provider to local store | NVD JSON, exploit files | Staged validation, parameterized SQL, sanitized filenames, never executed |
| TB5 | Scanner to outside services | SMTP, webhook, NVD, Docker/GitHub | Certificate validation, credential files, least-privilege CI |
| TB6 | Source to released artifact | Code, dependencies, build | Review, pinned and hash-locked inputs, signed provenance |

## 3. Secure design principles

Each row argues the principle is applied, with inspectable evidence.

| Principle | Argument | Evidence |
| --- | --- | --- |
| **Fail-safe defaults** | The dashboard binds to `127.0.0.1`; first launch creates a random administrator password instead of a fixed one; a missing or corrupt account file blocks login rather than restoring defaults; scans verify target certificates unless `--insecure-tls` is given; an unusable credential file is reported, never silently ignored. | `--web-host` default in `autopwn_suite/utils.py`; `AccountStore.initialize` in `autopwn_suite/web_auth.py`; `autopwn_suite/web/options.py` (`verify_tls`); tests `test_runtime_missing_or_invalid_auth_file_never_restores_defaults`, `test_untrusted_certificate_is_rejected_by_default_with_actionable_issue` |
| **Complete mediation** | Authentication is installed first as a `before_request` hook, so every existing and future route, static file, download and event stream is private by default. Every non-GET request also needs a per-session CSRF token. | `install_auth` in `autopwn_suite/web_auth.py`; tests `test_every_existing_route_requires_login_including_static_sse_and_downloads`, `test_all_mutations_require_csrf_even_without_a_body` |
| **Least privilege** | Web probes are read-only (`GET`, `OPTIONS`, `TRACE`) and stay on one origin; diagnostic requests carry no operator credentials or cookies; replay accepts only plans generated from recorded evidence. | `ProbeClient` and `scoped_get` in `autopwn_suite/web/http.py`; `AnonymousAuth` in `autopwn_suite/web/transport.py`; `validate_plan` in `autopwn_suite/web/poc_runtime.py` |
| **Separation of privilege / least common mechanism** | The CI that builds and the job that signs and pushes are separate; pull-request jobs are read-only and receive no secrets; signing uses short-lived workflow identity rather than a stored key. | `.github/workflows/publish-docker.yml`, `security.yml`, [RELEASING.md](RELEASING.md), [SECRETS.md](SECRETS.md) |
| **Economy of mechanism** | Cryptography is delegated to Python's `ssl`/`hashlib` (scrypt) and Sigstore rather than custom code; one validated options schema serves CLI, dashboard, profiles and schedules. | `password_hash` in `autopwn_suite/web_auth.py`; `autopwn_suite/web/options.py` |
| **Open design** | Controls do not depend on secrecy of the design: source, threat model and advisories are public. | This directory; [SECURITY.md](../SECURITY.md) |
| **Psychological acceptability** | Secure behavior is the default and the escape hatch is explicit and explained: certificate failures print the exact flag and the risk; login and password reset have documented commands. | Warning text in `bounded_request` (`autopwn_suite/web/http.py`); README "Signing in", "TLS certificate verification" |
| **Allowlist validation** | Untrusted fields are checked against allowed patterns or schemas and rejected otherwise (see section 4, CWE-20/78). | `_validate_target`, `_validate_nmap_flags`, `normalize_options`, `validate_account` |
| **Defense in depth** | Login is not the only gate: loopback default, HTTPS requirement for remote clients, Origin checks, `SameSite=Strict` cookies, no-store/no-sniff/no-frame headers, a Content-Security-Policy (strict on the sign-in page), Permissions-Policy and cross-origin isolation headers, and no server-version disclosure. | `install_auth` in `autopwn_suite/web_auth.py`; test `test_remote_cleartext_login_is_rejected_and_forwarded_headers_cannot_override_it` |

## 4. Common implementation weaknesses and how they are countered

| Weakness | Countermeasure and evidence |
| --- | --- |
| **Command/argument injection** (CWE-78, CWE-88) | Nmap runs with an argument vector and `shell=False`; dashboard targets and flags must match restrictive allowlist regexes, may not contain shell metacharacters, and flags may not name Nmap output, input-list or data files (`uses_files` in `autopwn_suite/nmap_progress.py`; NSE scripts and their arguments remain trusted administrator functionality). `autopwn_suite/nmap_progress.py` (`subprocess.Popen(..., shell=False)`); `_validate_target`, `_validate_nmap_flags` in `autopwn_suite/web_ui.py` |
| **SQL injection** (CWE-89) | The vulnerability database uses parameterized queries and read-only snapshots; updates are staged and validated before replacement. `autopwn_suite/vulnerability_db.py`; `tests/unit/test_vulnerability_db.py` |
| **Cross-site scripting** (CWE-79) | Dashboard values are escaped before insertion into markup (`esc()` in `app.js`, `escape()` in `web_security.js`, `html.escape` in report generation); a vulnerability's severity reaches a class attribute or the page only as one of five fixed words (`sevClass()` in `app.js`) and its CVSS score is escaped, because a copied vulnerability database controls both. Profile metadata injection was fixed in v2.6.1 (AUTOPWN-SA-2026-002). `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_review.py`, `tests/unit/test_web_security_ui.py` |
| **Cross-site request forgery** (CWE-352) | Per-session CSRF tokens on all non-GET requests plus same-origin checks and `SameSite=Strict` cookies. `tests/unit/test_web_auth.py` |
| **Broken authentication / weak password storage** (CWE-287, CWE-916) | Random 24-byte-entropy initial password, scrypt (N=32768, r=8, p=3) with a per-account random salt, constant-time comparison, throttled failures with bounded concurrent hashing, revocable server-side sessions invalidated on password change or reset. `autopwn_suite/web_auth.py`; `test_login_throttling_cannot_be_bypassed_by_new_challenges`, `test_account_change_requires_current_password_rotates_sessions_and_persists` |
| **Improper certificate validation** (CWE-295) | Scan requests, replay and SMTP validate certificates by default; the opt-out is per scan and recorded in each finding and generated PoC. TLS diagnostics intentionally inspect untrusted certificates but send no HTTP data or credentials. `autopwn_suite/web/http.py`, `autopwn_suite/report.py`, `autopwn_suite/web/poc.py`; `tests/unit/test_web_transport_security.py`, `tests/unit/test_smtp_security.py` |
| **Credential exposure** (CWE-522, CWE-798) | Diagnostic HTTP ignores environment credentials (`trust_env=False`) and strips `Authorization`, `Cookie` and `Proxy-Authorization`; credentials can live in separate owner-controlled files that are re-read at use and never copied into dashboard settings; there is no built-in default password. Notification failures log only the exception class and HTTP status, because request errors quote the webhook URL, which is a credential. Web scan log lines and coverage issues pass through `redact_text`, which redacts the query secrets of every URL they mention that starts with a lowercase `http://` or `https://` (the announcement line of a web scan and a target typed without that scheme still show the URL as given; AUTOPWN-SA-2026-017), and the crawler logs fixed text instead of the request exception. `autopwn_suite/web/transport.py`, `autopwn_suite/web/runtime.py` (`redact_text`), `autopwn_suite/credential_files.py` (`delivery_error_summary`); `tests/unit/test_credential_files.py`, `tests/unit/test_report.py`, `tests/unit/test_web_ui.py`, `tests/unit/test_web_webvuln.py` |
| **Path traversal / unsafe file write** (CWE-22) | Downloaded exploit filenames are reduced to a single sanitized path component. `_safe_path_component` in `autopwn_suite/getexploits.py`; `test_remote_names_cannot_escape_the_output_folder` in `tests/unit/test_getexploits.py` |
| **SSRF and open redirection by scanner** (CWE-918, CWE-601) | Redirects are followed at most three times and never leave the target origin (HTTP-to-HTTPS upgrade on the same host excepted); probes beyond the permitted origin or method raise. `scoped_get`, `ProbeClient.send` in `autopwn_suite/web/http.py`; `tests/unit/test_web_http.py` |
| **Resource exhaustion** (CWE-400) | Request budgets, crawl limits, response-size caps, request deadlines covering connect, TLS and body, cancellation, bounded login hashing, and patterns over response text with bounded gaps that read at most a capped part of the body (a regular expression holds the interpreter lock, so one that backtracks over a hostile body would stall the scan, its Stop button and the dashboard), and HTML analysis that visits each element once, reads only the start of the first few headings and looks at no more than 100 forms per page, 2,000 form controls per page and a bounded part of each form (an ancestor walk, a heading text or a search of a whole subtree per element would make a deeply nested page quadratic; a page that exceeds a bound is reported as partly analysed), and body comparisons that read only a shorter prefix when `difflib` would otherwise spend tens of seconds on a body of many different characters (varied text is compared on roughly its first 20,000 characters, a page of mostly repeated markup in full) and stop searching for common blocks after half a second, counting the blocks found so far, so a periodic body cannot keep a comparison running either. `autopwn_suite/web/options.py` (`LIMITS`), `autopwn_suite/web/transport.py` (`_RequestDeadline`), `autopwn_suite/web/sqli.py`, `content.py`, `xss.py`, `crawler.py`, `similarity.py` and `poc_runtime.py`; `tests/unit/test_web_transport_security.py`, `tests/unit/test_web_hostile_bodies.py` |
| **Unsafe deserialization / code execution** (CWE-502, CWE-94) | No `eval`, `exec`, `pickle` or `shell=True` in application code; downloaded exploit content is saved, never executed; PoC replay never accepts client-supplied code. Checked by Bandit in the required `.github/workflows/security.yml` job (via `scripts/security_policy.py`) and by GitHub CodeQL code scanning |
| **Vulnerable components / supply chain** (CWE-1104, CWE-494) | Locked and hash-pinned dependencies, pinned container base and package snapshot, SBOMs, OSV/Dependabot monitoring, signed releases verified against the expected workflow identity. `poetry.lock`, `requirements-locked.txt`, [DEPENDENCIES.md](DEPENDENCIES.md), [RELEASING.md](RELEASING.md) |
| **Insecure defaults at deployment** (CWE-1188) | Loopback binding by default; compose uses loopback; remote access demands HTTPS; startup prints a warning when listening beyond localhost. `autopwn_suite/web_ui.py` (`start_server`), `docker-compose.yml` |

## 5. How the argument is kept true

- **Automated gates (required on every pull request):** unit and integration tests
  with a coverage floor of 80%, Ruff and ESLint ([coding standards](CODING_STANDARDS.md)),
  Bandit (SAST) and OSV-Scanner (SCA) through `scripts/security_policy.py`, and a
  check that the hash-locked container requirements match `poetry.lock`. GitHub
  CodeQL code scanning and Dependabot alerts run as repository settings.
- **Review:** changes that touch authentication, transport, persistence, native
  execution or release workflows must be checked against the
  [threat model](THREAT_MODEL.md) table, and that table updated in the same change.
- **Findings:** real defects are tracked in [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md);
  an unresolved scenario is never recorded as "not affected".

## 6. Known counter-evidence and residual risk

These are deliberate limits, not omissions. They are part of the argument because a
case that hides them would not be an assurance case.

- **One shared administrator account, no MFA, no per-user audit trail.** Dashboard
  access is all-or-nothing administrative authority.
- **The dashboard's Content-Security-Policy still allows inline scripts and styles.** `index.html` uses inline
  event handlers, so its policy limits content to the same origin but cannot forbid inline code; the sign-in page,
  which has none, uses a strict policy. Removing the inline handlers would let the dashboard policy match it.
- **Plaintext at rest.** Settings, profiles, schedules and, unless credential files
  are used, SMTP/API values are stored unencrypted; protection relies on host
  permissions and disk encryption ([SECRETS.md](SECRETS.md)).
- **HTTPS is the operator's responsibility** for any non-loopback access. The
  application does not terminate TLS itself.
- **Releases before v2.6.1.** Login, TLS verification by default and loopback binding
  protect only deployments running v2.6.1 or later. These are breaking changes for
  scans of self-signed targets (`--insecure-tls`) and for remote dashboard use.
- **Scanner functionality that handles untrusted targets by design:** legacy-protocol
  and invalid-certificate inspection, and active injection probes against targets the
  operator selects. The operator is responsible for authorization to test a target.
- **Nmap output is parsed with the standard library XML parser.** The data comes from
  a local Nmap process, but target-controlled strings flow through it; a hardened
  parser such as `defusedxml` would reduce residual risk and is a candidate improvement.
- **DNS resolution** is performed by the operating system and is outside the
  project's network deadlines.
- **Container and OS packages.** Operating-system packages come from the Debian base
  image and are not managed as project dependencies; they appear in the signed SBOM and
  scan reports, and a signature establishes origin, not safety. The service runs as root
  and the image defines no unprivileged user. The Linux daemon installer likewise runs
  its service as root, so it refuses to install from an interpreter, package or
  configuration directory that another user could modify (`_root_controlled` in
  `autopwn_suite/daemon/daemon_installer.py`).
- **Standalone binaries** are not code-signed for Windows or macOS; their authenticity rests on
  the Sigstore-signed `SHA256SUMS` and release manifest, each has an SBOM generated from its
  build environment, and they are built twice from pinned inputs and must be identical, so a
  rebuilt binary can be compared with the signed hashes
  ([how](BUILDING.md#rebuilding-a-standalone-binary)).
- **Process limits.** The project has a single maintainer today
  ([continuity plan](CONTINUITY.md)); independent human review is configured but its
  strength depends on a second reviewer being available.
- **Closed advisory.** AUTOPWN-SA-2026-001 was fixed in v2.6.1 by the login system; the
  maintainer decided on 2026-10-16 that this closes it. v2.6.0 and earlier remain affected.
