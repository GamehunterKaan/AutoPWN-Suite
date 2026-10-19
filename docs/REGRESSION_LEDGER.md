# Regression-test ledger

Supports the OpenSSF `regression_tests_added50` criterion: regression tests must be
added for at least 50% of the bugs fixed in the last six months. This ledger covers
**2026-04-19 to 2026-10-19** and is rebuilt from public history, so anyone can check it.

## Method

1. Take every non-merge commit reachable from the 2.7.0 release in the window (**291**).
2. Select the commits that fix a defect in product behavior. Read the subject and the change:
   the words `fix`, `bug`, `vulnerability`, `prevent`, `resolve`, `regression`, `correct`, `handle`,
   `avoid`, `harden` and `escape` find some of them, but most fixes of 2.7.0 use other verbs
   (`stop`, `keep`, `report`, `bound`, `retry`).
3. Exclude changes that do not fix product behavior (a YAML typo, a version bump, wording, tooling,
   features added by the same pull request).
4. For each remaining fix, record whether the same commit changed files under `tests/`.

Reproduce with:

```bash
git log v2.7.0 --since=2026-04-19 --no-merges --format='%h %ad %s' --date=short
git show --name-only --format= <commit>
```

**Limits.** Choosing the fixes is a judgement, and a commit subject can miss a fix described in
other words. The ledger counts commits, not individual defects (a commit can fix several), and a
test in the same commit is taken as the regression test. Fixes that the pull request made to
its own earlier commits are listed too. There were no bug reports on the public issue tracker in
this window; the most recent bug report (#67) predates it.

## Ledger

| Commit | Date | Fix | Regression tests changed in the same commit |
| --- | --- | --- | --- |
| `ec9ef0f` | 2026-10-19 | Read a URL whole before a line separator turns into a space, and encode URLs alike in the PoC runtime | `tests/unit/test_hostile_text.py`, `tests/unit/test_hostile_urls.py`, `tests/unit/test_web_webvuln.py` |
| `50a9284` | 2026-10-19 | Keep the OS fingerprint's lines and clean what Nmap and the dashboard log when a scan fails | `tests/unit/test_hostile_nmap_text.py` |
| `e1352a1` | 2026-10-19 | Store the URLs of a finding as percent-encoding instead of raw control characters | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_hostile_text.py`, `tests/unit/test_hostile_urls.py` and others |
| `fb85285` | 2026-10-19 | Remove unpaired surrogates from printed text | `tests/unit/test_hostile_provider_text.py`, `tests/unit/test_hostile_text.py` |
| `e794c88` | 2026-10-19 | Clean NVD, local database and Exploit-DB text before it is printed | `tests/unit/test_hostile_provider_text.py` |
| `14bbf58` | 2026-10-19 | Clean Nmap banners, hostnames and script output when the XML is read | `tests/unit/test_hostile_nmap_text.py` |
| `cd778c3` | 2026-10-19 | Print web scan text as one line without control or layout characters | `tests/unit/test_hostile_text.py`, `tests/unit/test_web_dirbust.py`, `tests/unit/test_web_webvuln.py` |
| `2e5e2e0` | 2026-10-19 | Redact a typed target as one string and keep a quote or a Unicode space from cutting a URL | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_utils.py`, `tests/unit/test_web_dashboard.py` and others |
| `dc0f265` | 2026-10-19 | Show the typed target redacted in job records, exports and the CLI summary | `tests/unit/test_utils.py`, `tests/unit/test_web_dashboard.py` |
| `649a67e` | 2026-10-19 | Redact every query value, userinfo and fragment in web scan diagnostics | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_web_dirbust.py`, `tests/unit/test_web_poc.py` and others |
| `fed9a3c` | 2026-10-19 | Turn off a profile's schedules when saving it drops stored Nmap options | `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_review.py` |
| `35e79a7` | 2026-10-19 | Refuse Nmap options in the dashboard and check technique and ports against fixed lists | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_review.py` |
| `5a0a416` | 2026-10-19 | Send the scan and profile forms' structured Nmap controls and drop the free-text field | `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_static.py` |
| `4050493` | 2026-10-19 | Say what the umask does to the install directory and to a set-aside copy | `tests/unit/test_daemon_installer.py`, `tests/unit/test_web_ui.py` |
| `d4ab103` | 2026-10-19 | Restrict dashboard data files that an earlier release left readable | `tests/unit/test_web_ui.py` |
| `51fff63` | 2026-10-19 | Create the installed daemon configuration owner-only from its first byte | `tests/unit/test_daemon_installer.py` |
| `90f4ef2` | 2026-10-19 | Wrap the account form's new and confirm password pair by column width | `tests/unit/test_web_account_form_style.py` |
| `d79a8c0` | 2026-10-19 | Style and space the Settings account form like the other sections | `tests/unit/test_web_account_form_style.py` |
| `7868742` | 2026-10-19 | Make the sign-in challenge a signed cookie the server does not store | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_web_auth.py` |
| `975cdc0` | 2026-10-19 | Bound the Java trace signature, the length of crawled links and what a crawl keeps | `tests/unit/test_web_crawler.py`, `tests/unit/test_web_hostile_bodies.py`, `tests/unit/test_web_poc.py` |
| `1f25417` | 2026-10-19 | Bound every walk of the crawler's form analysis, including the one inside bs4 | `tests/unit/test_web_hostile_bodies.py` |
| `aef5436` | 2026-10-19 | Show a schedule the scheduler disabled, and document the set-aside files and the new fuzz targets | `tests/unit/test_web_ui_behavior.py` |
| `4ea7ff7` | 2026-10-19 | Bound the two hostile-body comparisons and the crawler's form analysis that the first bounds missed | `tests/unit/test_web_hostile_bodies.py` |
| `8840ab3` | 2026-10-19 | Reload the schedule list after editing a profile | `tests/unit/test_web_ui_behavior.py` |
| `2d34426` | 2026-10-19 | Disable a schedule only for a validation failure and describe overlap skips exactly | `tests/unit/test_web_ui_review.py` |
| `d0e5f58` | 2026-10-19 | Keep one copy of a partly invalid profiles or schedules file, not one per start | `tests/unit/test_web_ui.py` |
| `b06b43f` | 2026-10-19 | Write a disabled schedule to the server log as well as the dashboard log | `tests/unit/test_web_ui_review.py` |
| `8ce4ad4` | 2026-10-19 | Do not run a missed slot for a schedule that was just enabled or retimed | `tests/unit/test_web_ui.py` |
| `429953d` | 2026-10-19 | Treat deeply nested JSON as malformed input in the dashboard and fuzz harness | `tests/unit/test_fuzz_harnesses.py`, `tests/unit/test_web_auth.py`, `tests/unit/test_web_ui.py` |
| `4be702e` | 2026-10-19 | Retry the account file replacement that Windows refuses while it is open | `tests/unit/test_web_auth.py` |
| `07c8a63` | 2026-10-19 | Cap pending sign-in challenges per client address | `tests/unit/test_web_auth.py` |
| `188c69d` | 2026-10-19 | Skip a scheduled web scan in offline mode instead of completing it empty | `tests/unit/test_web_ui_review.py` |
| `79114a4` | 2026-10-19 | Disable a schedule that no longer validates instead of failing every minute | `tests/unit/test_web_ui_review.py` |
| `a693847` | 2026-10-19 | Do not start a scheduled scan while the previous one still runs | `tests/unit/test_web_ui_review.py` |
| `b432234` | 2026-10-19 | Run a daily or weekly schedule that missed its exact minute | `tests/unit/test_web_ui.py` |
| `409c3d6` | 2026-10-19 | Keep a profiles or schedules file the dashboard cannot load | `tests/unit/test_web_ui.py` |
| `d6f3cb3` | 2026-10-19 | Do not register an event-stream subscriber for HEAD /api/events | `tests/unit/test_web_ui.py` |
| `354af3a` | 2026-10-19 | Follow the chosen offline mode, not the NVD fallback, in the dashboard | `tests/unit/test_offline_scans.py` |
| `d3df974` | 2026-10-19 | Log the class of a failed test email, not the SMTP reply | `tests/unit/test_web_ui.py` |
| `be76aca` | 2026-10-19 | Copy a scan job's config under its lock in to_dict | `tests/unit/test_offline_scans.py`, `tests/unit/test_web_ui.py` |
| `57cb2b9` | 2026-10-19 | Release the resume data of a completed dashboard scan | `tests/unit/test_web_resume.py`, `tests/unit/test_web_ui.py` |
| `0b11873` | 2026-10-19 | Write dashboard settings, profiles and schedules owner-only | `tests/unit/test_web_ui.py` |
| `a1fa6d8` | 2026-10-19 | Count a lone-surrogate username as a failed sign-in | `tests/unit/test_web_auth.py` |
| `6b07f50` | 2026-10-19 | Keep the crawl order when bounding the links a checkpoint stores | `tests/unit/test_web_crawler.py` |
| `95619e0` | 2026-10-19 | Stop the search for common blocks at a deadline in body comparisons | `tests/unit/test_web_hostile_bodies.py` |
| `7ea3e32` | 2026-10-19 | Keep redacting every credential name that contains "pass" | `tests/unit/test_web_poc.py` |
| `1c8c454` | 2026-10-19 | Drop terminal control characters from web scan log lines and coverage notes | `tests/unit/test_web_webvuln.py` |
| `11596d7` | 2026-10-19 | Redact credential parameters without catching "author" and "bypass" | `tests/unit/test_web_poc.py` |
| `a2b55db` | 2026-10-19 | Poll descriptors that select() cannot take in the web transport | `tests/unit/test_web_transport_security.py` |
| `8efba4a` | 2026-10-19 | Record each web finding without copying all the earlier ones | `tests/unit/test_web_resume.py` |
| `1f0f4d8` | 2026-10-19 | Treat a host that cannot be IDNA-encoded as a failed connection | `tests/unit/test_web_transport_security.py` |
| `5b94bc5` | 2026-10-19 | Drop terminal control characters from finding text | `tests/unit/test_web_dirbust.py` |
| `b004172` | 2026-10-19 | Redact URLs in web scan log lines and coverage issues | `tests/unit/test_web_webvuln.py` |
| `b87be47` | 2026-10-19 | Bound the links the crawler keeps per page in the job checkpoint | `tests/unit/test_web_crawler.py` |
| `f552cf7` | 2026-10-19 | Bound the difflib comparisons of response bodies | `tests/unit/test_web_hostile_bodies.py` |
| `2c6a1ed` | 2026-10-19 | Read only the start of the first few headings in directory-listing detection | `tests/unit/test_web_hostile_bodies.py` |
| `0b8b08b` | 2026-10-19 | Read deeply nested HTML once in the XSS reflection check and the PoC parser | `tests/unit/test_web_hostile_bodies.py` |
| `a1089a6` | 2026-10-19 | Stop the dashboard webhook posts from following redirects | `tests/unit/test_web_ui.py` |
| `466e76a` | 2026-10-19 | Refuse the legacy -m log option in the dashboard's file-option check | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_nmap_progress.py`, `tests/unit/test_web_ui.py` |
| `ac23411` | 2026-10-19 | Keep each Python API Nmap argument whole when the scan arguments are joined | `tests/unit/test_api.py` |
| `3c2dbc5` | 2026-10-19 | Let --version and --help run when the data directory cannot be created | `tests/unit/test_paths.py` |
| `8cc170a` | 2026-10-19 | Do not follow redirects when posting the webhook report | `tests/unit/test_report.py` |
| `a53c599` | 2026-10-19 | Ignore a UTF-8 byte order mark and stray whitespace in key and secret files | `tests/unit/test_credential_files.py`, `tests/unit/test_utils.py` |
| `f687c8e` | 2026-10-19 | Validate --web-port and AUTOPWN_WEB_PORT instead of crashing the parser | `tests/unit/test_utils.py` |
| `64594f1` | 2026-10-19 | Make the Nmap install offer fail cleanly and stop the scan when it fails | `tests/unit/test_utils.py` |
| `2b371f8` | 2026-10-19 | Exit with status 1 when the config file or the Nmap install cannot be used | `tests/unit/test_scan_regressions.py`, `tests/unit/test_utils.py` |
| `c06334b` | 2026-10-19 | Build generated report names only from filesystem-safe characters | `tests/unit/test_utils.py` |
| `fb1fb09` | 2026-10-19 | Pass -6 to Nmap when every target is an IPv6 address | `tests/unit/test_nmap_progress.py` |
| `22765bd` | 2026-10-19 | Match Nmap file options by name and keep them out of dashboard scan flags | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_nmap_progress.py`, `tests/unit/test_web_ui.py` |
| `d95f177` | 2026-10-19 | Stop each noise host's Nmap when the noise scan ends and cap the host count | `tests/unit/test_scan_regressions.py`, `tests/unit/test_scanner.py` |
| `38cd1b2` | 2026-10-19 | Name a read-only file as a cause when a Windows replace is denied | `tests/unit/test_offline_scans.py`, `tests/unit/test_vulnerability_db.py` |
| `96930e1` | 2026-10-19 | Hash the staging prefix from the file name's bytes, not its UTF-8 text | `tests/unit/test_vulnerability_db.py` |
| `686bebd` | 2026-10-19 | Name a skipped, unpublished newest year in the update's final message and the docs | `tests/unit/test_vulnerability_db.py` |
| `ab1fc05` | 2026-10-19 | Keep the exit message on stderr and survive a failed save when a scan aborts | `tests/unit/test_offline_scans.py` |
| `e235a75` | 2026-10-19 | Blame a running scan only for a Windows file lock, and retry the final replace | `tests/unit/test_vulnerability_db.py` |
| `80f03e5` | 2026-10-19 | Bound the inflated size of one offline search, not only of each record | `tests/unit/test_vulnerability_db.py` |
| `0a64574` | 2026-10-19 | Remove the SQLite journal that a killed update left beside its staging file | `tests/unit/test_vulnerability_db.py` |
| `0b12a88` | 2026-10-19 | Bound and validate the records read from a copied vulnerability database | `tests/unit/test_vulnerability_db.py` |
| `4b7c4dd` | 2026-10-19 | Open a vulnerability database on a Windows UNC path | `tests/unit/test_vulnerability_db.py` |
| `218a720` | 2026-10-19 | Report the exploitability sub-score of an older CVSS version for v4 records | `tests/unit/test_nist_search.py` |
| `26fce2d` | 2026-10-19 | Remove staging files that a killed database update left behind | `tests/unit/test_vulnerability_db.py` |
| `1ddd7c4` | 2026-10-19 | Retry transient feed errors and tolerate an unpublished newest-year feed | `tests/unit/test_vulnerability_db.py` |
| `80b4f41` | 2026-10-19 | Say why a database update fails when a Windows scan holds the mirror open | `tests/unit/test_offline_scans.py`, `tests/unit/test_vulnerability_db.py` |
| `f47ec7b` | 2026-10-19 | Save the output and name both failures when an NVD lookup aborts a scan | `tests/unit/test_offline_scans.py`, `tests/unit/test_vulnerability_db.py` |
| `a05888f` | 2026-10-19 | Give the Nmap install commands the standalone binary's system library path, and accept any letter case in the wizard | `tests/unit/test_daemon_installer.py`, `tests/unit/test_utils.py` |
| `14bb9af` | 2026-10-19 | Poll quickly once a scan runs, keep keyboard focus on Start Scan, and survive a failed first render | `tests/unit/test_web_ui_behavior.py` |
| `a9d5193` | 2026-10-19 | Stop rebuilding scan cards on every update so Stop keeps focus and clicks | `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_static.py` |
| `60a352d` | 2026-10-19 | Poll the dashboard slowly unless a scan is running and never in a hidden tab | `tests/unit/test_web_ui_behavior.py` |
| `ee95f93` | 2026-10-19 | Show the host detail panel below the main area on narrow viewports | `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_static.py` |
| `fd6df22` | 2026-10-19 | Keep the reader's place in the terminal and list every scan in its filter | `tests/unit/test_web_ui_behavior.py` |
| `74dbb55` | 2026-10-19 | Resume the event stream after the last log entry so no line is lost or shown twice | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_web_auth.py`, `tests/unit/test_web_ui.py` and others |
| `95f55d7` | 2026-10-19 | Keep settings unsaveable when they failed to load at startup | `tests/unit/test_web_ui_behavior.py` |
| `9fae6d9` | 2026-10-19 | Announce toasts to assistive technology and stop the faded toast blocking clicks | `tests/unit/test_web_ui_static.py` |
| `922dcf5` | 2026-10-19 | Render vulnerability severity only as one of five fixed words | `tests/unit/test_web_ui_behavior.py` |
| `11fd4c9` | 2026-10-19 | Ignore a second click on Start Scan while the first request is in flight | `tests/unit/test_web_ui_behavior.py` |
| `67c2394` | 2026-10-19 | Report the HTTP status when starting a scan gets a non-JSON answer | `tests/unit/test_web_ui_behavior.py` |
| `37b79a5` | 2026-10-19 | Pass the profile-name toast the failure flag in the right position | `tests/unit/test_web_ui_behavior.py` |
| `2ab81f1` | 2026-10-19 | Let the container stop on SIGTERM instead of waiting for Docker to kill it | `tests/unit/test_entry_points.py` |
| `652d91e` | 2026-10-19 | Keep uninstalling when systemctl daemon-reload fails | `tests/unit/test_install_scripts.py` |
| `af94663` | 2026-10-19 | Hand the application directory to root and size sudo by the link's directory | `tests/unit/test_install_scripts.py` |
| `c520a5f` | 2026-10-19 | Make --daemon-uninstall remove the service | `tests/unit/test_daemon_installer.py` |
| `d2fa630` | 2026-10-19 | Start system programs from the standalone Linux binary with their own libraries | `tests/unit/test_daemon_installer.py`, `tests/unit/test_subprocess_env.py`, `tests/unit/test_utils.py` |
| `0413c81` | 2026-10-19 | Check the daemon's installation before the wizard and from the unit's view | `tests/unit/test_daemon_installer.py` |
| `bf36ab8` | 2026-10-19 | Restart the daemon when --daemon-install runs again | `tests/unit/test_daemon_installer.py`, `tests/unit/test_install_scripts.py` |
| `f15a8aa` | 2026-10-19 | Make the config wizard refuse what the config loader rejects | `tests/unit/test_daemon_installer.py` |
| `896506c` | 2026-10-19 | Let the daemon wait for its next round when discovery finds no hosts | `tests/unit/test_autopwn.py` |
| `12258f3` | 2026-10-19 | Stop staging a DESTDIR that sits inside the checkout into itself | `tests/unit/test_install_scripts.py` |
| `d0061e4` | 2026-10-19 | Keep the working virtual environment until its replacement is built | `tests/unit/test_install_scripts.py` |
| `53e083e` | 2026-10-19 | Expire cached NVD results after an hour and guard the cache with a lock | `tests/unit/test_nist_search.py` |
| `cbceba8` | 2026-10-19 | Drop raw-socket Nmap flags from custom flags when the scan is not run as root | `tests/unit/test_scanner.py` |
| `fdfec1b` | 2026-10-19 | Report a host that hit --host-timeout as timed out, not as having no open ports | `tests/unit/test_scan_regressions.py` |
| `185c793` | 2026-10-19 | Print banner, CVE and exploit text literally instead of as Rich markup | `tests/unit/test_fuzz_inputs.py`, `tests/unit/test_getexploits.py`, `tests/unit/test_scan_regressions.py` and others |
| `770f8d9` | 2026-10-19 | Stop the event stream from replaying the log history and cap the terminal | `tests/unit/test_web_auth.py`, `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_behavior.py` |
| `3673bd5` | 2026-10-19 | Show scan start and stop failures as toasts instead of only in the Terminal tab | `tests/unit/test_web_ui_behavior.py` |
| `56335b7` | 2026-10-19 | Stop FLASK_DEBUG from enabling Werkzeug's debugger in the dashboard | `tests/unit/test_web_ui.py` |
| `607010d` | 2026-10-19 | Log delivery failures as fixed text, not response or exception text | `tests/unit/test_report.py`, `tests/unit/test_web_ui.py` |
| `303a2d7` | 2026-10-19 | Write UTF-8 when Windows output is redirected or piped | `tests/unit/test_entry_points.py` |
| `fc4ff84` | 2026-10-19 | Send the requested report after an automatic NVD fallback | `tests/unit/test_offline_scans.py` |
| `fd46339` | 2026-10-19 | Create and install the daemon configuration owner-only | `tests/unit/test_daemon_installer.py` |
| `7a72c37` | 2026-10-19 | Let --create-config write a percent sign in a secret or URL | `tests/unit/test_daemon_installer.py` |
| `03e708b` | 2026-10-19 | Stop treating "no" as yes at the interactive confirmations | `tests/unit/test_utils.py` |
| `4b356c9` | 2026-10-19 | Keep directory discovery on the requested path when the root redirects | `tests/unit/test_web_dirbust.py`, `tests/unit/test_web_webvuln.py` |
| `c43ad41` | 2026-10-19 | Bound the regular expressions that read target response bodies | `tests/unit/test_web_hostile_bodies.py` |
| `3ec5bab` | 2026-10-18 | Stop logging the webhook URL when a delivery fails (AUTOPWN-SA-2026-006) | `tests/unit/test_credential_files.py`, `tests/unit/test_report.py`, `tests/unit/test_web_ui.py` |
| `94cd936` | 2026-10-16 | Stop echoing exception text in dashboard auth responses | `tests/unit/test_web_auth.py` |
| `11d2c9a` | 2026-10-16 | Add dashboard login, verified TLS by default, credential files and loopback default | `tests/__init__.py`, `tests/auth_helpers.py`, `tests/conftest.py` and others |
| `e3ef359` | 2026-10-15 | Return safe validation errors when resuming scans | `tests/unit/test_web_resume.py` |
| `6debf3c` | 2026-10-15 | Keep failed crawl pages pending for subsequent resume attempts | `tests/unit/test_web_resume.py` |
| `f7bea03` | 2026-10-15 | Keep timed-out Nmap hosts incomplete and rescan them on resume | `tests/unit/test_web_resume.py` |
| `b3bd587` | 2026-10-14 | Continue remaining parameter batches and retain cumulative coverage totals | `tests/unit/test_web_resume.py` |
| `128872d` | 2026-10-14 | Web findings badge count and webhook toggle persistence across restarts | `tests/unit/test_web_security_ui.py`, `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_behavior.py` |
| `7f01a9f` | 2026-10-14 | Guarantee Nmap cleanup during setup failures and short timeouts | `tests/integration/test_nmap_process.py`, `tests/unit/test_nmap_backend.py`, `tests/unit/test_nmap_progress.py` |
| `40c4a68` | 2026-10-14 | Declare dashboard dependencies for production installs | **none** |
| `d40230b` | 2026-10-12 | Preserve web evidence disclosures across dashboard refreshes | `tests/unit/test_web_security_ui.py` |
| `e34e3b0` | 2026-10-08 | Exception detail exposure in web API validation (CodeQL `py/stack-trace-exposure`, alerts #6-#10, fixed 2026-10-08) | `tests/unit/test_web_ui_review.py` |
| `6785056` | 2026-10-05 | Dashboard evidence display, scheduling and persistence | `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_review.py` |
| `f11ca3e` | 2026-10-05 | Web probing, report delivery and daemon cleanup | `tests/unit/test_daemon_installer.py`, `tests/unit/test_getexploits.py`, `tests/unit/test_report.py` and others |
| `82a26aa` | 2026-10-05 | Configuration, target handling and scan-result correctness | `tests/unit/test_api.py`, `tests/unit/test_autopwn.py`, `tests/unit/test_scan_regressions.py` and others |

### Excluded from the count

| Commits | Reason |
| --- | --- |
| `e04ebe8`, `1b5a845`, `5a54b4f`, `ec45b8a`, `928609d`, `2738a4a`, `83e91ff`, `ecd9277`, `e996408` | Added by this pull request, not a defect in a release. |
| `6abdfaf`, `7009ea6`, `4a45c0e`, `672550f`, `53ebf5b`, `6ba0669`, `da478b2`, `a8b1d8b`, `de6e8c7`, `68a5458`, `9206d25`, `9895533`, `2da00e0` | Release, build and CI tooling for the new install and publishing methods. |
| `1b0cc5a`, `7a5fb4f`, `cc392ef`, `bbe89fc` | Wording, comments, imports or license headers only. |
| `ee0b2df` | Test additions only (seeded fuzz cases). |
| `938b9f5`, `bb256b0` | Additions or behavior changes whose subject does not describe a defect (judgement). |
| `29584b8` | Typo in a funding YAML key; not product behavior. |
| `ade01bc` | Version bump with a test adjustment; not a defect fix. |

## Result

**137 of 138** product-defect fixes in the window (99%) added or changed automated tests in the
same commit, above the 50% requirement. CodeQL alerts #4 and #5 (DOM XSS and attribute
sanitization) and #1 (workflow permissions) were fixed outside the window (2026-04-15 and
2025-10-18).

## Keeping this current

The [contribution rules](../.github/CONTRIBUTING.md#test-policy-and-interpreting-results) require a regression
test with every bug fix. Maintainers add each new fix here at release time, or re-run the method above before
answering the criterion again.
