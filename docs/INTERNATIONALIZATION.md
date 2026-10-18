# Internationalization and localization

## Current status

AutoPWN Suite is **English-only**. There is no translation framework, no message
catalog and no language selection. User-facing text is written directly in the
source:

- CLI and daemon messages in the Python modules (`autopwn_suite/cli.py`, `autopwn_suite/*.py`),
  rendered through `rich`.
- Dashboard text in `autopwn_suite/web_ui_static/index.html`, `login.html`, `app.js`,
  `auth.js`, `login.js` and `web_security.js`; both HTML pages declare `lang="en"`.
- Reports, notification e-mails, web-check findings and remediation text generated in
  Python (for example `autopwn_suite/report.py` and `autopwn_suite/web/`).
- Documentation, issues and pull-request discussion are in English
  (OpenSSF criterion `english`).

The project does not claim to be localized and no translation is planned to ship
before the groundwork below is reviewed ([ROADMAP.md](ROADMAP.md), Q2 2027).

## Why this is acceptable now

- AutoPWN Suite is a specialist, operator-facing security tool. Its output
  includes protocol names, CVE descriptions, Nmap output, HTTP evidence and exploit
  titles that originate from English-language external sources (NVD, Exploit-DB,
  Nmap and target responses) and are not translated by the project.
- The project is maintained by one volunteer ([GOVERNANCE.md](../GOVERNANCE.md)),
  who can review English changes but cannot responsibly review translations
  of security wording in many languages. A partial or machine-translated interface
  could mislead an operator about risk and scope.
- Hard-coded text is the main cost of adding localization later, so the practical
  step today is to keep that cost from growing (see the contributor guidance below)
  rather than to ship an unreviewed translation layer.

## Plan

1. **Keep new text localizable** by following the guidance below in every change.
2. **Inventory (Q2 2027):** list user-facing strings by surface (CLI, dashboard,
   reports, notifications, web-check findings) and mark text that is protocol data and
   must not be translated.
3. **Centralize:** move dashboard strings into one JavaScript module/object and CLI
   and report strings into one Python module per surface, referenced by key. Keep
   behavior identical and covered by the existing tests.
4. **Evaluate a mechanism** (for example Python `gettext` and a JavaScript message
   map) and document the decision, including how translations are reviewed and
   which language the machine-readable output (`JSON`, API) keeps. API field names,
   status codes and JSON keys remain English and stable.
5. **Accept translations** only when a named reviewer who reads the target language
   is willing to maintain them. Untranslated strings fall back to English.

This plan depends on contributor capacity and may change. If a reviewer is available
earlier, open an issue to discuss starting with step 3.

## Guidance for contributors (applies now)

- **Keep strings in one place.** Put a new user-facing message in a clearly named
  constant or a single helper near its feature, not scattered across conditionals
  and not repeated.
- **Do not build sentences by concatenation.** Use one complete message with named
  placeholders (`f"{count} hosts scanned"`, not `"scanned " + count + " hosts"`),
  because word order and plurals differ between languages. Avoid assembling
  grammatical pieces such as articles and plural `s` by hand; write explicit singular
  and plural messages or a neutral form (`Hosts scanned: 3`).
- **Do not embed text in logic.** Never compare against displayed text, parse
  your own messages, or derive behavior from a label. Use stable identifiers
  (status codes, enum values, keys) and map them to display text at the edge.
- **Separate data from presentation.** The REST API, JSON exports and stored
  settings must contain locale-independent values: ISO 8601 UTC timestamps,
  numbers in plain form, English-stable enum keys.
- **UTF-8 everywhere.** Open and write files with an explicit `encoding="utf-8"`
  (the existing code does so for settings, profiles, schedules and reports). Serve
  and declare HTML/JSON as UTF-8, and do not assume ASCII hostnames, banners or
  evidence. Treat target-supplied text as arbitrary bytes that may not be valid
  UTF-8 and decode with a replacement strategy rather than crashing.
- **Locale-independent behavior.** Do not depend on the system locale for
  parsing, sorting or comparison. Sort by stable keys (IP address, severity rank,
  timestamp), not by localized text. Do not use locale-dependent `strftime("%b")`
  month names or `%c` for stored or exchanged values; use ISO 8601. Dashboard
  display of dates and numbers may use the browser locale
  (`toLocaleString`, `Intl`) for presentation only.
- **Plan for expansion and direction.** UI text can be much longer in other languages:
  avoid fixed-width containers and truncating labels, and do not rely on
  all-caps CSS or letter-spacing for meaning. Do not position text with
  left/right assumptions that would break right-to-left languages; prefer logical
  CSS properties in new code.
- **No text in images or icons.** Use real text with accessible names
  ([accessibility](ACCESSIBILITY.md)).
- **Avoid slang, idioms and jokes** in messages and documentation, and avoid
  culture-specific examples (names, addresses, date formats) when a neutral example works.
- **Document the user-visible change** in [CHANGELOG.md](../CHANGELOG.md) like any
  other behavior.

## Known limitations

- Some dashboard messages concatenate fragments and build plurals by hand (for example
  `'CVE'+(vc>1?'s':'')` and `'Could not load the scan report: ' + e.message` in `app.js`).
- Some timestamps are shown using `strftime("%b %d %Y %H:%M:%S")` (for example in
  CLI/report timestamps) and the dashboard formats dates with `toLocaleString()`.
  Stored job and schedule timestamps use ISO 8601 UTC.
- The generated PoC, remediation and report text is English-only.
- CVE, exploit and Nmap data are shown in the language supplied by their sources.

Reports of internationalization problems (for example mojibake or a crash on a
non-ASCII hostname or banner) are bugs: file a
[GitHub issue](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/new/choose) with the
input that caused it.
