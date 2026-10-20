# Internationalization and localization

## Current status

AutoPWN Suite ships a working localization mechanism with **English (source) and
Turkish** as the first translated language. Localization covers:

- CLI, daemon and library messages in the Python modules (`autopwn_suite/cli.py`,
  `autopwn_suite/*.py`), via Python `gettext` (`autopwn_suite/i18n.py`). Every translatable
  string is wrapped with `_()` (or `ngettext()` for plurals) and extracted into
  `autopwn_suite/locales/autopwn.pot`; `autopwn_suite/locales/tr/LC_MESSAGES/autopwn.po`
  holds the Turkish catalog, compiled to `autopwn.mo`. The dashboard's notification texts sit in f-strings
  that `xgettext` cannot read, so `autopwn_suite/web_ui.py` lists them with `N_()`; a test checks the list.
- Reports, notification e-mails and web-check findings' static labels in
  `autopwn_suite/report.py` and `autopwn_suite/web/*.py` are translated the same way.
  CVE descriptions, exploit titles, PoC bodies and other third-party security
  data from NVD/Exploit-DB/Nmap/target responses are **not** translated: they
  are external data, not UI text, and nothing can sensibly machine-translate
  advisory prose without risking a misleading rewrite.
- Two internal exceptions, by design. `web_ui._resume_web_options` reads the English text of the
  web-coverage issues "Query parameter limit reached; coverage is limited." and "Response size
  limit reached; content coverage is limited." (and of two unwrapped messages) to decide which limits to
  raise when a scan resumes, so those messages are not translated; a test checks they stay out of the
  catalog. And `autopwn_suite/web/webvuln.py`'s web-scan
  coverage tracker matches a few `warning`/`error` log messages against a
  hardcoded English keyword list to decide whether a scan should report
  itself as "partial" (see the comment at `ScanLog.logger` in that file).
  Those specific messages are deliberately left untranslated so that
  detection keeps working regardless of the active language; every other
  diagnostic message in the same files is translated normally.
- The REST API, JSON exports and stored settings remain English-stable (human-readable text that is stored
  with scan results, such as web-coverage issue text, uses the language the server ran in):
  `jsonify()` error responses add a machine-readable `"code"` field
  alongside the existing English `"error"` text (which is unchanged, so
  existing integrations and tests keep working), and the dashboard looks up
  `"code"` to render a localized message instead of parsing English prose.
- Dashboard text in `autopwn_suite/web_ui_static/` is localized via
  `autopwn_suite/web_ui_static/i18n.js`, a dependency-free `{en, tr}` dictionary
  with `t(key, vars)`/`tErrorCode(code, fallback)` lookups, `data-i18n*`
  attributes on static HTML, and a language `<select>` on both the dashboard
  (Settings) and the pre-auth sign-in page. The sign-in page is public, so it carries its own small
  `{en, tr}` table in `login.js` (a test keeps it equal to `i18n.js`) and the dictionary stays behind sign-in. Switching reloads the page, so text that the scripts build is
  rendered again in the new language. The choice persists in
  `localStorage` and is sent to the backend on every API call via the
  `X-App-Language` request header (currently informational; responses still
  carry the stable `"code"` field above for the frontend to localize).
  `index.html`/`login.html` declare a static `lang="en"` attribute that
  `i18n.js` updates to the active language at load and on every switch.
- Documentation, issues and pull-request discussion stay in English
  (OpenSSF criterion `english`).

Language selection: `--lang {en,tr}` (or `--language`) on the command line,
else the `AUTOPWN_LANG` environment variable, else the last explicit choice (persisted to
`language.txt` next to `update_channel.txt` in the data directory: `AUTOPWN_DATA_DIR` or the per-user
default), else the system locale (`LC_ALL`/`LC_MESSAGES`/`LANG`), else English. A language chosen
via `--lang` is remembered for later invocations.

The initial Turkish catalog is machine-translated and every entry is marked
`#, fuzzy` in `autopwn.po` — functional (gettext still compiles and serves
fuzzy entries) but not yet reviewed by a Turkish-speaking maintainer.
Security-meaning strings in particular (offline-mode warnings, TLS/certificate
warnings, root/permission warnings, destructive-action confirmations) need a
native-speaker review pass before being trusted in a live engagement; track
remaining work with `msgattrib --only-fuzzy autopwn_suite/locales/tr/LC_MESSAGES/autopwn.po`.

## Why machine translation, reviewed incrementally

- AutoPWN Suite is a specialist, operator-facing security tool, and a wrong
  translation of risk-relevant wording is worse than no translation. Shipping
  the mechanism with fuzzy-marked machine translation makes the feature
  immediately usable while keeping an explicit, trackable worklist for
  correctness review, rather than blocking the whole feature on one
  volunteer reviewing ~300 strings by hand before anything ships.
- The project is maintained by one volunteer ([GOVERNANCE.md](../GOVERNANCE.md)).
  Fuzzy markers mean no string silently claims to be reviewed when it isn't.
- `scripts/i18n_messages.py` wraps `xgettext`/`msgmerge`/`msgfmt` for
  `extract` (regenerate `autopwn.pot`), `merge --lang tr` (fold new strings
  into `tr.po`), `compile --lang tr` (regenerate `tr.mo`) and
  `check --lang tr` (CI drift guard: fails if `tr.mo` doesn't match `tr.po`).

## Plan

1. **Keep new text localizable** by following the guidance below in every change
   — wrap new user-facing Python strings with `_()`/`ngettext()`, run
   `python scripts/i18n_messages.py extract` and `merge --lang tr`, and add a
   translation (fuzzy is fine) before merging. For new dashboard strings, add
   a key to both the `en` and `tr` dictionaries in `i18n.js` and use `t()`/
   `data-i18n*` instead of a literal string.
2. ~~**Dashboard JS pass**~~ — done: `autopwn_suite/web_ui_static/i18n.js`,
   `data-i18n*` attributes on `index.html`/`login.html`, a language selector
   on each, and the `app.js`/`web_security.js` retrofit.
3. **Review fuzzy entries:** a named reviewer who reads Turkish works through
   `msgattrib --only-fuzzy`, starting with security-meaning strings, and clears
   the fuzzy flag as each is confirmed correct. This also covers the Turkish
   half of `i18n.js`'s dictionary, which is machine-translated the same way.
4. **Accept additional languages** only when a named reviewer who reads that
   language is willing to maintain it; add it to `SUPPORTED_LANGUAGES` in
   `autopwn_suite/i18n.py` once a reviewed (or explicitly fuzzy-flagged, same policy
   as above) catalog exists, and add a matching dictionary to `i18n.js`.
   Untranslated/missing strings fall back to English.

## Guidance for contributors (applies now)

- **Wrap new Python user-facing strings with `_()`.** Use `_("...")` (installed
  globally by `autopwn_suite/i18n.py`, no per-file import needed) or `ngettext(singular,
  plural, n)` for countable messages. `xgettext` cannot extract placeholders from
  an f-string, so interpolate with `.format()` instead:
  `_("Target {target} seems to be offline.").format(target=target)`, not an
  f-string. After adding or changing a string, run
  `python scripts/i18n_messages.py extract` then
  `python scripts/i18n_messages.py merge --lang tr` to fold it into the Turkish
  catalog (a fuzzy/untranslated entry is fine — it falls back to English), then
  `compile --lang tr`.
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
  UTF-8 and decode with a replacement strategy rather than crashing. Scanned
  text keeps every printable character of every script, but `printable` removes
  its control, bidirectional and zero-width characters, including the zero-width
  joiner and non-joiner and the Mongolian vowel separator that some scripts use for
  shaping, so that a target cannot
  forge a line or reorder what the operator reads; the text shown can differ from
  the bytes the host sent in that respect.
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

- The Turkish CLI/report catalog (`autopwn.po`) and the Turkish half of
  `i18n.js`'s dictionary are both machine-translated and pending
  native-speaker review (see "Current status" above); the CLI side is
  tracked with `msgattrib --only-fuzzy`, the dashboard side has no equivalent
  tracked-review tooling yet since `i18n.js` has no fuzzy-marker convention.
- `autopwn_suite/web/webvuln.py` deliberately leaves a handful of coverage-tracking
  log messages untranslated so its English-keyword-based "scan is partial"
  detection keeps working in every language; see the comment on `ScanLog`
  in that file before translating a message there.
- Some timestamps are shown using `strftime("%b %d %Y %H:%M:%S")` (for example in
  CLI/report timestamps) and the dashboard formats dates with `toLocaleString()`.
  Stored job and schedule timestamps use ISO 8601 UTC.
- The generated PoC and remediation text is English-only.
- CVE, exploit and Nmap data are shown in the language supplied by their sources.

Reports of internationalization problems (for example mojibake or a crash on a
non-ASCII hostname or banner) are bugs: file a
[GitHub issue](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/new/choose) with the
input that caused it.
