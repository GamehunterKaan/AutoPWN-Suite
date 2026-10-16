# Accessibility

This document states what accessibility support the web dashboard and the project
documentation actually provide, lists known gaps, and sets requirements for
contributors. It is based on a manual review of the dashboard source in
`modules/web_ui_static/` on 2026-10-16. **The project makes no claim of conformance
with WCAG 2.x or any other accessibility standard**, and no automated or assistive-
technology audit has been performed. The CLI, Python API and REST API need no visual
interface and are usable from a terminal or screen reader as text.

## Scope

| Surface | Notes |
| --- | --- |
| CLI (`autopwn.py`) | Text output through `rich`. Colors are used for emphasis; the text itself carries the meaning. Scan results can be exported as JSON/HTML/text reports. |
| Web dashboard (`index.html`, `app.js`, `web_security.js`, `styles.css`) | Single-page application with a left scan form, a main tabbed area and a right detail panel. Dark theme only. |
| Sign-in page (`login.html`, `login.css`, `login.js`) | A small separate form page. |
| Documentation (`README.md`, `docs/*.md`, `.github/*.md`) | Markdown rendered by GitHub, which provides headings, links and responsive layout. |

## What is present today

Only features that exist in the source are listed.

- Both HTML pages declare `lang="en"`, a document `<title>` and a responsive viewport.
- The dashboard uses landmark elements (`<header>`, `<aside>`, `<main>`) and a
  single `<h1>` for the Web Security page; the sign-in page uses `<main>` and `<h1>`.
- The sign-in form associates `<label for>` with both inputs, sets `autocomplete`
  attributes and announces status messages with `role="status" aria-live="polite"`.
  The Account form in Settings and the local-database status use the same pattern.
- Web finding details and the resume settings use the native `<dialog>` element
  opened with `showModal()`, which provides focus containment and Escape-to-close
  in browsers. Dialogs are labelled through `aria-labelledby`, and their close
  buttons have `aria-label`.
- Scan progress bars expose `role="progressbar"` with `aria-valuemin`, `aria-valuemax`,
  `aria-valuenow`, `aria-valuetext` and an `aria-label`.
- The Web Security page uses real `<button>` elements for finding rows and
  detail tabs, with a visible `:focus-visible` outline (2 px accent color) and an
  `aria-label` for the tab group.
- Primary body text on the dashboard background is high contrast (about 14:1 for
  the main text color).
- Layout adapts at 1100 px and 760 px widths and the page scrolls on narrow
  screens; the viewport zoom is not disabled.
- A `.sr-only` utility class exists for visually hidden text.
- Many form fields in Settings and Web controls use `<label for>`; boolean options use
  checkboxes, and one switch has `role="switch"`.

## Known gaps and issues

These are real limitations of the current dashboard. They are tracked here until
fixed; the fixes are planned in [ROADMAP.md](ROADMAP.md) (Q1 2027) and accepted from
contributors at any time.

| Priority | Gap | Where | Planned fix |
| --- | --- | --- | --- |
| High | The main tabs (Active Scans, Hosts, Vulnerabilities, Terminal, Settings) and several controls such as the advanced-options toggle are `<div>` elements with `onclick`, so they are not reachable or operable by keyboard and expose no role or selected state. | `index.html` (`#tabs`, `#adv-toggle`, host and scan cards in `app.js`) | Use `<button>` or `role="tab"` with `aria-selected`, `tablist`/`tabpanel` relationships and arrow-key support. |
| High | Most scan-form fields use a `<div class="fl">` caption instead of a `<label>`, so screen readers do not announce a name for them (the file has far fewer `<label>` elements than `<input>`/`<select>` controls). | `index.html` scan form | Associate each caption with its control using `<label for>` or `aria-labelledby`. |
| High | Text input, select and textarea focus is shown only by a border-color change after `outline:none`; the focus color against its background is about 4:1 and the unfocused border is nearly invisible. Buttons, toggles and tabs lack a custom focus indicator. | `styles.css` | Restore a high-contrast `:focus-visible` outline for all interactive elements. |
| High | Secondary text colors fail contrast: the "muted" tab, caption and footer color (`--text3`) is about 2.8:1 to 2.9:1 on the panel backgrounds, below the 4.5:1 normal-text minimum. Many labels are 10-11 px uppercase monospace. | `styles.css` | Raise muted text contrast to at least 4.5:1 and avoid text smaller than about 12 px. |
| Medium | Live scan output and toast messages are not in `aria-live` regions, so progress changes, errors and completed scans are not announced. | `app.js` (`toast`, terminal view, scan cards) | Add polite live regions for status, errors and completion (avoid announcing every terminal line). |
| Medium | Status is communicated mostly by color (severity, scan state pills, progress). Text labels exist for many but not all states. | `styles.css`, `app.js` | Ensure every color-coded state has a text or icon equivalent. |
| Medium | No skip link, and keyboard focus order across the three-panel layout has not been tested. | `index.html` | Add a skip-to-main link; verify tab order. |
| Medium | Icon-only links in the left footer use the `title` attribute only; the dashboard logo SVG and some decorative icons have no text alternative or `aria-hidden`. Links with `target="_blank"` do not warn that they open a new window. | `index.html` | Provide accessible names and mark decorative SVGs `aria-hidden`. |
| Medium | No `prefers-reduced-motion` handling for the pulsing and sliding indicators (`pb`, `slide` animations) and transitions. | `styles.css` | Disable or reduce animation when the user asks for reduced motion. |
| Low | The dashboard is dark-theme only and does not honor `prefers-color-scheme`, `prefers-contrast` or forced-colors modes. | `styles.css` | Add a light theme and respect high-contrast preferences. |
| Low | Exported PDF/HTML reports are generated from page markup and have not been checked for document structure or tagging. | `app.js` print/export functions | Review report markup for headings, table headers and language. |
| Low | Numeric and date values use the browser locale via `toLocaleString()` in the dashboard but are not marked up with machine-readable `<time>` elements. | `app.js` | Optional improvement. |
| Not assessed | Screen-reader behavior (NVDA, JAWS, VoiceOver, Orca), browser zoom to 200%/400%, and the dashboard with Windows High Contrast have not been tested. | all | Test with at least one screen reader and at 200% zoom and record the results here. |

## Contributor checklist for UI changes

Every dashboard change should meet these requirements, and reviewers check them
([CONTRIBUTING.md](../.github/CONTRIBUTING.md)):

- [ ] Every control is a native interactive element (`<button>`, `<a href>`,
      `<input>`, `<select>`) or has the correct ARIA role, name, state and keyboard
      handling. Never attach `onclick` to a `<div>` without these.
- [ ] Every form field has a programmatic name (`<label for>` or `aria-labelledby`),
      and validation errors are associated with the field and announced.
- [ ] A visible `:focus-visible` indicator is present on every interactive element
      and is not removed with `outline:none` unless a replacement with at least 3:1
      contrast is provided.
- [ ] Text contrast is at least 4.5:1 (3:1 for large text and UI component
      boundaries). Check new colors before adding them.
- [ ] Information is not conveyed by color alone; add text or an icon with an
      accessible name.
- [ ] Dynamic changes (progress, errors, completion) are announced with
      `role="status"`/`aria-live="polite"` or `role="alert"` for urgent errors.
- [ ] Dialogs use `<dialog>` or an equivalent that traps and restores focus and closes
      with Escape; headings keep a logical order.
- [ ] The interface works with keyboard only, at 200% zoom and in a narrow viewport,
      and honors `prefers-reduced-motion` for new animations.
- [ ] Images and icons have text alternatives or are hidden from assistive technology
      when decorative.
- [ ] User-facing strings remain plain, concise English that follows the
      [internationalization guidance](INTERNATIONALIZATION.md).

Fixing a gap listed above is a good first contribution. Reference this document in the
pull request and update the table when a gap is closed.

## Documentation accessibility

- Documentation is Markdown with descriptive link text, ordered headings and tables
  that have header rows; avoid "click here" links in new text.
- Diagrams (for example the Mermaid chart in [ARCHITECTURE.md](ARCHITECTURE.md)) are
  accompanied by a numbered prose description of the same flow.
- Screenshots in the README are illustrations; new screenshots should be described
  in nearby text, and instructions must not depend only on an image.
- Use plain language and spell out acronyms on first use. Write commands in fenced
  code blocks.

## Reporting accessibility problems

Report accessibility barriers as ordinary
[GitHub issues](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/new/choose),
including the page or tab, browser, assistive technology (if any) and what could not
be done. Barriers that block use of the dashboard for people who rely on assistive
technology are treated as bugs, subject to the volunteer-maintenance limits in
[SUPPORT.md](../SUPPORT.md). Because the CLI and API are available, those can serve as
alternatives for scanning while the dashboard gaps are addressed.
