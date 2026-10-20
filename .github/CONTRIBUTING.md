# Contributing

Pull requests with suggested changes and fixes are welcome directly: you do not need to open an
issue or ask the owners first. Describe the change and why it is needed in the pull request.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Add or update tests for behavior changes and document functional and security
   modifications under `Unreleased` in [CHANGELOG.md](../CHANGELOG.md). The
   maintainer assigns the release version using [SemVer](https://semver.org/).
4. Run `poetry check --lock`, `poetry run ruff check .` and `poetry run pytest`
   using Poetry 2.5.1, and follow the [coding standards](../docs/CODING_STANDARDS.md)
   (PEP 8 via Ruff for Python, ESLint for the dashboard JavaScript). All required
   CI checks must pass before merging. The maintainer reviews and merges accepted
   changes after a non-author human approves them. Bot/AI review cannot replace
   that approval; administrators must follow the same rule.
5. Use [Build instructions](../docs/BUILDING.md) and
   [Dependency management](../docs/DEPENDENCIES.md). Dependency changes must
   update both runtime manifests and the lockfile as applicable. Do not commit
   credentials, generated executables or unreviewable application binaries.
6. Sign off every commit under the
   [Developer Certificate of Origin](#developer-certificate-of-origin-dco).
7. For user-interface changes, follow the
   [accessibility requirements](#accessibility-and-internationalization-requirements).

Check the [roadmap](../docs/ROADMAP.md) for planned work and non-goals before
proposing a large feature.

The project roles and access inventory are in [GOVERNANCE.md](../GOVERNANCE.md).
Contributors must have the legal right to submit each contribution under the
repository's Apache-2.0 license, as required by GitHub's contribution terms.
Report security issues privately using [SECURITY.md](../SECURITY.md).

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a contributor license agreement. By signing off a commit, you certify
that you have the right to submit it under the repository's Apache-2.0 license.
**Every commit in a pull request must contain a `Signed-off-by` trailer** with
your real name and an e-mail address you control:

```text
Signed-off-by: Your Name <you@example.com>
```

Git adds this line when you commit with `-s`:

```sh
git commit -s -m "Describe the change"
# Add a missing sign-off to the latest commit
git commit --amend -s --no-edit
# Add sign-offs to every commit on your branch (rewrites history)
git rebase --signoff main
```

The name and e-mail must match your Git `user.name` and `user.email`. If you use the
GitHub web editor, enable sign-off for web commits in your own GitHub settings or
add the trailer to the commit message. The maintainer checks sign-off during review
and does not merge a pull request that lacks it. No automated DCO check is currently
configured. The requirement applies to contributions made after this section was
merged; earlier commits are not retroactively changed.

The full text of the certificate follows.

> Developer Certificate of Origin
> Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
> have the right to submit it under the open source license
> indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
> of my knowledge, is covered under an appropriate open source
> license and I have the right under that license to submit that
> work with modifications, whether created in whole or in part
> by me, under the same open source license (unless I am
> permitted to submit under a different license), as indicated
> in the file; or
>
> (c) The contribution was provided directly to me by some other
> person who certified (a), (b) or (c) and I have not modified
> it.
>
> (d) I understand and agree that this project and the contribution
> are public and that a record of the contribution (including all
> personal information I submit with it, including my sign-off) is
> maintained indefinitely and may be redistributed consistent with
> this project or the open source license(s) involved.

## Accessibility and internationalization requirements

The dashboard has known accessibility gaps listed in
[ACCESSIBILITY.md](../docs/ACCESSIBILITY.md), and the interface is English with a machine-translated Turkish catalog, as
described in [INTERNATIONALIZATION.md](../docs/INTERNATIONALIZATION.md). Changes to
`autopwn_suite/web_ui_static/` or other user-facing output must not make either worse:

- Use native controls (`<button>`, `<label for>`, `<dialog>`) or the correct ARIA
  roles, names and keyboard handling; do not add `onclick` to a plain `<div>`.
- Keep a visible focus indicator, at least 4.5:1 text contrast, and do not convey
  state by color alone. Announce dynamic status through `aria-live` regions.
- Verify the change with the keyboard alone and at 200% zoom, and use the checklist
  in ACCESSIBILITY.md in your pull request description.
- Keep new user-facing strings together, as complete sentences with placeholders (no
  string concatenation or hand-built plurals), use UTF-8 explicitly, and keep stored or
  exchanged data locale-independent (ISO 8601 timestamps, stable keys).

Reviewers check these points for any change that affects the dashboard or
user-visible text.

## Good first contributions

New or occasional contributors can pick any of these small, self-contained tasks. Each one
is a single focused pull request that does not need deep knowledge of the scanner. Open the
pull request directly, or comment on an issue first if you want to avoid duplicated work;
maintainers label starter issues `good first issue` and `help wanted`.

| Task | Where to start | Skills |
| --- | --- | --- |
| Add real `<label>` elements for the scan-form fields that only have a caption `<div>` | `autopwn_suite/web_ui_static/index.html`, gap list in [ACCESSIBILITY.md](../docs/ACCESSIBILITY.md) | HTML |
| Add a "skip to main content" link and check keyboard tab order | `autopwn_suite/web_ui_static/index.html` | HTML, CSS |
| Honor `prefers-reduced-motion` for dashboard animations | `autopwn_suite/web_ui_static/styles.css` | CSS |
| Raise the contrast of the muted `--text3` text color to at least 4.5:1 | `autopwn_suite/web_ui_static/styles.css` | CSS |
| Announce scan progress and completion to screen readers with a polite live region (not every terminal line) | `autopwn_suite/web_ui_static/app.js` (scan cards), gap list in [ACCESSIBILITY.md](../docs/ACCESSIBILITY.md) | JavaScript |
| Add tests for the uncovered lines of `autopwn_suite/random_user_agent.py` (error and empty-file paths) | `tests/unit/`, `python -m pytest --cov=autopwn_suite.random_user_agent` | Python, pytest |
| Add tests for the uncovered branches of `autopwn_suite/nist_search.py` | `tests/unit/test_nist_search.py` | Python, pytest |
| Improve an unclear error message or help text in `autopwn_suite/utils.py` (`cli()`), keeping the existing wording style | `autopwn_suite/utils.py` | Python |
| Fix a typo or unclear sentence in the documentation | `README.md`, `docs/` | Markdown |

Before you start, read the [coding standards](../docs/CODING_STANDARDS.md) and the test
policy below. Sign off your commits (`git commit -s`) as described in the DCO section.

## Code-quality warnings

The full rules, rationale and exceptions are in the
[coding standards](../docs/CODING_STANDARDS.md); contributions must comply with them.
Run the same quality checks locally that run in the required Poetry CI job:

```sh
poetry run ruff check .
node --check autopwn_suite/web_ui_static/app.js
node --check autopwn_suite/web_ui_static/web_security.js
node --check autopwn_suite/web_ui_static/auth.js
node --check autopwn_suite/web_ui_static/login.js
npx --yes eslint@10.12.0 --config eslint.config.mjs autopwn_suite/web_ui_static
poetry run python scripts/export_locked_requirements.py --check
poetry run python scripts/i18n_messages.py check --lang tr  # needs GNU gettext (msgfmt)
```

Ruff 0.17.1 enforces PEP 8 (`E`, `W`), Pyflakes (`F`), flake8-bugbear (`B`) and
sorted imports (`I`) with a 200-column limit, as configured in `pyproject.toml`. Any
finding fails the check; resolve it before merge (`ruff check . --fix` applies the safe
fixes). ESLint applies the explicit rule set in `eslint.config.mjs` to the dashboard
scripts. Warnings raised by this project's own code (deprecated APIs, syntax warnings)
are errors under `pytest`. Do not silence a real defect; a justified exception must be
narrow, explained where it is configured, and called out in the pull request. Node is
needed for these developer checks, not to run the Python application. Shared pytest
fixtures and intentional public re-exports use explicit `name as name` imports so they
remain registered/exported without unused-import warnings. Security findings follow
[the separate SCA/SAST policy](../docs/SECURITY_TESTING.md).

## Test policy and interpreting results

Run `poetry run pytest` locally with Python 3.10+ after installing the dependencies
in [BUILDING.md](../docs/BUILDING.md). Pytest runs unit and integration tests in
`tests/`, including native Nmap contracts, configuration/offline behavior, web
probe budgets, dashboard/API/scheduler state, persistence, provider parsing and
release/security gates. Install Nmap for loopback integration tests. Tests use
synthetic/mock targets where possible; never substitute an unauthorized host.

CI runs the Poetry suite on every PR to main and every main push. It requires
all tests to pass and at least **80% branch-aware overall coverage**; failures,
errors or coverage below the threshold block merge. Read the failing assertion
and traceback, repair the behavior and rerun the affected tests, then the suite.
Review skipped tests and explain any new skip; a skipped case is not evidence
that its behavior passed. The separate Linux/macOS jobs import the app and run
a loopback scan; CodeQL and the [security policy](../docs/SECURITY_TESTING.md)
also run on every change. Checks rerun after pushes to an open PR.

Every **major behavior change** must add or update automated tests: new features,
interfaces, permission or trust boundaries, data formats/storage, scheduling,
dependency behavior, and changes to scan results, cancellation or limits. Tests
must exercise expected behavior, failure paths and relevant boundary cases;
bug fixes need a regression demonstrating the bug. Reviewers check this before
approval. Documentation-only edits need no redundant behavior test. Update the
[threat model](../docs/THREAT_MODEL.md) for new features or breaking changes that
affect security boundaries.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to making participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or
advances
* Trolling, insulting/derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or electronic
  address, without explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate,
threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project team. All complaints will be reviewed 
and investigated and will result in a response that is deemed necessary 
and appropriate to the circumstances. The project team is obligated to 
maintain confidentiality with regard to the reporter of an incident.
Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4,
available at [http://contributor-covenant.org/version/1/4][version]

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
