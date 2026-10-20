# Coding standards

Contributions must follow these standards. CI enforces them automatically in the
required `poetry-tests` job, so a change that violates them cannot be merged.

## Python

- **Style guide:** [PEP 8](https://peps.python.org/pep-0008/), checked by Ruff
  (`E`, `W` pycodestyle rules), with [PEP 257](https://peps.python.org/pep-0257/)
  docstring conventions where a docstring is written.
- **Line length:** 200 columns instead of PEP 8's 79. The code base already uses long,
  dense expressions in scanners and templates; the limit keeps those readable without a
  mass rewrite. New code should still prefer shorter lines.
- **Correctness rules:** Pyflakes (`F`) and flake8-bugbear (`B`) catch undefined names,
  unused imports, mutable defaults, late-binding closures, missing `raise ... from` and
  implicit `zip` truncation.
- **Imports:** sorted and grouped by Ruff's isort rules (`I`).
- **Target version:** Python 3.10 (`target-version = "py310"`); do not use newer syntax.
- **Configuration and exceptions:** all settings live in `pyproject.toml` under
  `[tool.ruff]`. Per-file exceptions are intentional and explained there:
  long literal templates (`autopwn_suite/web/details.py`, `autopwn_suite/web/poc.py`) and test fixtures
  (`E501`), and callbacks run immediately inside their loop (`B023`). Prefer fixing the code
  to adding an exception, and explain any new exception in the pull request.

Run locally:

```bash
poetry run ruff check .          # report violations
poetry run ruff check . --fix    # apply safe fixes (import order, whitespace)
```

## JavaScript (dashboard, `autopwn_suite/web_ui_static/`)

- Plain browser scripts (no bundler, no framework), ECMAScript 2022, strict mode.
- Enforced by ESLint with the explicit rule set in `eslint.config.mjs`: no undefined or
  unused local variables, `===` instead of `==`, `const` where a binding is never
  reassigned, no `var`, no `eval`/implied `eval`, no unreachable or duplicate code.
- Every script must also pass `node --check`.
- Build user-visible HTML only from escaped values (see existing `escape()` helpers);
  never assign untrusted text with `innerHTML` unescaped.

Run locally (Node.js 20 or newer):

```bash
npx --yes eslint@10.12.0 --config eslint.config.mjs autopwn_suite/web_ui_static
```

## Warnings policy

The aim is the strictest setting that is practical for each tool:

- **Ruff/ESLint:** any violation fails CI; there is no warning tier.
- **Python runtime warnings in tests:** `SyntaxWarning`, and `DeprecationWarning` or
  `FutureWarning` raised by this project's own code (`autopwn_suite`), are
  errors under `pytest`. Using a deprecated API therefore fails the build instead of
  accumulating. Third-party deprecation warnings are not fatal because they differ between
  supported Python versions and are outside a contributor's change; they are reviewed when
  dependencies are updated.
- **Tests that intentionally disable a protection** (for example TLS verification against a
  loopback server) must mark the specific expected warning with
  `pytest.mark.filterwarnings`, never silence warnings broadly.
- **Security analysis:** Bandit (SAST) and OSV-Scanner (SCA) run in the required
  `security.yml` job; GitHub CodeQL code scanning is enabled on the repository.

## Assertions and input checking

Production code does not use `assert` to validate input or enforce security properties,
because Python removes assertions under `python -O`. Untrusted input is checked with
explicit conditions that raise a documented exception (for example `ValueError`), and
invariants are verified by the test suite, including the seeded fuzz tests in
`tests/unit/test_fuzz_inputs.py`, which feed mutated input to the Nmap XML parser, the
options schema, the target allowlist, the dashboard's structured scan fields and its refusal
of any free-text Nmap options (every spelling of an Nmap file option and NSE option included),
the web port and generated report names, the event-stream resume point, account
validation, the login endpoints, the schedule time fields, the profiles and schedules
loaders, the stored records of a copied vulnerability database, the update checker's names and GitHub
responses, and the text a scanned
target controls (terminal sanitizing, URL redaction and body comparison), and require
that only documented errors occur.

## Tests

Major new functionality and every bug fix need automated tests; see
[CONTRIBUTING](../.github/CONTRIBUTING.md#test-policy-and-interpreting-results).
Coverage must stay at or above 80% (`--cov-fail-under=80`).

## Reviewing changes

Reviewers check these standards plus the project's secure-design rules in
[the assurance case](ASSURANCE_CASE.md): validate untrusted input against an allowlist,
keep secure defaults (verify TLS, bind to loopback, require authentication), and never log
or commit secrets.
