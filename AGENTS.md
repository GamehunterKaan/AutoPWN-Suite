# Agent guide

AutoPWN Suite is an operator-run vulnerability scanner (CLI, Python library, Flask dashboard) that drives Nmap and bounded web probes. The repository holds **OpenSSF Baseline levels 1-3 and the Best Practices Passing, Silver and Gold badges**. The root policy files, `.github/CONTRIBUTING.md` and `docs/` are the *evidence* for those criteria, so a statement in them that stops being true is a defect. This page is the short version; the linked documents are authoritative.

## Orientation

- The code is the `autopwn_suite/` package. At the root, `autopwn.py` (CLI launcher and Docker entrypoint) and `api.py` (compatibility re-export) serve source checkouts.
- `scripts/` is release, policy and build tooling; `.security/` the policy data (VEX, license overrides, SAST exceptions, bandit requirements); `packaging/` the PyInstaller spec and pinned build tools; `fuzz/` and `.clusterfuzzlite/` the fuzz harnesses and their build.
- Scan only targets you are authorized to test. Tests mock Nmap and HTTP, serve from `127.0.0.1` and use sample targets (`192.0.2.0/24`, `.test` and `.invalid` names); nothing blocks real traffic, so keep new tests off the network.

## Done means

- The steps of the required `test` job (`.github/workflows/poetry-tests.yml`) pass locally: lockfile check, `ruff`, the dashboard `node --check` and ESLint steps (Node 20+), `export_locked_requirements.py --check`, then `poetry run pytest` with branch coverage at least 80%. Use Poetry 2.5.1 exactly (`pipx install poetry==2.5.1`, then `poetry install`); other versions refuse to run.
- Package code stays Python 3.10-compatible: the `Tests (...)` jobs run on 3.10 with `pip install -r requirements.txt`. Run pytest itself on 3.11+ (`scripts/` use `tomllib`).
- Behavior changes carry tests and bug fixes a regression test; the evidence docs below describe the new behavior.
- `CHANGELOG.md` `## [Unreleased]` (or the newest section while its version is unreleased) has Functional and Security notes for anything user-visible, security-relevant, or a dependency or CI change; write "no security impact" when true.

## Keep the evidence true

Update these in the same change:

| You change | Update |
| --- | --- |
| CLI flag, environment variable, config key, HTTP route, file location, port | `README.md`, `docs/INTERFACES.md`, and the matching rows of `docs/THREAT_MODEL.md` and `docs/ARCHITECTURE.md` |
| Trust boundary, untrusted input, auth, crypto, stored data | `docs/THREAT_MODEL.md`, and `docs/ASSURANCE_CASE.md` when a design claim moves |
| Security fix | `docs/SECURITY_ADVISORIES.md`, `SECURITY.md` (never call an unresolved issue fixed, never invent a CVE ID) |
| Dependency or build tool | `docs/DEPENDENCIES.md`; grep `docs/` and `README.md` for the old version or locked-package count |
| Install, build, packaging | `docs/BUILDING.md` and the `README.md` Installation section |
| Release, signing, publishing | `docs/RELEASING.md`, `docs/CONTINUITY.md` |
| New or changed workflow | `docs/SECURITY_TESTING.md`; also `GOVERNANCE.md` (Automation identities) and `docs/SECRETS.md` when it gains a write permission, secret or OIDC identity |
| Dashboard UI or user-facing text | the accessibility and internationalization rules in `.github/CONTRIBUTING.md`, `docs/ACCESSIBILITY.md`, `docs/INTERNATIONALIZATION.md` |

## Requirements

**Dependencies**
- Declare every runtime dependency in both `pyproject.toml` and `requirements.txt` with matching version constraints (the test compares names only), then `poetry lock` (Poetry 2.5.1; `poetry update PACKAGE` to bump one) and `poetry run python scripts/export_locked_requirements.py`. Any edit to a `pyproject.toml` dependency table, the dev group included, changes the lock hash, and only CI's `poetry check --lock` catches a stale lock.
- A new runtime dependency passes the Security policy check (no OSV findings, approved license) and ships prebuilt wheels (the container and binary builds use `--only-binary=:all:`).
- Regenerate `poetry.lock`, `requirements-locked.txt`, `packaging/requirements-*.txt` and `.security/requirements-bandit.txt`; hand edits are overwritten. For the last two groups edit the `.in` file and run the `uv pip compile` command in the `.txt` header. Keep the `poetry-core` pin in `pyproject.toml` equal to the one in `packaging/requirements-publish.txt`.
- New third-party installs in release, container, security and fuzz steps come from hash-pinned files (`--require-hashes`); `.github/workflows/tests.yml`, `install.sh`, the wheel smoke installs and Poetry's own installation are the existing exceptions.

**Workflows**
- Model new workflows on `.github/workflows/poetry-tests.yml` and `.github/workflows/security.yml`. Pin every external `uses:` to a full 40-character commit SHA with a `# v4`-style tag comment and container images to a digest; set `persist-credentials: false` on every `actions/checkout`; declare `permissions` at workflow and job level, read-only unless a job must write; trigger on `pull_request`, not `pull_request_target`; pass inputs, refs and tags to scripts through `env:` (validate refs against `^[0-9a-f]{40}$`), never `${{ }}` inside `run:`.
- Build release artifacts from the validated release source archive passed between jobs, not from a ref taken from an input (CodeQL flags that), and run no PR code in `workflow_run` or write-token jobs.
- PyPI publishes through trusted publishing (`.github/workflows/publish-pypi.yml`, environment `pypi`; never add a PyPI token) and signing uses keyless OIDC. The only stored secrets are `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, referenced only by the push and sign jobs. Keep signing in the `sign` job of `.github/workflows/publish-docker.yml`: that workflow's path is the signer identity consumers verify.
- Keep the required check names stable (`test`, `Tests (ubuntu-latest)`, `Tests (macos-latest)`, `Security policy`, `Independent human approval`, plus `Analyze (...)` and `CodeQL` from CodeQL default setup) and give the workflows behind them no `paths:` filter: a renamed or skipped required check blocks merging.

**Versions and releases**
- The maintainer versions and releases (`docs/RELEASING.md`); leave `version` alone. `pyproject.toml` `version`, `autopwn_suite/__init__.py` `__version__` and a `## [X.Y.Z]` changelog section with non-empty `### Functional changes` and `### Security changes` must agree; a test checks.

**Security invariants**
- Bind to loopback by default (the Docker image deliberately binds `0.0.0.0` inside the container; publish its port to loopback). Require sign-in on every dashboard route and the CSRF token on non-GET routes (tests iterate all routes); never extend the public list in `install_auth`.
- Verify target TLS certificates by default (`--insecure-tls` opts out; the diagnostics in `autopwn_suite/web/tls.py` deliberately inspect untrusted certificates).
- Validate untrusted input with explicit allowlist checks that reject through the documented error (`ValueError`-style, or the dashboard's HTTP 400), never `assert`; give each new parser or validator seeded fuzz coverage (`tests/unit/test_fuzz_inputs.py`, `fuzz/`).
- Send target HTTP only through the helpers in `autopwn_suite/web/http.py` (read-only methods, same origin, bounded); run Nmap from an argv list with `shell=False`; escape untrusted text before it reaches HTML.
- Offline mode makes no calls to online services (Nmap still scans the chosen targets): gate every new outbound call behind it and extend `tests/unit/test_offline_scans.py`.
- Keep secrets out of logs, reports, responses and commits: responses and logs carry fixed text, not exception text, and secret-bearing inputs use `*_FILE` credential files (`autopwn_suite/credential_files.py`) and stay out of settings JSON and job output.
- Fix a failing security gate (OSV, bandit, CodeQL), or waive it only through a reviewed OpenVEX statement or `.security/sast-exceptions.json` (evidence, 90 days at most); `# nosec` is ignored and malicious-package findings cannot be waived. Dashboard header or CSP changes keep the OWASP ZAP baseline (`.github/zap/rules.tsv`) passing.
- Report vulnerabilities privately (`SECURITY.md`), never in public issues or PRs.

**Git and review**
- Work on a branch and open a pull request to `main` directly: a suggested change or fix needs no issue and no prior approval from the maintainer. It needs the required checks, an up-to-date branch and one approval from a human who is neither the author nor the last pusher, so agents cannot approve or merge; any push dismisses earlier approvals, so batch pushes.
- Sign off every commit (`git commit -s`; the DCO in `.github/CONTRIBUTING.md`, which the maintainer checks and CI does not) and, as `main` does, add a `Co-Authored-By` trailer for AI assistance.
- The PR description says why a new dependency is needed and explains any new lint exception or skipped test; dashboard changes include the accessibility checklist.
- Ask first before force-pushing, tagging, releasing, or changing repository, PyPI or Docker Hub settings or code-scanning alerts.

## Gotchas

- Partial test runs fail the coverage gate: add `--no-cov`. The full suite takes about three minutes.
- `tests/conftest.py` points `AUTOPWN_DATA_DIR` (dashboard account, settings, CVE database) at a temporary directory; otherwise it is a per-user directory. Outputs, exploits and `api.txt` use the working directory.
- `SyntaxWarning` anywhere and `DeprecationWarning` or `FutureWarning` from `autopwn_suite` fail pytest.
- Python, JavaScript, shell, Dockerfile and `.spec` files start with the SPDX and copyright header (copy a neighbour's, after any shebang); nothing enforces it.
- `README.md` is the PyPI project description, and a published description cannot be edited: link documents and images with absolute URLs (`https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/...`, images from `raw.githubusercontent.com`); `tests/unit/test_readme_links.py` fails on a relative target.
- A Windows working tree can hold CRLF files while the index is LF; keep each file's line endings when editing.
- `tests/unit/test_install_scripts.py` runs its install-script cases only with bash and tar (9 of 13 skip on Windows); `tests/integration/test_nmap_live.py` needs Nmap; four test modules skip without Node.

## How to work

Every agent or session that changes this repository works this way:

- State assumptions and ask when a requirement is ambiguous.
- Make surgical changes: every changed line traces to the request, and unrelated dead code is mentioned, not deleted.
- Turn the task into a checkable goal and loop until it passes.

## Where to read next

- Layout and data flow: `docs/ARCHITECTURE.md`
- Style, lint and test rules: `docs/CODING_STANDARDS.md`, `.github/CONTRIBUTING.md`
- Secure-design rules and trust boundaries: `docs/ASSURANCE_CASE.md`, `docs/THREAT_MODEL.md`
- Security policy (SCA, SAST, VEX, fuzzing): `docs/SECURITY_TESTING.md`
- Dependencies, builds, releases: `docs/DEPENDENCIES.md`, `docs/BUILDING.md`, `docs/RELEASING.md`
- CLI, environment and library surface: `docs/INTERFACES.md`
- Secrets: `docs/SECRETS.md`; vulnerability reports: `SECURITY.md`
- New or large features: check the non-goals in `docs/ROADMAP.md` first; governance: `GOVERNANCE.md`
