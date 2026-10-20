# Dependency management

## Selection

The maintainer selects dependencies needed for an implemented feature, preferring
maintained packages with an established upstream, compatible Python support,
licenses compatible with distribution under Apache-2.0, and no unresolved known
vulnerability affecting the proposed use. Review a package's origin, maintenance,
transitive dependencies, release history, and security advisories before adding
or replacing it. Avoid similarly named substitute packages and unnecessary
dependencies. A proposed addition must explain its purpose in its pull request.

## Sources and installation

Python packages come from PyPI through pip or Poetry. Runtime requirements are
declared in `requirements.txt` and `[tool.poetry.dependencies]` in
`pyproject.toml`; developer/test requirements are in the Poetry dev group.
`poetry.lock` records resolved direct and transitive versions and package hashes.
Use Poetry **2.5.1**, the version declared in the manifest and CI, for lock updates.
Poetry installs locked versions; pip's requirements installation resolves versions
within declared constraints and is not an identical locked environment.

Nmap is a separately installed executable. Obtain it from the OS package manager
or [Nmap's official distribution](https://nmap.org/download.html) and put it on
`PATH`. CI uses APT or Homebrew. The container uses the official Python slim image
and APT for Nmap. Python's standard library handles Nmap XML and process control;
there is no Python Nmap wrapper dependency. GitHub Actions dependencies are
declared in workflow `uses:` entries; review upstream action changes before
updating them. Release actions are pinned to commit SHAs.

NVD CVE feeds are application data, not executable dependencies. Explicit database
updates fetch official HTTPS feeds, check the advertised decompressed SHA-256 and
size, validate their records, and atomically replace the local SQLite mirror.
Downloaded exploit files are untrusted reference material and are not executed
by AutoPWN. They must not be treated as package dependencies or checked into Git.

## Scope of dependency monitoring

The project's dependencies are its **Python requirements** (`pyproject.toml`, `poetry.lock`). Those are what
OSV-Scanner checks on every change, what Dependabot alerts cover, and what must be fixed or documented before
a release. Operating-system packages inside the container image are inherited from the Debian base image and
updated by rebuilding on a newer pinned base; they are listed in the signed image SBOM and scan reports but are
not managed as project dependencies.

The tools that build the release artifacts are pinned separately and are not shipped: PyInstaller and its helpers
(`packaging/requirements-build.in` and the hash-pinned `.txt` generated from it), the CPython interpreter that builds
the standalone binaries (`packaging/build-python.json`: a python-build-standalone release with the SHA-256 of the
archive for each platform; its OpenSSL, zlib and the other C libraries inside it are frozen into the binaries, so
the release is tracked like any dependency) and `build` with `poetry-core`
(`packaging/requirements-publish.in`/`.txt`, the same `poetry-core` version as `[build-system]` in
`pyproject.toml`). `.security/requirements-bandit.txt` pins the static-analysis tool the same way. The security policy
scans all three files with OSV-Scanner on every change and release and blocks on
known vulnerabilities; their licenses are not gated because nothing from them is distributed (PyInstaller is
GPL-2.0-or-later with an exception that allows distributing the frozen program under the project's own license).
Tests check that each `.txt` is hash-pinned and agrees with its `.in`. The packages frozen into each standalone binary
are the runtime requirements for its platform, so they are covered by the same lockfile checks as the container.

## Tracking and updates

1. Update both runtime dependency declarations when adding/removing a package.
   Keep their names and compatible version constraints aligned.
2. Run `poetry lock` with Poetry 2.5.1 and commit `pyproject.toml` and
   `poetry.lock` together. Use `poetry update PACKAGE` for an intentional package
   update; review the resulting transitive changes.
3. Run `poetry check --lock` and `poetry run pytest`. CI includes tests checking
   manifest agreement and undeclared runtime imports. To change a build tool, edit the
   `.in` file in `packaging/`, regenerate its `.txt` with the `uv pip compile` command
   in that file's header and keep the `poetry-core` pin in `pyproject.toml` equal to
   the one in `packaging/requirements-publish.txt`.
4. Review GitHub dependency alerts and Dependabot security-update pull requests.
   Check whether an advisory affects our reachable use and prioritize exploitable
   issues. Test upgrades and explain security-relevant changes in the changelog.
5. Before release, review unresolved dependency alerts, applicable mitigations,
   and the exact changes in the lockfile and container dependencies. Track
   remaining work in an issue without publishing undisclosed exploit details.

The [security testing policy](SECURITY_TESTING.md) defines mandatory OSV
vulnerability/malicious-package checks, license thresholds, VEX exceptions and
pre-release image checks. Every compiled image architecture receives a CycloneDX
SBOM generated from its actual image archive, covered by the signed release
manifest. Do not infer installed image contents from the Poetry lockfile alone.
Each standalone binary receives its own CycloneDX SBOM, generated by
`scripts/binary_sbom.py` from the build environment of that platform (installed
runtime packages, PyInstaller, CPython and the python-build-standalone release). It is not a scan of the
executable and does not list the native libraries inside the interpreter distribution or the wheels.

The maintainer owns this process. A lockfile or passing CI alone is not proof
that dependencies are safe; document assessment and mitigation decisions.
