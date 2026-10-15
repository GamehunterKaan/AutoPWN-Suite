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

## Tracking and updates

1. Update both runtime dependency declarations when adding/removing a package.
   Keep their names and compatible version constraints aligned.
2. Run `poetry lock` with Poetry 2.5.1 and commit `pyproject.toml` and
   `poetry.lock` together. Use `poetry update PACKAGE` for an intentional package
   update; review the resulting transitive changes.
3. Run `poetry check --lock` and `poetry run test`. CI includes tests checking
   manifest agreement and undeclared runtime imports.
4. Review GitHub dependency alerts and Dependabot security-update pull requests.
   Check whether an advisory affects our reachable use and prioritize exploitable
   issues. Test upgrades and explain security-relevant changes in the changelog.
5. Before release, review unresolved dependency alerts, applicable mitigations,
   and the exact changes in the lockfile and container dependencies. Track
   remaining work in an issue without publishing undisclosed exploit details.

The maintainer owns this process. A lockfile or passing CI alone is not proof
that dependencies are safe; document assessment and mitigation decisions.
