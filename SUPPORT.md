# Release support lifecycle

AutoPWN Suite supports **the latest stable release only**. Support begins when
that release is published and ends when the next stable release is published.
There is no fixed calendar term or long-term-support branch. Prereleases are for
evaluation and receive no promised security maintenance; upgrade to the stable
release. The same policy applies to source archives, Docker images, the PyPI
package and the standalone binaries: a fix for any of them is a new stable release,
never a replaced file.

As of 2026-10-18, **v2.7.0** is the supported stable release. **All versions below
2.7.0 are end of life** and no longer receive security updates. The maintainer
updates this statement with every stable release and identifies superseded
versions in its release notes. A mutable Docker `latest` alias is not a version:
record the release version and digest before reporting a problem.

Support includes triage of reproducible bugs, security reports and dependency
updates, and fixes in a subsequent stable release when available. This volunteer
project provides no guaranteed fix date, operational support or service uptime.
Older versions receive no backports unless a specific advisory explicitly names
an exception and its end date. Upgrade to the latest stable version for fixes.

Use [GitHub issues](https://github.com/GamehunterKaan/AutoPWN-Suite/issues) for
ordinary bugs and questions. Report vulnerabilities privately using
[SECURITY.md](SECURITY.md); its acknowledgement and coordination timeframes apply
throughout triage, including reports about unsupported versions. Known unresolved
issues and mitigations are in the [advisory index](docs/SECURITY_ADVISORIES.md).

Support depends on one volunteer maintainer. The
[continuity plan](docs/CONTINUITY.md) explains how issue handling and releases are
meant to continue if the maintainer is unavailable, and the
[roadmap](docs/ROADMAP.md) lists planned work and non-goals. Accessibility barriers
in the dashboard and internationalization problems are treated as ordinary bugs; see
[accessibility](docs/ACCESSIBILITY.md) and
[internationalization](docs/INTERNATIONALIZATION.md).
