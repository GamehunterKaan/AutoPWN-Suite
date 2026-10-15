# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change. 

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Add or update tests for behavior changes and document functional and security
   modifications under `Unreleased` in [CHANGELOG.md](../CHANGELOG.md). The
   maintainer assigns the release version using [SemVer](https://semver.org/).
4. Run `poetry check --lock` and `poetry run test` using Poetry 2.5.1. All required
   CI checks must pass before merging. The maintainer reviews and merges accepted
   changes after a non-author human approves them. Bot/AI review cannot replace
   that approval; administrators must follow the same rule.
5. Use [Build instructions](../docs/BUILDING.md) and
   [Dependency management](../docs/DEPENDENCIES.md). Dependency changes must
   update both runtime manifests and the lockfile as applicable. Do not commit
   credentials, generated executables or unreviewable application binaries.

The project roles and access inventory are in [GOVERNANCE.md](../GOVERNANCE.md).
Contributors must have the legal right to submit each contribution under the
repository's Apache-2.0 license, as required by GitHub's contribution terms.
Report security issues privately using [SECURITY.md](../SECURITY.md).

## Test policy and interpreting results

Run `poetry run test` locally with Python 3.10+ after installing the dependencies
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
