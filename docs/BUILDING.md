# Build and run from source

## Requirements

- Python **3.10 or later, below 4.0**, pip, and Git. No compiler or SDK is needed
  for the Python source itself. Some platforms may need package-specific build
  tools if compatible binary wheels are unavailable.
- Nmap on `PATH` for network/port scans. Website-only dashboard scans do not
  require Nmap. Some Nmap scan techniques need administrator/root privileges.
- Poetry **2.5.1** for the locked developer environment, tests, or a Python wheel.
- Node.js for developer JavaScript syntax checks and workflow-script tests;
  the running Python application does not require Node.
- Docker Engine with Buildx for container builds; Linux host networking is used
  for local network discovery. The Python source can also run on Windows/macOS.

Direct Python libraries and development tools are enumerated in
`pyproject.toml` and `requirements.txt`; the lockfile includes transitive versions.
See [Dependency management](DEPENDENCIES.md) for selection, sources, and updates.

## Python source installation

```sh
git clone https://github.com/GamehunterKaan/AutoPWN-Suite.git
cd AutoPWN-Suite
python -m venv .venv
```

Activate the environment with `. .venv/bin/activate` on Linux/macOS or
`.\.venv\Scripts\Activate.ps1` in PowerShell. Then:

```sh
python -m pip install -r requirements.txt
python autopwn.py --help
python autopwn.py --web --web-host 127.0.0.1
```

For network scanning, install Nmap (for example, `sudo apt-get install nmap` on
Debian/Ubuntu or `brew install nmap` on macOS). Windows users can use the official
Nmap installer. Scan only systems for which you have authorization.
The source is interpreted Python; no separate compilation step is required.

## Locked development environment and package build

```sh
pipx install poetry==2.5.1
poetry install
poetry check --lock
poetry run ruff check .
node --check modules/web_ui_static/app.js
node --check modules/web_ui_static/web_security.js
poetry run test
poetry build
```

`poetry build` writes a wheel and source distribution into `dist/`. Build outputs
are ignored by Git and must not be committed. The repository currently
distributes source archives and a container; local package builds are another
way to inspect/package the source, not a claim of a PyPI publication.

## Container build

From the repository root, build the local Dockerfile explicitly:

```sh
docker build --tag autopwn-suite:local .
docker run --rm --network host -e AUTOPWN_WEB_HOST=127.0.0.1 \
  -v autopwn-data:/data -e AUTOPWN_DATA_DIR=/data autopwn-suite:local
```

Open `http://127.0.0.1:8080` on the Docker host. This example is for Linux host
networking; Docker Desktop networking and raw-packet capabilities depend on the
host's configuration. The image installs runtime Python dependencies and Nmap.
It starts `python autopwn.py --web`. Do not expose the administrative dashboard
to untrusted clients. The dashboard requires sign-in with a single administrator
account and listens on `127.0.0.1` by default (the image itself sets
`AUTOPWN_WEB_HOST=0.0.0.0` inside the container, so publish its port to loopback
only); provide HTTPS for any remote access. These are unreleased changes.

For a multi-platform image with a configured Buildx builder:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --tag YOUR_REGISTRY/autopwn-suite:local --push .
```

The checked-in `docker-compose.yml` runs a published image. It has no `build:`
entry, so `docker compose up --build` does not build this repository's source.
Use `docker compose up -d` for that published-image deployment.

## Installing to a staging directory (DESTDIR/PREFIX)

`install.sh` and `uninstall.sh` follow the usual packaging conventions. Defaults
are unchanged: the application goes to `/opt/autopwn-suite` and the command to
`/usr/local/bin/autopwn-suite`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PREFIX` | `/usr/local` | Installation prefix. If set explicitly, `APPDIR` defaults to `$PREFIX/lib/autopwn-suite`. |
| `BINDIR` | `$PREFIX/bin` | Directory for the `autopwn-suite` command. |
| `APPDIR` | `/opt/autopwn-suite` (or `$PREFIX/lib/autopwn-suite` when `PREFIX` is set) | Application directory, including its `.venv`. |
| `DESTDIR` | empty | Staging root; every file written goes under it. |
| `PYTHON` | `python3` | Interpreter used to create the virtualenv. |
| `REQUIREMENTS_FILE` | `requirements.txt` | Dependency file; `requirements-locked.txt` gives hash-verified, lockfile-exact installs. |

```sh
# Live install to a custom prefix (no sudo when the directories are writable)
PREFIX="$HOME/.local" bash install.sh

# Packager staging install: nothing outside "$DESTDIR" is touched
DESTDIR="$PWD/pkgroot" PREFIX=/usr bash install.sh
DESTDIR="$PWD/pkgroot" PREFIX=/usr bash uninstall.sh   # mirrors the same variables
```

With `DESTDIR` set, the scripts copy the source and write the wrapper only: no
`sudo`, no ownership changes, no systemd calls, and no virtualenv (a venv embeds
absolute paths and cannot be relocated, and creating it needs network access
that packaging build roots often lack). The generated wrapper refers to the
final path (for example `/usr/lib/autopwn-suite`), never the `DESTDIR` path. The
script prints the two commands to run on the target system (typically from a
package post-install step) to create `$APPDIR/.venv` and install the
dependencies. Without `DESTDIR`, the venv is created in place as before, and
`sudo` is used only when the target is not writable by the current user.
`uninstall.sh` must be given the same `PREFIX`/`BINDIR`/`APPDIR` (and optional
`SYSTEMDDIR`, default `/etc/systemd/system`) that were used to install.

## Repeatable builds

The goal is that building the same source revision twice produces the same
artifact. What is controlled, and what is not:

| Artifact | Status |
| --- | --- |
| Python source / `autopwn.py` | Interpreted source; there is no build output to differ. Release source archives are produced by `scripts/release_assets.py` from the reviewed commit. |
| Container image content (all layer files, modes, owners) | Pinned inputs, see below. |
| Container layer timestamps and image `created` time | Deterministic only when built with `SOURCE_DATE_EPOCH` and the BuildKit `rewrite-timestamp=true` exporter option, as `publish-docker.yml` does. |
| `poetry build` wheel/sdist | Not verified; do not rely on it being bit-for-bit reproducible. |

Container inputs that are pinned:

- **Base image**: `ARG BASE_IMAGE` in the `Dockerfile` is `tag@sha256:<index digest>`.
  The digest is the multi-architecture index, so amd64 and arm64 are both fixed.
- **Debian packages (nmap and its dependencies)**: apt is pointed at a dated
  `snapshot.debian.org` archive (`ARG DEBIAN_SNAPSHOT`, must be on or after the
  base image's creation date). Package versions therefore depend on that date,
  not on when you build.
- **Python dependencies**: installed from `requirements-locked.txt` with
  `pip install --no-compile --require-hashes --only-binary=:all:`. That file is
  generated from `poetry.lock` (runtime group only, every artifact hash, no
  timestamps) by `python scripts/export_locked_requirements.py`; the unit test
  suite fails if it is stale. `--no-compile` avoids `.pyc` files, which embed
  install-time metadata. `PYTHONDONTWRITEBYTECODE=1` is set in the image.
- **Nondeterministic leftovers** (apt/dpkg logs, ldconfig cache, apt lists) are
  deleted in the same layer.

To update the pins deliberately (this is the only way they change):

```sh
python scripts/update_base_image.py              # same tag, new digest, today's snapshot
python scripts/export_locked_requirements.py     # after any poetry.lock change
```

Review and commit the resulting diff. `update_base_image.py` refuses a digest
whose index lacks linux/amd64 or linux/arm64.

### Verifying a build yourself

Use a BuildKit builder with the `docker-container` driver (the default `docker`
driver cannot use `rewrite-timestamp`). Build twice from clean checkouts, with
the same epoch, and compare:

```sh
epoch="$(git log -1 --format=%ct)"
for n in 1 2; do
  docker buildx build --no-cache --platform linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH="$epoch" \
    --output "type=docker,dest=image-$n.tar,rewrite-timestamp=true" .
done
sha256sum image-1.tar image-2.tar   # should be identical
```

Without `rewrite-timestamp`, expect differing layer digests even though file
contents are identical (only modification times differ). To confirm that, list
both `docker save` archives' layer tarballs and compare entries ignoring mtime.

### Honest limits

- The local verification of this setup built one platform (linux/amd64) twice
  on one machine with different source mtimes and got byte-identical image
  archives. arm64 (built under QEMU in CI), builds on other hosts, and builds
  on different days against the snapshot service have not been verified to be
  identical; they should be, because the inputs are pinned, but check with the
  procedure above before relying on it.
- The reproducibility depends on third-party availability: Docker Hub (digest),
  `snapshot.debian.org`, and PyPI file hosting must still serve the pinned
  content. A removed PyPI file or an unreachable snapshot fails the build
  rather than changing it silently.
- Apt trusts Debian archive signatures; the snapshot `Release` files are
  accepted past their `Valid-Until` date (`Acquire::Check-Valid-Until=false`) as
  is required for any historic snapshot.
- The final image still contains the base image's own layers; their internal
  timestamps are those of the pinned upstream image.
- Registry push metadata and attestations (provenance, signatures) contain
  timestamps and are not part of the reproducible image content. The workflow
  loads the image locally (`type=docker`), signs the pushed manifest digest with
  cosign, and does not claim that two registry pushes have the same manifest.
