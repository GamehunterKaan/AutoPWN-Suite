# Build and run from source

## Requirements

- Python **3.10 or later, below 4.0**, pip, and Git. No compiler or SDK is needed
  for the Python source itself. Some platforms may need package-specific build
  tools if compatible binary wheels are unavailable.
- Nmap on `PATH` for network/port scans. Website-only dashboard scans do not
  require Nmap. Some Nmap scan techniques need administrator/root privileges.
- Poetry **2.5.1** for the locked developer environment and tests. The wheel is
  built with `poetry-core==2.5.0` (pinned in `pyproject.toml`).
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
The source is interpreted Python; no separate compilation step is required. The code
lives in the `autopwn_suite` package; `autopwn.py` and `api.py` at the repository root
are launchers for a source checkout. To install the package itself, run
`pip install .` (or `pipx install .`) in the checkout; this puts the `autopwn-suite`
command on `PATH`.

## Locked development environment and package build

```sh
pipx install poetry==2.5.1
poetry install
poetry check --lock
poetry run ruff check .
node --check autopwn_suite/web_ui_static/app.js
node --check autopwn_suite/web_ui_static/web_security.js
poetry run pytest
poetry build
```

`poetry build` writes a wheel and source distribution into `dist/`. Build outputs
are ignored by Git and must not be committed. Releases publish exactly such a
wheel and source distribution to PyPI (see [Releasing](RELEASING.md)); the release
workflow builds them with `python -m build --no-isolation` from the hash-pinned
`packaging/requirements-publish.txt`.

## Standalone binaries

Releases also attach single-file binaries built with PyInstaller. To build one for
your platform from a checkout (any Python 3.10 or newer runs the script; the interpreter
that builds the binary is downloaded):

```sh
python scripts/build_binary.py --target linux-amd64 --work-dir "$HOME/autopwn-build" \
  --source-date-epoch "$(git log -1 --format=%ct)" --repeat --output dist/autopwn-suite
python scripts/smoke_install.py "$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n 1)" dist/autopwn-suite
```

The targets are `linux-amd64`, `linux-arm64`, `windows-amd64` and `macos-arm64`, and each
must be built on that platform (PyInstaller does not cross-compile). `--repeat` builds twice from
scratch and fails unless both binaries are identical. The script:

1. downloads the CPython that `packaging/build-python.json` pins for the target (a self-contained
   python-build-standalone archive) and unpacks it only if its SHA-256 matches;
2. downloads the hash-pinned `requirements-locked.txt` and `packaging/requirements-build.txt` wheels with
   platform tags fixed per target (`PLATFORM_TAGS`, oldest-compatible build first, because pip would otherwise
   pick between several builds of one release by the glibc or macOS version of the machine) and installs them
   into a virtual environment of that interpreter;
3. runs PyInstaller with `PYTHONHASHSEED=1` and `SOURCE_DATE_EPOCH` set to the commit time.

`packaging/autopwn-suite.spec` bundles the dashboard assets, the data files, the two
sources the proof-of-concept generator reads as text, `LICENSE`, `NOTICE` and the
metadata of every bundled package, and runs the interpreter in UTF-8 mode. It leaves out what
the installer recorded about the build machine (`RECORD`, `INSTALLER`: they hold the path of the
virtual environment), the build machine's `libgcc_s` (every glibc system provides it) and the Windows Universal
C Runtime (Windows 10 provides it; PyInstaller copies it only when the Windows SDK is installed). The
`.in` files next to each requirements file are the inputs; regenerate the hash-pinned
`.txt` files with the `uv pip compile` command written at the top of each. No
compiler or linker is invoked: PyInstaller ships a prebuilt bootloader. The security
policy scans these pinned build tools for known vulnerabilities.

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
It starts `python autopwn.py --web`, which is PID 1 of the container; the launcher exits on
SIGTERM (status 143), because the kernel ignores that signal for PID 1 unless a handler exists and
`docker stop` would otherwise wait for Docker's 10-second kill timeout. Do not expose the administrative dashboard
to untrusted clients. The dashboard requires sign-in with a single administrator
account and listens on `127.0.0.1` by default (the image itself sets
`AUTOPWN_WEB_HOST=0.0.0.0` inside the container, which is why the example above
uses host networking with `AUTOPWN_WEB_HOST=127.0.0.1`: a port published with `-p`,
even as `-p 127.0.0.1:8080:8080`, reaches the dashboard from the bridge gateway,
which is not loopback, so sign-in over plain HTTP is refused; put a TLS reverse
proxy that keeps the `Host` header in front and set `AUTOPWN_WEB_SECURE_COOKIE=1`
instead); provide HTTPS for any remote access. Sign-in and the loopback default were introduced in v2.6.1.

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
| `PYTHON` | `python3` | Interpreter (Python 3.10 or newer) used to create the virtualenv. |
| `REQUIREMENTS_FILE` | `requirements.txt` | Dependency file; `requirements-locked.txt` gives hash-verified, lockfile-exact installs. |
| `SYSTEMDDIR` | `/etc/systemd/system` | Directory holding the daemon unit; `install.sh` checks it for a service that an earlier release installed, and `uninstall.sh` removes the unit from it. |

```sh
# Live install to a custom prefix (no sudo when the directories are writable)
PREFIX="$HOME/.local" bash install.sh

# Packager staging install: nothing outside "$DESTDIR" is touched
DESTDIR="$PWD/pkgroot" PREFIX=/usr bash install.sh
DESTDIR="$PWD/pkgroot" PREFIX=/usr bash uninstall.sh   # mirrors the same variables
```

Without `DESTDIR`, `install.sh` creates `$APPDIR/.venv`, installs the dependencies
and then the package from the checkout itself (`pip install --no-deps`), so no second
copy of the source tree is kept, and links `$BINDIR/autopwn-suite` to the command in
that venv. `sudo` is used only when the target is not writable by the current user (for the command
link, the directory that holds it is what counts, not the venv an existing link points to).
Run as root, the script also makes `$APPDIR` belong to root and not group- or world-writable, also when
an earlier run as a normal user created it: the daemon installer only accepts an installation that no
other user can modify. Run as a normal user, the installation belongs to that user and the script says
so: `sudo autopwn-suite` would run files that user can change, and `--daemon-install` refuses it until
`sudo bash install.sh` has been run.
Re-running it replaces the venv and leaves other files in `$APPDIR` (such as the
daemon configuration) alone. Before it changes anything it checks that `$PYTHON` is
Python 3.10 or newer and can create virtual environments with pip. It then sets the old
venv aside as `$APPDIR/.venv.old` while the new one is built and puts it back if the build
fails or the script is interrupted, so a failed upgrade (no network, no matching wheel)
leaves the working installation and its command link in place. A `.venv.old` that exists
when the script starts was left by a run that was killed: the script stops without
touching anything so that you can decide which environment to keep. A daemon installed by release 2.6 or earlier runs its own
copy of the source in `$APPDIR`, which `install.sh` does not replace, so that service keeps
running the older version. `install.sh` therefore warns when the unit still starts
`autopwn.py`; run `sudo autopwn-suite --daemon-install` once, which asks for the
configuration again and restarts the service.

With `DESTDIR` set, the script stages the source in `$APPDIR/src` and writes the
command link only: no `sudo`, no ownership changes, no systemd calls, and no
virtualenv (a venv embeds absolute paths and cannot be relocated, and creating it
needs network access that packaging build roots often lack). The link refers to the
final path (for example `/usr/lib/autopwn-suite/.venv/bin/autopwn-suite`), never the
`DESTDIR` path. The script prints the three commands to run on the target system
(typically from a package post-install step) to create `$APPDIR/.venv`, install the
dependencies and install the staged source. A `DESTDIR` inside the checkout (the
`$PWD/pkgroot` example above, or `debian/tmp`) is left out of the staged copy of the source.
`uninstall.sh` must be given the same `PREFIX`/`BINDIR`/`APPDIR` (and optional
`SYSTEMDDIR`, default `/etc/systemd/system`) that were used to install. A failing
`systemctl daemon-reload` (no running systemd, as in a container) only prints a warning, so the
application directory and the command are still removed.

## Repeatable builds

The goal is that building the same source revision twice produces the same
artifact. What is controlled, and what is not:

| Artifact | Status |
| --- | --- |
| Python source (`autopwn_suite/`) | Interpreted source; there is no build output to differ. Release source archives are produced by `scripts/release_assets.py` from the reviewed commit. |
| PyPI wheel and sdist | Inputs are pinned (`poetry-core==2.5.0`, hash-pinned `build` and its dependencies, `SOURCE_DATE_EPOCH` from the commit time). Building the same commit repeatedly produced identical bytes for both files with `pip wheel` and `python -m build`, and `publish-pypi.yml` builds twice and refuses to publish if the files differ. |
| Standalone binaries | Repeatable, and reproducible from the pinned toolchain described in [Rebuilding a standalone binary](#rebuilding-a-standalone-binary). `build-binary.yml` builds every binary twice on its runner and the job fails unless both builds are identical; pull requests and releases both run it. Each binary is smoke-tested and has an SBOM. |
| Container image content (all layer files, modes, owners) | Pinned inputs, see below. |
| Container layer timestamps and image `created` time | Deterministic only when built with `SOURCE_DATE_EPOCH` and the BuildKit `rewrite-timestamp=true` exporter option, as `publish-docker.yml` does. |
| `poetry build` with another backend version | Not verified; the pinned backend version is part of the input. |
| Standalone binary built with another interpreter or other tool versions | Different bytes by design: the interpreter and every tool version is an input, pinned in `packaging/build-python.json` and the hash-pinned requirements. |

### Rebuilding a standalone binary

The inputs of a binary are the source archive, `SOURCE_DATE_EPOCH` (the commit time of the release
commit), the interpreter archive pinned by SHA-256 in `packaging/build-python.json`, the hash-pinned
Python requirements and PyInstaller with its prebuilt bootloader (inside the hash-pinned wheel),
`PYTHONHASHSEED=1`, the fixed wheel platform tags in `scripts/build_binary.py`, and the platform it is built on. The interpreter is a self-contained
python-build-standalone distribution, so no Python or shared library of the build machine is copied
into the binary: the GitHub runner image does not influence the result, and a binary built in a
different directory, virtual environment or interpreter location is identical. Build from a checkout
without line-ending conversion (`core.autocrlf=false`; the release archive has LF endings) or from the release's
source archive unpacked with `tar`: PyInstaller records an executable data file differently, so copying the
files from a file system that marks everything executable (for example a Windows drive seen from WSL) changes
the bytes. To check a release:

```sh
git -c core.autocrlf=false clone --branch vVERSION https://github.com/GamehunterKaan/AutoPWN-Suite && cd AutoPWN-Suite
python scripts/build_binary.py --target linux-amd64 --work-dir "$HOME/autopwn-build" \
  --source-date-epoch "$(git log -1 --format=%ct)" --output autopwn-suite
sha256sum autopwn-suite    # compare with the autopwn-suite-vVERSION-linux-amd64 line of the signed SHA256SUMS
```

Limits: the build must run on the target platform (Windows binaries on Windows, macOS binaries on
macOS, and so on); the Linux binaries link the C library and zlib of the machine that runs them,
which is not an input of the build; a changed interpreter archive, requirement or PyInstaller
version gives different bytes on purpose; and the identical-bytes claim covers the build, not the
runtime behavior of the dependencies.

Checked on the v2.7.0 pull request builds: the Linux x86-64 binary rebuilt on Ubuntu 24.04 and the Windows
binary rebuilt on Windows 11 were byte-identical to the files the GitHub-hosted runners built from the same
source archive. The Linux arm64 and macOS binaries are verified by the build-twice check on their runners.

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

- The local verification of this setup built each of linux/amd64 and
  linux/arm64 (the latter under QEMU user-mode emulation) twice on one machine,
  from two clean checkouts with different file modification times, and got
  byte-identical image archives for each platform (the two platforms naturally
  differ from each other). Builds on other hosts and builds on different days
  against the snapshot service have not been verified to be identical; they
  should be, because the inputs are pinned, but check with the procedure above
  before relying on it.
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
