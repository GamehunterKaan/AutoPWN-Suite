# Build and run from source

## Requirements

- Python **3.10 or later, below 4.0**, pip, and Git. No compiler or SDK is needed
  for the Python source itself. Some platforms may need package-specific build
  tools if compatible binary wheels are unavailable.
- Nmap on `PATH` for network/port scans. Website-only dashboard scans do not
  require Nmap. Some Nmap scan techniques need administrator/root privileges.
- Poetry **2.5.1** for the locked developer environment, tests, or a Python wheel.
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
to untrusted clients: the application currently has no built-in login.

For a multi-platform image with a configured Buildx builder:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --tag YOUR_REGISTRY/autopwn-suite:local --push .
```

The checked-in `docker-compose.yml` runs a published image. It has no `build:`
entry, so `docker compose up --build` does not build this repository's source.
Use `docker compose up -d` for that published-image deployment.
