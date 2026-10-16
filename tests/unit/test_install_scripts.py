# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""install.sh / uninstall.sh path variables and repeatable-build policy checks."""

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
posix_only = pytest.mark.skipif(
    sys.platform == "win32" or BASH is None or shutil.which("tar") is None,
    reason="install scripts need a POSIX bash and tar",
)

# A stand-in interpreter: `python -m venv DIR` creates a fake virtualenv whose
# activate script defines deactivate() and whose pip only records its arguments,
# so the test never touches the network or the real system.
FAKE_PYTHON = """#!/usr/bin/env bash
set -e
[ "$1" = "-m" ] && [ "$2" = "venv" ] || { echo "unexpected: $*" >&2; exit 1; }
venv="$3"
mkdir -p "$venv/bin"
printf '%s\\n' 'export PATH="'"$venv"'/bin:$PATH"' 'deactivate() { :; }' > "$venv/bin/activate"
printf '%s\\n' '#!/usr/bin/env bash' 'echo "$*" >> "$PIP_LOG"' > "$venv/bin/pip"
printf '%s\\n' '#!/usr/bin/env bash' 'exit 0' > "$venv/bin/python"
chmod +x "$venv/bin/pip" "$venv/bin/python"
"""


@pytest.fixture
def source_tree(tmp_path):
    repo = tmp_path / "repo"
    (repo / "modules").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".venv").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".venv" / "marker").write_text("do not copy\n")
    (repo / "modules" / "tool.py").write_text("print('tool')\n")
    (repo / "autopwn.py").write_text("print('autopwn')\n")
    (repo / "requirements.txt").write_text("requests\n")
    (repo / "requirements-locked.txt").write_text("requests==1.0 --hash=sha256:00\n")
    for script in ("install.sh", "uninstall.sh"):
        # Normalize line endings: Windows checkouts may use CRLF.
        text = (ROOT / script).read_bytes().replace(b"\r\n", b"\n")
        (repo / script).write_bytes(text)
    fake = tmp_path / "fake-python"
    fake.write_text(FAKE_PYTHON)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return repo


def run_script(repo, script, env_overrides, expect=0, cwd=None):
    env = {k: v for k, v in os.environ.items() if k not in {"PREFIX", "BINDIR", "APPDIR", "DESTDIR", "PYTHON"}}
    env.update(env_overrides)
    result = subprocess.run(
        [BASH, str(repo / script)], env=env, capture_output=True, text=True, timeout=120, cwd=cwd)
    assert result.returncode == expect, result.stdout + result.stderr
    return result


@posix_only
def test_scripts_are_valid_bash():
    for script in ("install.sh", "uninstall.sh"):
        text = (ROOT / script).read_bytes().replace(b"\r\n", b"\n")
        result = subprocess.run([BASH, "-n"], input=text, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode()


@posix_only
def test_destdir_stages_every_file_and_wrapper_uses_final_path(source_tree, tmp_path):
    stage = tmp_path / "stage"
    result = run_script(source_tree, "install.sh", {"DESTDIR": str(stage), "PREFIX": "/usr"})

    app = stage / "usr/lib/autopwn-suite"
    wrapper = stage / "usr/bin/autopwn-suite"
    assert (app / "autopwn.py").is_file()
    assert (app / "modules/tool.py").is_file()
    assert not (app / ".git").exists() and not (app / ".venv").exists()
    assert wrapper.stat().st_mode & 0o755 == 0o755

    text = wrapper.read_text()
    assert 'REPO_DIR="/usr/lib/autopwn-suite"' in text
    assert str(stage) not in text
    # No venv is created inside DESTDIR; the operator is told how to make it.
    assert "python3 -m venv /usr/lib/autopwn-suite/.venv" in result.stdout
    # Nothing escaped the staging directory.
    written = {p.relative_to(stage).parts[0] for p in stage.iterdir()}
    assert written == {"usr"}


@posix_only
def test_default_layout_is_unchanged_under_destdir(source_tree, tmp_path):
    stage = tmp_path / "stage"
    run_script(source_tree, "install.sh", {"DESTDIR": str(stage)})
    assert (stage / "opt/autopwn-suite/autopwn.py").is_file()
    wrapper = stage / "usr/local/bin/autopwn-suite"
    assert 'REPO_DIR="/opt/autopwn-suite"' in wrapper.read_text()


@posix_only
def test_bindir_and_appdir_override_prefix(source_tree, tmp_path):
    stage = tmp_path / "stage"
    run_script(
        source_tree, "install.sh",
        {"DESTDIR": str(stage), "PREFIX": "/usr", "BINDIR": "/usr/sbin", "APPDIR": "/srv/ap//"})
    assert (stage / "srv/ap/autopwn.py").is_file()
    assert 'REPO_DIR="/srv/ap"' in (stage / "usr/sbin/autopwn-suite").read_text()


@posix_only
def test_relative_destdir_is_made_absolute(source_tree, tmp_path):
    run_script(source_tree, "install.sh", {"DESTDIR": "relative-stage"}, cwd=tmp_path)
    assert (tmp_path / "relative-stage/opt/autopwn-suite/autopwn.py").is_file()


@posix_only
def test_non_staged_install_creates_venv_without_sudo(source_tree, tmp_path):
    fake_bin = tmp_path / "no-sudo"
    fake_bin.mkdir()
    sudo = fake_bin / "sudo"
    sudo.write_text("#!/usr/bin/env bash\necho sudo-was-called >&2\nexit 99\n")
    sudo.chmod(0o755)
    pip_log = tmp_path / "pip.log"
    app, bindir = tmp_path / "live/app", tmp_path / "live/bin"
    env = {
        "APPDIR": str(app), "BINDIR": str(bindir),
        "PYTHON": str(tmp_path / "fake-python"), "PIP_LOG": str(pip_log),
        "REQUIREMENTS_FILE": "requirements-locked.txt",
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    result = run_script(source_tree, "install.sh", env)
    assert "sudo-was-called" not in result.stderr
    assert (app / ".venv/bin/python").is_file()
    assert (bindir / "autopwn-suite").stat().st_mode & stat.S_IXUSR
    assert f'REPO_DIR="{app}"' in (bindir / "autopwn-suite").read_text()
    log = pip_log.read_text()
    assert "install --upgrade pip setuptools wheel" in log
    assert f"install -r {app}/requirements-locked.txt" in log

    run_script(source_tree, "uninstall.sh", {"APPDIR": str(app), "BINDIR": str(bindir),
                                            "PATH": env["PATH"]})
    assert not app.exists() and not (bindir / "autopwn-suite").exists()


@posix_only
def test_uninstall_destdir_removes_only_staged_files(source_tree, tmp_path):
    stage = tmp_path / "stage"
    env = {"DESTDIR": str(stage), "PREFIX": "/usr"}
    run_script(source_tree, "install.sh", env)
    unit = stage / "etc/systemd/system/autopwn-daemon.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Unit]\n")
    keep = stage / "usr/bin/other-tool"
    keep.write_text("keep\n")

    result = run_script(source_tree, "uninstall.sh", env)
    assert "systemctl" not in result.stdout
    assert not (stage / "usr/lib/autopwn-suite").exists()
    assert not (stage / "usr/bin/autopwn-suite").exists()
    assert not unit.exists()
    assert keep.read_text() == "keep\n"


@posix_only
@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh"])
def test_unsafe_or_relative_paths_are_rejected(source_tree, tmp_path, script):
    run_script(source_tree, script, {"APPDIR": "/", "DESTDIR": str(tmp_path / "s")}, expect=2)
    run_script(source_tree, script, {"APPDIR": "relative/dir", "DESTDIR": str(tmp_path / "s")}, expect=2)
    run_script(source_tree, script, {"PREFIX": "usr", "DESTDIR": str(tmp_path / "s")}, expect=2)


# ---------------------------------------------------------------- repeatable builds


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "export_locked_requirements", ROOT / "scripts/export_locked_requirements.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_locked_requirements_match_poetry_lock():
    exporter = load_exporter()
    committed = (ROOT / "requirements-locked.txt").read_bytes().decode().replace("\r\n", "\n")
    assert committed == exporter.render(ROOT / "poetry.lock"), (
        "requirements-locked.txt is stale; run python scripts/export_locked_requirements.py")


def test_locked_requirements_are_fully_hash_pinned():
    text = (ROOT / "requirements-locked.txt").read_text()
    requirements = [line for line in text.splitlines() if re.match(r"^[A-Za-z0-9]", line)]
    assert requirements
    for line in requirements:
        assert re.match(r"^[A-Za-z0-9._-]+==[^\s=]+", line), line
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 4)[4])
    for block in blocks:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", block), block
    assert "pytest" not in text and "ruff" not in text  # runtime group only


def test_dockerfile_follows_repeatable_build_policy():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^ARG BASE_IMAGE=\S+:\S+@sha256:[0-9a-f]{64}$", dockerfile, re.M)
    assert re.search(r"^ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z$", dockerfile, re.M)
    assert "snapshot.debian.org/archive/debian/" in dockerfile
    assert "ARG SOURCE_DATE_EPOCH" in dockerfile
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile
    assert "pip install --no-compile --require-hashes --only-binary=:all: -r requirements-locked.txt" in dockerfile
    assert not re.search(r"^FROM\s+python:3-slim", dockerfile, re.M)
    # The tracked ignore file must not exclude the hash-pinned requirements.
    assert "requirements-locked.txt" not in (ROOT / ".dockerignore").read_text()


def test_publish_workflow_passes_source_date_epoch():
    workflow = (ROOT / ".github/workflows/publish-docker.yml").read_text()
    assert "SOURCE_DATE_EPOCH=${{ needs.validate.outputs.source_date_epoch }}" in workflow
    assert "rewrite-timestamp=true" in workflow
