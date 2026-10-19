# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""install.sh / uninstall.sh path variables and repeatable-build policy checks."""

import importlib.util
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
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
# so the test never touches the network or the real system. The two `-c` checks
# install.sh makes before it touches anything pass unless FAKE_OLD_PYTHON or
# FAKE_NO_ENSUREPIP is set; the fake pip fails when FAKE_PIP_FAILS is set and, when
# FAKE_PIP_HANGS names a file, creates it and waits to be killed.
FAKE_PYTHON = """#!/usr/bin/env bash
set -e
if [ "$1" = "-c" ]; then
    case "$2" in
        *version_info*) exit "${FAKE_OLD_PYTHON:-0}" ;;
        *ensurepip*) exit "${FAKE_NO_ENSUREPIP:-0}" ;;
    esac
fi
[ "$1" = "-m" ] && [ "$2" = "venv" ] || { echo "unexpected: $*" >&2; exit 1; }
venv="$3"
mkdir -p "$venv/bin"
printf '%s\\n' 'export PATH="'"$venv"'/bin:$PATH"' 'deactivate() { :; }' > "$venv/bin/activate"
printf '%s\\n' '#!/usr/bin/env bash' 'echo "$*" >> "$PIP_LOG"' \\
    '[ -z "${FAKE_PIP_HANGS:-}" ] || { touch "$FAKE_PIP_HANGS"; sleep 60; }' '[ -z "${FAKE_PIP_FAILS:-}" ]' > "$venv/bin/pip"
printf '%s\\n' '#!/usr/bin/env bash' 'exit 0' > "$venv/bin/python"
chmod +x "$venv/bin/pip" "$venv/bin/python"
"""


@pytest.fixture
def source_tree(tmp_path):
    repo = tmp_path / "repo"
    (repo / "autopwn_suite").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".venv").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".venv" / "marker").write_text("do not copy\n")
    (repo / "autopwn_suite" / "tool.py").write_text("print('tool')\n")
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
    env = {k: v for k, v in os.environ.items() if k not in {"PREFIX", "BINDIR", "APPDIR", "DESTDIR", "PYTHON", "SYSTEMDDIR"}}
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
def test_destdir_stages_the_source_and_links_to_the_final_path(source_tree, tmp_path):
    stage = tmp_path / "stage"
    result = run_script(source_tree, "install.sh", {"DESTDIR": str(stage), "PREFIX": "/usr"})

    app = stage / "usr/lib/autopwn-suite"
    command_link = stage / "usr/bin/autopwn-suite"
    assert (app / "src/autopwn.py").is_file()
    assert (app / "src/autopwn_suite/tool.py").is_file()
    assert not (app / "src/.git").exists() and not (app / "src/.venv").exists()
    assert command_link.is_symlink()
    assert os.readlink(command_link) == "/usr/lib/autopwn-suite/.venv/bin/autopwn-suite"
    # No venv is created inside DESTDIR; the operator is told how to make it.
    assert "python3 -m venv /usr/lib/autopwn-suite/.venv" in result.stdout
    assert "pip install --no-deps /usr/lib/autopwn-suite/src" in result.stdout
    # Nothing escaped the staging directory.
    written = {p.relative_to(stage).parts[0] for p in stage.iterdir()}
    assert written == {"usr"}


@posix_only
@pytest.mark.parametrize("destdir", ["pkgroot", "debian/tmp"])
def test_destdir_inside_the_checkout_is_not_copied_into_itself(source_tree, destdir):
    # The documented `DESTDIR="$PWD/pkgroot"` and Debian's debian/tmp both sit inside the source tree.
    stage = source_tree / destdir
    for _ in range(2):  # the second run stages over the first
        run_script(source_tree, "install.sh", {"DESTDIR": str(stage), "PREFIX": "/usr"}, cwd=source_tree)
    staged = stage / "usr/lib/autopwn-suite/src"
    assert (staged / "autopwn.py").is_file() and (staged / "autopwn_suite/tool.py").is_file()
    assert not (staged / destdir).exists()
    assert os.readlink(stage / "usr/bin/autopwn-suite") == "/usr/lib/autopwn-suite/.venv/bin/autopwn-suite"


@posix_only
def test_default_layout_is_unchanged_under_destdir(source_tree, tmp_path):
    stage = tmp_path / "stage"
    run_script(source_tree, "install.sh", {"DESTDIR": str(stage)})
    assert (stage / "opt/autopwn-suite/src/autopwn.py").is_file()
    command_link = stage / "usr/local/bin/autopwn-suite"
    assert os.readlink(command_link) == "/opt/autopwn-suite/.venv/bin/autopwn-suite"


@posix_only
def test_bindir_and_appdir_override_prefix(source_tree, tmp_path):
    stage = tmp_path / "stage"
    run_script(
        source_tree, "install.sh",
        {"DESTDIR": str(stage), "PREFIX": "/usr", "BINDIR": "/usr/sbin", "APPDIR": "/srv/ap//"})
    assert (stage / "srv/ap/src/autopwn.py").is_file()
    assert os.readlink(stage / "usr/sbin/autopwn-suite") == "/srv/ap/.venv/bin/autopwn-suite"


@posix_only
def test_relative_destdir_is_made_absolute(source_tree, tmp_path):
    run_script(source_tree, "install.sh", {"DESTDIR": "relative-stage"}, cwd=tmp_path)
    assert (tmp_path / "relative-stage/opt/autopwn-suite/src/autopwn.py").is_file()


@posix_only
def test_non_staged_install_creates_venv_without_sudo(source_tree, tmp_path):
    fake_bin = tmp_path / "no-sudo"
    fake_bin.mkdir()
    sudo = fake_bin / "sudo"
    sudo.write_text("#!/usr/bin/env bash\necho sudo-was-called >&2\nexit 99\n")
    sudo.chmod(0o755)
    pip_log = tmp_path / "pip.log"
    app, bindir = tmp_path / "live/app", tmp_path / "live/bin"
    # An earlier release left a wrapper script here and the daemon keeps its configuration in the app directory.
    bindir.mkdir(parents=True)
    (bindir / "autopwn-suite").write_text("#!/usr/bin/env bash\n")
    app.mkdir(parents=True)
    (app / "autopwn-daemon.conf").write_text("[DAEMON]\n")
    env = {
        "APPDIR": str(app), "BINDIR": str(bindir), "SYSTEMDDIR": str(tmp_path / "no-systemd"),
        "PYTHON": str(tmp_path / "fake-python"), "PIP_LOG": str(pip_log),
        "REQUIREMENTS_FILE": "requirements-locked.txt",
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    }
    result = run_script(source_tree, "install.sh", env)
    assert "sudo-was-called" not in result.stderr
    assert (app / ".venv/bin/python").is_file()
    assert (bindir / "autopwn-suite").is_symlink()
    assert os.readlink(bindir / "autopwn-suite") == f"{app}/.venv/bin/autopwn-suite"
    # Installed from the checkout itself: no second copy of the source tree.
    assert not (app / "autopwn.py").exists() and not (app / "src").exists()
    assert (app / "autopwn-daemon.conf").read_text() == "[DAEMON]\n"
    log = pip_log.read_text()
    assert "install --upgrade pip setuptools wheel" in log
    assert f"install -r {source_tree}/requirements-locked.txt" in log
    assert f"install --no-deps {source_tree}" in log

    run_script(source_tree, "uninstall.sh", {"APPDIR": str(app), "BINDIR": str(bindir),
                                            "PATH": env["PATH"]})
    assert not app.exists() and not os.path.lexists(bindir / "autopwn-suite")


def working_install(tmp_path):
    """An existing install: a venv holding the command and a link to it, as install.sh leaves them."""
    app, bindir = tmp_path / "live/app", tmp_path / "live/bin"
    command = app / ".venv/bin/autopwn-suite"
    command.parent.mkdir(parents=True)
    command.write_text("#!/usr/bin/env bash\necho old\n")
    command.chmod(0o755)
    (app / ".venv/marker").write_text("working\n")
    bindir.mkdir(parents=True)
    (bindir / "autopwn-suite").symlink_to(command)
    env = {
        "APPDIR": str(app), "BINDIR": str(bindir), "SYSTEMDDIR": str(tmp_path / "no-systemd"),
        "PYTHON": str(tmp_path / "fake-python"), "PIP_LOG": str(tmp_path / "pip.log"),
    }
    return app, bindir, env


def assert_working_install_untouched(app, bindir):
    assert (app / ".venv/marker").read_text() == "working\n"
    assert (bindir / "autopwn-suite").resolve() == (app / ".venv/bin/autopwn-suite").resolve()
    assert os.access(bindir / "autopwn-suite", os.X_OK)  # not a dangling link
    assert sorted(path.name for path in app.iterdir()) == [".venv"]
    assert sorted(path.name for path in (app / ".venv").iterdir()) == ["bin", "marker"]


@posix_only
@pytest.mark.parametrize("failure, message", [
    ({"FAKE_OLD_PYTHON": "1"}, "3.10"),
    ({"FAKE_NO_ENSUREPIP": "1"}, "python3-venv"),
    ({"FAKE_PIP_FAILS": "1"}, "restoring the previous virtual environment"),
], ids=["python-too-old", "no-venv-support", "pip-fails"])
def test_failed_upgrade_leaves_the_working_install(source_tree, tmp_path, failure, message):
    app, bindir, env = working_install(tmp_path)
    result = run_script(source_tree, "install.sh", {**env, **failure}, expect=1)
    assert message in result.stderr
    assert_working_install_untouched(app, bindir)


@posix_only
def test_killed_upgrade_leaves_the_working_install(source_tree, tmp_path):
    app, bindir, env = working_install(tmp_path)
    started = tmp_path / "pip-started"
    process = subprocess.Popen(
        [BASH, str(source_tree / "install.sh")], env={**os.environ, **env, "FAKE_PIP_HANGS": str(started)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while not started.exists():
            assert process.poll() is None and time.monotonic() < deadline, "install.sh ended before pip ran"
            time.sleep(0.05)
        os.killpg(process.pid, signal.SIGTERM)  # the script and the pip it is waiting for
        _, stderr = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
    assert "restoring the previous virtual environment" in stderr
    assert_working_install_untouched(app, bindir)


@posix_only
def test_upgrade_replaces_the_environment_and_removes_the_old_one(source_tree, tmp_path):
    app, bindir, env = working_install(tmp_path)
    result = run_script(source_tree, "install.sh", env)
    assert "Installation complete!" in result.stdout
    assert (app / ".venv/bin/python").is_file() and not (app / ".venv/marker").exists()
    assert sorted(path.name for path in app.iterdir()) == [".venv"]  # nothing set aside is left behind
    assert os.readlink(bindir / "autopwn-suite") == f"{app}/.venv/bin/autopwn-suite"


@posix_only
def test_environment_left_by_a_killed_upgrade_is_never_overwritten(source_tree, tmp_path):
    app, bindir, env = working_install(tmp_path)
    # A run that was killed mid-build left the working environment set aside and a half-built one in its place.
    (app / ".venv").rename(app / ".venv.old")
    (app / ".venv").mkdir()
    (app / ".venv/marker").write_text("half-built\n")
    result = run_script(source_tree, "install.sh", env, expect=1)
    assert ".venv.old" in result.stderr
    assert (app / ".venv.old/marker").read_text() == "working\n"
    assert (app / ".venv/marker").read_text() == "half-built\n"


LEGACY_UNIT = """[Service]
WorkingDirectory=/opt/autopwn-suite
ExecStart=/opt/autopwn-suite/.venv/bin/python /opt/autopwn-suite/autopwn.py -c /opt/autopwn-suite/autopwn-daemon.conf
"""
CURRENT_UNIT = """[Service]
WorkingDirectory=/opt/autopwn-suite
ExecStart=/opt/autopwn-suite/.venv/bin/python -m autopwn_suite -c /opt/autopwn-suite/autopwn-daemon.conf
"""


def install_with_unit(source_tree, tmp_path, unit, **extra):
    """A non-staged install with a fake systemd directory, optionally holding a daemon unit."""
    systemd = tmp_path / "systemd"
    systemd.mkdir()
    if unit is not None:
        (systemd / "autopwn-daemon.service").write_text(unit)
    env = {
        "APPDIR": str(tmp_path / "live/app"), "BINDIR": str(tmp_path / "live/bin"),
        "PYTHON": str(tmp_path / "fake-python"), "PIP_LOG": str(tmp_path / "pip.log"),
        "SYSTEMDDIR": str(systemd),
    }
    env.update(extra)
    return run_script(source_tree, "install.sh", env), systemd / "autopwn-daemon.service"


@posix_only
def test_install_warns_when_a_daemon_from_an_earlier_release_still_runs_its_own_copy(source_tree, tmp_path):
    result, unit = install_with_unit(source_tree, tmp_path, LEGACY_UNIT)
    assert "WARNING:" in result.stdout and "autopwn.py" in result.stdout
    assert "sudo autopwn-suite --daemon-install" in result.stdout
    # --daemon-install restarts the service itself, so no separate restart step is asked for.
    assert "also restarts it" in result.stdout and "systemctl restart" not in result.stdout
    if os.geteuid() != 0:
        assert "sudo bash install.sh" in result.stdout
    # The installer only reports: the service file is never rewritten or restarted.
    assert unit.read_text() == LEGACY_UNIT


@posix_only
@pytest.mark.parametrize("unit", [CURRENT_UNIT, None], ids=["current-unit", "no-unit"])
def test_install_stays_quiet_when_the_daemon_is_current_or_absent(source_tree, tmp_path, unit):
    result, _ = install_with_unit(source_tree, tmp_path, unit)
    assert "WARNING" not in result.stdout + result.stderr
    assert "Installation complete!" in result.stdout


@posix_only
def test_staged_install_never_inspects_the_systemd_directory(source_tree, tmp_path):
    systemd = tmp_path / "systemd"
    systemd.mkdir()
    (systemd / "autopwn-daemon.service").write_text(LEGACY_UNIT)
    result = run_script(source_tree, "install.sh", {"DESTDIR": str(tmp_path / "stage"), "SYSTEMDDIR": str(systemd)})
    assert "WARNING" not in result.stdout + result.stderr


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
    assert not os.path.lexists(stage / "usr/bin/autopwn-suite")
    assert not unit.exists()
    assert keep.read_text() == "keep\n"


@posix_only
@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh"])
def test_unsafe_or_relative_paths_are_rejected(source_tree, tmp_path, script):
    run_script(source_tree, script, {"APPDIR": "/", "DESTDIR": str(tmp_path / "s")}, expect=2)
    run_script(source_tree, script, {"APPDIR": "relative/dir", "DESTDIR": str(tmp_path / "s")}, expect=2)
    run_script(source_tree, script, {"PREFIX": "usr", "DESTDIR": str(tmp_path / "s")}, expect=2)
    run_script(source_tree, script, {"SYSTEMDDIR": "relative/dir", "DESTDIR": str(tmp_path / "s")}, expect=2)


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
