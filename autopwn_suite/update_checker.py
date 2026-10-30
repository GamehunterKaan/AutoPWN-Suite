# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Check GitHub for a newer release or commit than the running copy."""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

import requests

from autopwn_suite.paths import data_dir

UPSTREAM_REPO = "GamehunterKaan/AutoPWN-Suite"  # the repository whose releases PyPI's autopwn-suite package holds
DEFAULT_REPO = os.environ.get("AUTOPWN_UPDATE_REPO", UPSTREAM_REPO)
PACKAGE = "autopwn-suite"
API_ROOT = "https://api.github.com/repos/{repo}"
REQUEST_TIMEOUT = 6
CHANNEL_FILE_NAME = "update_channel.txt"


def _channel_file():
    return data_dir() / CHANNEL_FILE_NAME


def _load_saved_channel():
    try:
        value = _channel_file().read_text().strip()
    except OSError:
        return None
    return value if value in ("release", "commit") else None


def _save_channel(channel):
    try:
        path = _channel_file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(channel)
    except OSError:
        pass


def resolve_update_channel(explicit_channel):
    """Resolve the effective channel: an explicit CLI choice wins and is remembered;
    otherwise fall back to the last remembered choice, then "release"."""
    if explicit_channel is not None:
        _save_channel(explicit_channel)
        return explicit_channel
    return _load_saved_channel() or "release"


class UpdateCheckError(RuntimeError):
    """A refused or failed check or update. ``code`` names the reason for callers, such as the dashboard, that
    show their own fixed text instead of the message."""

    def __init__(self, message, code="update_failed"):
        super().__init__(message)
        self.code = code


@dataclass
class UpdateStatus:
    mode: str
    repo: str
    current: str
    latest: str
    url: str
    update_available: bool


_REPO_PART = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_REF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+-]{0,254}")
_COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _checked_repo(repo):
    """``repo`` (or the default) when it is OWNER/REPO in GitHub's character set, so that it can only extend the
    path of the two fixed GitHub URLs."""
    repo = repo or DEFAULT_REPO
    parts = repo.split("/") if isinstance(repo, str) else []
    if len(parts) != 2 or any(part in (".", "..") or not _REPO_PART.fullmatch(part) for part in parts):
        raise UpdateCheckError(
            _(
                "The repository (--update-repo or AUTOPWN_UPDATE_REPO) must be written OWNER/REPO, "
                "using letters, digits, '.', '_' and '-'."
            ),
            "update_invalid_repo",
        )
    return repo


def _checked_ref(name, what):
    """A branch or tag name that git and the GitHub API read as a plain name: it cannot start with '-' (git would
    read an option), hold '..' or '//', start a component with '.', or end a component in '.lock'."""
    if (
        not isinstance(name, str)
        or not _REF_NAME.fullmatch(name)
        or ".." in name
        or "//" in name
        or "/." in name
        or ".lock/" in name
        or name.endswith(("/", ".", ".lock"))
    ):
        raise UpdateCheckError(
            _("The release tag name is not a plain git name.")
            if what == "release tag"
            else _("The branch name is not a plain git name."),
            "update_invalid_ref",
        )
    return name


def _text(data, key, default=""):
    """A string field of a GitHub response; a value of any other type counts as missing."""
    value = data.get(key)
    return value if isinstance(value, str) else default


def _get_json(url):
    try:
        response = requests.get(
            url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/vnd.github+json"}
        )
    except requests.RequestException as exc:
        raise UpdateCheckError(_("Could not reach GitHub ({error_type}).").format(error_type=type(exc).__name__),
                               "update_unreachable") from exc
    if response.status_code == 404:
        raise UpdateCheckError(_("Nothing found at {url}.").format(url=url), "update_not_found")
    if response.status_code == 403:
        raise UpdateCheckError(_("GitHub API rate limit exceeded; try again later."), "update_rate_limited")
    if not response.ok:
        raise UpdateCheckError(_("GitHub API returned HTTP {status}.").format(status=response.status_code),
                               "update_http_error")
    try:
        payload = response.json()
    except (ValueError, RecursionError) as exc:
        raise UpdateCheckError(_("GitHub API returned an unexpected response."), "update_bad_response") from exc
    if not isinstance(payload, dict):
        raise UpdateCheckError(_("GitHub API returned an unexpected response."), "update_bad_response")
    return payload


def _parse_version(tag):
    numbers = re.findall(r"\d+", (tag or "")[:100])
    return tuple(int(n) for n in numbers) if numbers else (0,)


def check_release(current_version, repo=None):
    """Compare ``current_version`` against the repo's latest GitHub release tag."""
    repo = _checked_repo(repo)
    data = _get_json(f"{API_ROOT.format(repo=repo)}/releases/latest")
    latest_tag = _text(data, "tag_name")
    update_available = _parse_version(latest_tag) > _parse_version(current_version)
    return UpdateStatus(
        mode="release",
        repo=repo,
        current=current_version,
        latest=latest_tag,
        url=_text(data, "html_url", f"https://github.com/{repo}/releases"),
        update_available=update_available,
    )


def _local_commit():
    """HEAD of the checkout this package runs from, or None when there is none. Git's top-level directory
    must be the package's parent: a copy installed inside another repository (a venv under a dotfiles
    repository) would otherwise report and update that repository."""
    root = _repo_root()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel", "HEAD"],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=5,
            check=True,
        )
        lines = result.stdout.splitlines()
        if len(lines) != 2 or not os.path.samefile(lines[0], root):
            return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return lines[1].strip() or None


def check_commit(branch="main", repo=None):
    """Compare the local git HEAD against the repo's latest commit on ``branch``."""
    repo = _checked_repo(repo)
    branch = _checked_ref(branch, "branch")
    local = _local_commit()
    if not local:
        raise UpdateCheckError(
            _(
                "Commit-based update checks require a git checkout of AutoPWN Suite; "
                "use --update-channel release instead."
            ),
            "update_not_checkout",
        )
    data = _get_json(f"{API_ROOT.format(repo=repo)}/commits/{branch}")
    latest_sha = _text(data, "sha")
    # A checkout that already contains the branch's commit (it is ahead of the branch) has nothing to update.
    # Only a commit ID reaches git; one the checkout lacks counts as new.
    update_available = bool(latest_sha) and latest_sha != local and not (
        _COMMIT_ID.fullmatch(latest_sha) and _is_ancestor(latest_sha, local))
    return UpdateStatus(
        mode="commit",
        repo=repo,
        current=local[:12],
        latest=latest_sha[:12] if latest_sha else "unknown",
        url=_text(data, "html_url", f"https://github.com/{repo}/commits/{branch}"),
        update_available=update_available,
    )


def check_for_updates(current_version, channel="release", branch="main", repo=None):
    """Dispatch to :func:`check_release` or :func:`check_commit` by ``channel``."""
    if channel == "commit":
        return check_commit(branch=branch, repo=repo)
    return check_release(current_version, repo=repo)


def format_status(status: UpdateStatus) -> str:
    if status.update_available:
        return _("Update available ({mode}): {current} -> {latest}\n{url}").format(
            mode=status.mode, current=status.current, latest=status.latest, url=status.url
        )
    return _("Up to date ({mode}): {current} (latest: {latest}).").format(
        mode=status.mode, current=status.current, latest=status.latest
    )


@dataclass
class UpdateResult:
    mode: str
    repo: str
    previous: str
    new: str
    ref: str
    dependencies_changed: bool = False

    @property
    def changed(self):
        return self.previous != self.new


# An update that changes one of these needs its dependencies installed again before the restart.
_DEPENDENCY_FILES = ("pyproject.toml", "poetry.lock", "requirements.txt", "requirements-locked.txt")


def _repo_root():
    return Path(__file__).resolve().parent.parent


def _run_git(args, check=True):
    try:
        return subprocess.run(
            ["git", *args], cwd=_repo_root(), capture_output=True, encoding="utf-8", errors="replace", timeout=30,
            check=check,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateCheckError(_("git {command} could not run ({error_type}).").format(command=args[0], error_type=type(exc).__name__),
                               "update_git_failed") from exc


def _ensure_clean_worktree():
    status = _run_git(["status", "--porcelain"])
    if status.stdout.strip():
        raise UpdateCheckError(
            _("Working tree has uncommitted changes; commit or stash them before applying an update."),
            "update_dirty_worktree",
        )


def _current_branch():
    result = _run_git(["symbolic-ref", "--short", "-q", "HEAD"], check=False)
    return result.stdout.strip() or None


def _is_ancestor(ancestor, descendant):
    return _run_git(["merge-base", "--is-ancestor", ancestor, descendant], check=False).returncode == 0


def _remote_url(repo):
    return f"https://github.com/{repo}.git"


def _fetch(repo, refspec):
    result = _run_git(["fetch", _remote_url(repo), refspec], check=False)
    if result.returncode != 0:
        raise UpdateCheckError(_("git fetch from {repo} failed (exit status {status}).").format(repo=repo, status=result.returncode),
                               "update_fetch_failed")


def _diverged(onto_description):
    return UpdateCheckError(
        _(
            "Cannot fast-forward to {onto}: the local branch has diverged. "
            "Resolve manually (e.g. git rebase, or git reset --hard after backing up changes)."
        ).format(onto=onto_description),
        "update_diverged",
    )


def _fast_forward_to(ref, onto_description):
    result = _run_git(["merge", "--ff-only", ref], check=False)
    if result.returncode != 0:
        if _is_ancestor("HEAD", ref):
            raise UpdateCheckError(
                _(
                    "git merge could not fast-forward to {onto} (exit status {status}), although nothing diverged. "
                    "Check for another running git command or a stale .git/index.lock, then try again."
                ).format(onto=onto_description, status=result.returncode),
                "update_git_failed",
            )
        raise _diverged(onto_description)


def current_commit():
    """The commit of the git checkout this copy runs from, which :func:`apply_update` can move, or None."""
    return _local_commit()


def _dependencies_changed(previous, new):
    """Whether the update between two commits changed a dependency file; a diff that fails counts as a change."""
    if previous == new:
        return False
    result = _run_git(["diff", "--name-only", previous, new, "--", *_DEPENDENCY_FILES], check=False)
    return result.returncode != 0 or bool(result.stdout.strip())


def _result(mode, repo, previous, new, ref):
    return UpdateResult(mode=mode, repo=repo, previous=previous[:12], new=new[:12], ref=ref,
                        dependencies_changed=_dependencies_changed(previous, new))


def apply_commit_update(branch="main", repo=None):
    """Fast-forward the current branch to ``repo``'s latest commit on ``branch``."""
    repo = _checked_repo(repo)
    branch = _checked_ref(branch, "branch")
    if not _local_commit():
        raise UpdateCheckError(_("Applying an update requires a git checkout of AutoPWN Suite."), "update_not_checkout")
    if _current_branch() is None:
        raise UpdateCheckError(_("HEAD is detached; checkout a branch before applying a commit-based update."),
                               "update_detached_head")
    _ensure_clean_worktree()
    previous = _local_commit()
    _fetch(repo, branch)
    _fast_forward_to("FETCH_HEAD", f"{repo}@{branch}")
    new = _local_commit()
    return _result("commit", repo, previous, new, branch)


def apply_release_update(repo=None):
    """Fast-forward (or checkout, if detached) to ``repo``'s latest release tag."""
    repo = _checked_repo(repo)
    if not _local_commit():
        raise UpdateCheckError(_("Applying an update requires a git checkout of AutoPWN Suite."), "update_not_checkout")
    _ensure_clean_worktree()
    data = _get_json(f"{API_ROOT.format(repo=repo)}/releases/latest")
    tag = _text(data, "tag_name")
    if not tag:
        raise UpdateCheckError(_("Latest release has no tag name."), "update_bad_response")
    _checked_ref(tag, "release tag")
    previous = _local_commit()
    _fetch(repo, f"refs/tags/{tag}:refs/tags/{tag}")
    if _current_branch() is None:
        # The same rule as the fast-forward on a branch: move only forward, so a detached HEAD that is newer
        # than the release stays where it is instead of going back to the tag.
        if _is_ancestor("HEAD", f"refs/tags/{tag}"):
            result = _run_git(["checkout", "--detach", f"refs/tags/{tag}"], check=False)
            if result.returncode != 0:
                raise UpdateCheckError(_("git checkout {tag} failed (exit status {status}).").format(tag=tag, status=result.returncode),
                                       "update_git_failed")
        elif not _is_ancestor(f"refs/tags/{tag}", "HEAD"):
            raise _diverged(tag)
    else:
        _fast_forward_to(tag, tag)
    new = _local_commit()
    return _result("release", repo, previous, new, tag)


# ── Installations other than a git checkout ──

PACKAGE_MANAGERS = ("pipx", "uv", "pip")
# pipx and uv keep each tool in a virtual environment of its own that holds one of these files.
_TOOL_MARKERS = (("pipx", "pipx_metadata.json"), ("uv", "uv-receipt.toml"))
_DOCKER_MARKER = Path("/.dockerenv")  # Docker creates it in every container
# A release version as PyPI holds it: the only text from GitHub that reaches a package manager.
_RELEASE_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}")
_INSTALL_TIMEOUT = 900
# Windows locks a running program's files: a package manager that replaces the autopwn-suite.exe launcher this process
# runs from fails halfway and can leave the environment without the package. There it runs after AutoPWN Suite exits.
_FILES_LOCKED_WHILE_RUNNING = os.name == "nt"


def install_method():
    """How the running copy was installed, which decides how it updates: "checkout" (a git checkout of this
    project, which apply_update fast-forwards), "pipx" or "uv" (a tool environment of either), "pip" (another
    virtual environment that holds the package, as pip or install.sh makes), "binary" (a standalone binary),
    "docker" (the container image) or "other"."""
    if getattr(sys, "frozen", False):
        return "binary"
    if _local_commit():
        return "checkout"
    if _DOCKER_MARKER.exists():
        return "docker"
    prefix = Path(sys.prefix)
    for method, marker in _TOOL_MARKERS:
        if (prefix / marker).is_file():
            return method
    if sys.prefix != sys.base_prefix and _installed_in(prefix):
        return "pip"
    return "other"


def _installed_in(prefix):
    """Whether the running code is the autopwn-suite package installed under `prefix`, not a copy run from a folder
    while the environment holds another."""
    try:
        metadata.distribution(PACKAGE)
        Path(__file__).resolve().relative_to(prefix.resolve())
    except (metadata.PackageNotFoundError, ValueError, OSError):
        return False
    return True


def installed_version():
    """The version of the autopwn-suite package on disk, which a package update changes under the running process;
    None when no package is installed."""
    try:
        return metadata.version(PACKAGE)
    except (metadata.PackageNotFoundError, OSError, ValueError):
        return None


def can_apply(method):
    """Whether apply_update can update this copy in place: a checkout, or (except on Windows) a pipx, uv or pip
    installation that this account may change, with pipx or uv on PATH."""
    if method == "checkout":
        return True
    return (method in PACKAGE_MANAGERS and not _FILES_LOCKED_WHILE_RUNNING and os.access(_repo_root(), os.W_OK)
            and (method == "pip" or shutil.which(method) is not None))


def update_command(method):
    """The command or page that updates a copy installed this way, for messages; None for an unknown installation."""
    return {
        "checkout": "autopwn-suite --apply-update",
        "pipx": f"pipx upgrade {PACKAGE}",
        "uv": f"uv tool upgrade {PACKAGE}",
        "pip": f'"{sys.executable}" -m pip install --upgrade {PACKAGE}' if _FILES_LOCKED_WHILE_RUNNING
        else "autopwn-suite --apply-update" if os.access(_repo_root(), os.W_OK) else "sudo autopwn-suite --apply-update",
        "binary": f"https://github.com/{UPSTREAM_REPO}/releases/latest",
        "docker": "docker compose pull && docker compose up -d",
    }.get(method)


def _package_command(method, version):
    """The argument vector that updates a pipx, uv or pip installation from PyPI. Wheels only: no package's own build
    code runs. pipx and uv install the newest release; pip installs `version`."""
    if method == "pip":
        return [sys.executable, "-m", "pip", "install", "--upgrade", "--only-binary=:all:", "--no-input",
                "--disable-pip-version-check", f"{PACKAGE}=={version}"]
    tool = shutil.which(method)
    if tool is None:
        raise UpdateCheckError(_("{tool} is not on PATH; run {command} where it is.").format(
            tool=method, command=update_command(method)), "update_tool_missing")
    if method == "pipx":
        return [tool, "upgrade", PACKAGE, "--pip-args=--only-binary=:all:"]
    return [tool, "tool", "upgrade", PACKAGE, "--no-build"]


def apply_package_update(method, repo=None):
    """Update an installation that pipx, uv or pip made to the latest release on PyPI; it never moves back."""
    repo = _checked_repo(repo)
    if repo != UPSTREAM_REPO:
        raise UpdateCheckError(
            _("PyPI holds the releases of {upstream} only; --update-repo and AUTOPWN_UPDATE_REPO apply to git "
              "checkouts.").format(upstream=UPSTREAM_REPO), "update_repo_not_pypi")
    if _FILES_LOCKED_WHILE_RUNNING:
        raise UpdateCheckError(
            _("Windows locks the files of a running program; close AutoPWN Suite, then run: {command}").format(
                command=update_command(method)), "update_windows")
    if not os.access(_repo_root(), os.W_OK):
        raise UpdateCheckError(
            _("This installation belongs to another account (install.sh installs it as root); "
              "run sudo autopwn-suite --apply-update."), "update_needs_root")
    data = _get_json(f"{API_ROOT.format(repo=repo)}/releases/latest")
    tag = _text(data, "tag_name")
    version = tag[1:] if tag[:1] in ("v", "V") else tag
    if not _RELEASE_VERSION.fullmatch(version):
        raise UpdateCheckError(_("The latest release names no version that PyPI could hold."), "update_bad_response")
    previous = installed_version() or "unknown"
    if _parse_version(version) <= _parse_version(previous):
        return UpdateResult("release", repo, previous, previous, tag)
    command = _package_command(method, version)
    try:
        completed = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace",
                                   timeout=_INSTALL_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateCheckError(_("{tool} could not run ({error_type}).").format(
            tool=method, error_type=type(exc).__name__), "update_install_failed") from exc
    if completed.returncode != 0:
        raise UpdateCheckError(_("{tool} could not update AutoPWN Suite (exit status {status}).").format(
            tool=method, status=completed.returncode), "update_install_failed")
    return UpdateResult("release", repo, previous, installed_version() or previous, tag)


def _manual_update(method):
    """The refusal for an installation that cannot update itself, saying how to update it instead."""
    if method == "binary":
        return UpdateCheckError(
            _("A standalone binary cannot replace itself safely; download the new one from {url} and verify it as "
              "the release notes describe.").format(url=update_command("binary")), "update_binary")
    if method == "docker":
        return UpdateCheckError(
            _("A container cannot update its own image; on the host, run: {command}").format(
                command=update_command("docker")), "update_docker")
    return UpdateCheckError(_("Applying an update requires a git checkout of AutoPWN Suite."), "update_not_checkout")


def update_hint(method):
    """One line saying how to apply an available update to a copy installed this way."""
    if method == "checkout" or method in PACKAGE_MANAGERS and can_apply(method):
        return _("Run --apply-update to install it.")
    if method in PACKAGE_MANAGERS and _FILES_LOCKED_WHILE_RUNNING:
        return _("Close AutoPWN Suite, then update it with: {command}").format(command=update_command(method))
    if method in PACKAGE_MANAGERS:
        return _("Update it with: {command}").format(command=update_command(method))
    return str(_manual_update(method))


def apply_update(channel="release", branch="main", repo=None):
    """Update this copy the way it was installed: :func:`apply_commit_update` or :func:`apply_release_update` for a
    git checkout, :func:`apply_package_update` for pipx, uv and pip; other installations are refused with how
    to update them."""
    if channel == "commit":
        return apply_commit_update(branch=branch, repo=repo)
    repo = _checked_repo(repo)
    method = install_method()
    if method in PACKAGE_MANAGERS:
        return apply_package_update(method, repo=repo)
    if method != "checkout":
        raise _manual_update(method)
    return apply_release_update(repo=repo)


def format_result(result: UpdateResult) -> str:
    if not result.changed:
        return _("Already up to date ({mode}): {current} ({ref}).").format(
            mode=result.mode, current=result.new, ref=result.ref)
    text = _(
        "Updated ({mode}) {previous} -> {new} ({ref}). Restart AutoPWN Suite to use the updated code."
    ).format(mode=result.mode, previous=result.previous, new=result.new, ref=result.ref)
    if result.dependencies_changed:
        text += " " + _(
            "This update changes the dependencies: install them again as the README's \"From source\" "
            "installation describes before restarting."
        )
    return text
