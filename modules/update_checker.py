# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Check GitHub for a newer release or commit than the running copy."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests

DEFAULT_REPO = os.environ.get("AUTOPWN_UPDATE_REPO", "GamehunterKaan/AutoPWN-Suite")
API_ROOT = "https://api.github.com/repos/{repo}"
REQUEST_TIMEOUT = 6
CHANNEL_FILE_NAME = "update_channel.txt"


def _channel_file():
    data_dir = Path(os.environ.get("AUTOPWN_DATA_DIR", str(Path(__file__).resolve().parent)))
    return data_dir / CHANNEL_FILE_NAME


def _load_saved_channel():
    try:
        value = _channel_file().read_text().strip()
    except OSError:
        return None
    return value if value in ("release", "commit") else None


def _save_channel(channel):
    try:
        _channel_file().write_text(channel)
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
    pass


@dataclass
class UpdateStatus:
    mode: str
    repo: str
    current: str
    latest: str
    url: str
    update_available: bool


def _get_json(url):
    try:
        response = requests.get(
            url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/vnd.github+json"}
        )
    except requests.RequestException as exc:
        raise UpdateCheckError(_("Could not reach GitHub: {error}").format(error=exc)) from exc
    if response.status_code == 404:
        raise UpdateCheckError(_("Nothing found at {url}.").format(url=url))
    if response.status_code == 403:
        raise UpdateCheckError(_("GitHub API rate limit exceeded; try again later."))
    if not response.ok:
        raise UpdateCheckError(_("GitHub API returned HTTP {status}.").format(status=response.status_code))
    try:
        return response.json()
    except ValueError as exc:
        raise UpdateCheckError(_("GitHub API returned an unexpected response.")) from exc


def _parse_version(tag):
    numbers = re.findall(r"\d+", tag or "")
    return tuple(int(n) for n in numbers) if numbers else (0,)


def check_release(current_version, repo=None):
    """Compare ``current_version`` against the repo's latest GitHub release tag."""
    repo = repo or DEFAULT_REPO
    data = _get_json(f"{API_ROOT.format(repo=repo)}/releases/latest")
    latest_tag = data.get("tag_name", "")
    update_available = _parse_version(latest_tag) > _parse_version(current_version)
    return UpdateStatus(
        mode="release",
        repo=repo,
        current=current_version,
        latest=latest_tag,
        url=data.get("html_url", f"https://github.com/{repo}/releases"),
        update_available=update_available,
    )


def _local_commit():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def check_commit(branch="main", repo=None):
    """Compare the local git HEAD against the repo's latest commit on ``branch``."""
    repo = repo or DEFAULT_REPO
    local = _local_commit()
    if not local:
        raise UpdateCheckError(
            _(
                "Commit-based update checks require a git checkout of AutoPWN Suite; "
                "use --update-channel release instead."
            )
        )
    data = _get_json(f"{API_ROOT.format(repo=repo)}/commits/{branch}")
    latest_sha = data.get("sha", "")
    update_available = bool(latest_sha) and latest_sha != local
    return UpdateStatus(
        mode="commit",
        repo=repo,
        current=local[:12],
        latest=latest_sha[:12] if latest_sha else "unknown",
        url=data.get("html_url", f"https://github.com/{repo}/commits/{branch}"),
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


def _repo_root():
    return Path(__file__).resolve().parent.parent


def _run_git(args, check=True):
    try:
        return subprocess.run(
            ["git", *args], cwd=_repo_root(), capture_output=True, text=True, timeout=30, check=check
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateCheckError(
            _("git {args} failed: {error}").format(args=" ".join(args), error=exc)
        ) from exc


def _ensure_clean_worktree():
    status = _run_git(["status", "--porcelain"])
    if status.stdout.strip():
        raise UpdateCheckError(
            _("Working tree has uncommitted changes; commit or stash them before applying an update.")
        )


def _current_branch():
    result = _run_git(["symbolic-ref", "--short", "-q", "HEAD"], check=False)
    return result.stdout.strip() or None


def _remote_url(repo):
    return f"https://github.com/{repo}.git"


def _fetch(repo, refspec):
    result = _run_git(["fetch", _remote_url(repo), refspec], check=False)
    if result.returncode != 0:
        raise UpdateCheckError(
            _("git fetch {repo} {refspec} failed: {error}").format(
                repo=repo, refspec=refspec, error=result.stderr.strip()
            )
        )


def _fast_forward_to(ref, onto_description):
    result = _run_git(["merge", "--ff-only", ref], check=False)
    if result.returncode != 0:
        raise UpdateCheckError(
            _(
                "Cannot fast-forward to {onto}: the local branch has diverged. "
                "Resolve manually (e.g. git rebase, or git reset --hard after backing up changes)."
            ).format(onto=onto_description)
        )


def apply_commit_update(branch="main", repo=None):
    """Fast-forward the current branch to ``repo``'s latest commit on ``branch``."""
    repo = repo or DEFAULT_REPO
    if not _local_commit():
        raise UpdateCheckError(_("Applying an update requires a git checkout of AutoPWN Suite."))
    if _current_branch() is None:
        raise UpdateCheckError(_("HEAD is detached; checkout a branch before applying a commit-based update."))
    _ensure_clean_worktree()
    previous = _local_commit()
    _fetch(repo, branch)
    _fast_forward_to("FETCH_HEAD", f"{repo}@{branch}")
    new = _local_commit()
    return UpdateResult(mode="commit", repo=repo, previous=previous[:12], new=new[:12], ref=branch)


def apply_release_update(repo=None):
    """Fast-forward (or checkout, if detached) to ``repo``'s latest release tag."""
    repo = repo or DEFAULT_REPO
    if not _local_commit():
        raise UpdateCheckError(_("Applying an update requires a git checkout of AutoPWN Suite."))
    _ensure_clean_worktree()
    data = _get_json(f"{API_ROOT.format(repo=repo)}/releases/latest")
    tag = data.get("tag_name")
    if not tag:
        raise UpdateCheckError(_("Latest release has no tag name."))
    previous = _local_commit()
    _fetch(repo, f"refs/tags/{tag}:refs/tags/{tag}")
    if _current_branch() is None:
        result = _run_git(["checkout", tag], check=False)
        if result.returncode != 0:
            raise UpdateCheckError(
                _("git checkout {tag} failed: {error}").format(tag=tag, error=result.stderr.strip())
            )
    else:
        _fast_forward_to(tag, tag)
    new = _local_commit()
    return UpdateResult(mode="release", repo=repo, previous=previous[:12], new=new[:12], ref=tag)


def apply_update(channel="release", branch="main", repo=None):
    """Dispatch to :func:`apply_release_update` or :func:`apply_commit_update` by ``channel``."""
    if channel == "commit":
        return apply_commit_update(branch=branch, repo=repo)
    return apply_release_update(repo=repo)


def format_result(result: UpdateResult) -> str:
    return _(
        "Updated ({mode}) {previous} -> {new} ({ref}). Restart AutoPWN Suite to use the updated code."
    ).format(mode=result.mode, previous=result.previous, new=result.new, ref=result.ref)
