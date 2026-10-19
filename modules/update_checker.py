# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Check GitHub for a newer release or commit than the running copy."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests

DEFAULT_REPO = os.environ.get("AUTOPWN_UPDATE_REPO", "codeyevsky/AutoPWN-Suite")
API_ROOT = "https://api.github.com/repos/{repo}"
REQUEST_TIMEOUT = 6


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
        raise UpdateCheckError(f"Could not reach GitHub: {exc}") from exc
    if response.status_code == 404:
        raise UpdateCheckError(f"Nothing found at {url}.")
    if response.status_code == 403:
        raise UpdateCheckError("GitHub API rate limit exceeded; try again later.")
    if not response.ok:
        raise UpdateCheckError(f"GitHub API returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError as exc:
        raise UpdateCheckError("GitHub API returned an unexpected response.") from exc


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
    repo_root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
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
            "Commit-based update checks require a git checkout of AutoPWN Suite; "
            "use --update-channel release instead."
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
        return (
            f"Update available ({status.mode}): {status.current} -> {status.latest}\n"
            f"{status.url}"
        )
    return f"Up to date ({status.mode}): {status.current} (latest: {status.latest})."
