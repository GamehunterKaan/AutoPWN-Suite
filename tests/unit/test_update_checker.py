# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Release- and commit-based update checks, without touching the network."""
import subprocess
from unittest.mock import MagicMock

import pytest

from modules import update_checker as uc


def response(status_code=200, **json_body):
    resp = MagicMock(status_code=status_code, ok=status_code < 400)
    resp.json.return_value = json_body
    return resp


def _git(repo, *args, check=True):
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=check
    )


def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Update Test")
    _git(path, "config", "user.email", "update@example.test")
    (path / "file.txt").write_text("one")
    _git(path, "add", ".")
    _git(path, "-c", "commit.gpgsign=false", "commit", "-m", "init")
    return path


def _commit(repo, name, content):
    (repo / name).write_text(content)
    _git(repo, "add", ".")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-m", f"add {name}")


@pytest.fixture
def repos(tmp_path):
    """An ``upstream`` repo and a ``local`` clone of it, as apply_update would see them."""
    upstream = _init_repo(tmp_path / "upstream")
    local = tmp_path / "local"
    subprocess.run(["git", "clone", str(upstream), str(local)], check=True, capture_output=True, text=True)
    return upstream, local


def test_release_reports_update_available(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name="v2.7.0", html_url="https://github.com/x/y/releases/tag/v2.7.0"))
    status = uc.check_release("2.6.1", repo="x/y")
    assert status.update_available
    assert status.latest == "v2.7.0"
    assert "Update available" in uc.format_status(status)


def test_release_reports_up_to_date(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name="v2.6.1", html_url="https://github.com/x/y/releases/tag/v2.6.1"))
    status = uc.check_release("2.6.1", repo="x/y")
    assert not status.update_available
    assert "Up to date" in uc.format_status(status)


def test_release_ignores_leading_v_and_trailing_noise(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name="AutoPWN-Suite-v2.10.0", html_url="https://github.com/x/y/releases/tag/v2.10.0"))
    status = uc.check_release("2.9.9", repo="x/y")
    assert status.update_available


def test_check_for_updates_dispatches_to_release_by_default(monkeypatch):
    monkeypatch.setattr(uc, "check_release", lambda *a, **k: "release-called")
    monkeypatch.setattr(uc, "check_commit", lambda *a, **k: pytest.fail("commit path used"))
    assert uc.check_for_updates("2.6.1") == "release-called"


def test_check_for_updates_dispatches_to_commit(monkeypatch):
    monkeypatch.setattr(uc, "check_commit", lambda *a, **k: "commit-called")
    monkeypatch.setattr(uc, "check_release", lambda *a, **k: pytest.fail("release path used"))
    assert uc.check_for_updates("2.6.1", channel="commit") == "commit-called"


def test_commit_requires_a_git_checkout(monkeypatch):
    monkeypatch.setattr(uc, "_local_commit", lambda: None)
    with pytest.raises(uc.UpdateCheckError, match="git checkout"):
        uc.check_commit(repo="x/y")


def test_commit_reports_update_available(monkeypatch):
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        sha="b" * 40, html_url="https://github.com/x/y/commit/b"))
    status = uc.check_commit(repo="x/y")
    assert status.update_available
    assert status.current == "a" * 12
    assert status.latest == "b" * 12


def test_commit_reports_up_to_date_when_sha_matches(monkeypatch):
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        sha="a" * 40, html_url="https://github.com/x/y/commit/a"))
    status = uc.check_commit(repo="x/y")
    assert not status.update_available


def test_network_failure_raises_update_check_error(monkeypatch):
    def raise_connection_error(*a, **k):
        raise uc.requests.RequestException("boom")
    monkeypatch.setattr(uc.requests, "get", raise_connection_error)
    with pytest.raises(uc.UpdateCheckError, match="Could not reach GitHub"):
        uc.check_release("2.6.1", repo="x/y")


def test_rate_limit_raises_update_check_error(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(status_code=403))
    with pytest.raises(uc.UpdateCheckError, match="rate limit"):
        uc.check_release("2.6.1", repo="x/y")


def test_missing_repo_or_release_raises_update_check_error(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(status_code=404))
    with pytest.raises(uc.UpdateCheckError):
        uc.check_release("2.6.1", repo="x/y")


def test_apply_commit_update_fast_forwards_local_branch(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    previous = uc._local_commit()

    result = uc.apply_update(channel="commit", branch="main", repo="x/y")

    assert result.mode == "commit"
    assert result.previous == previous[:12]
    assert result.new == uc._local_commit()[:12]
    assert previous != uc._local_commit()
    assert "Restart AutoPWN Suite" in uc.format_result(result)


def test_apply_commit_update_refuses_dirty_worktree(repos, monkeypatch):
    upstream, local = repos
    (local / "file.txt").write_text("dirty, uncommitted")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    with pytest.raises(uc.UpdateCheckError, match="uncommitted changes"):
        uc.apply_commit_update(branch="main", repo="x/y")


def test_apply_commit_update_refuses_detached_head(repos, monkeypatch):
    upstream, local = repos
    sha = _git(local, "rev-parse", "HEAD").stdout.strip()
    _git(local, "checkout", sha)
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    with pytest.raises(uc.UpdateCheckError, match="detached"):
        uc.apply_commit_update(branch="main", repo="x/y")


def test_apply_commit_update_refuses_diverged_branch(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two on upstream")
    _commit(local, "local-only.txt", "diverging local commit")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    with pytest.raises(uc.UpdateCheckError, match="diverged"):
        uc.apply_commit_update(branch="main", repo="x/y")


def test_apply_commit_update_requires_a_git_checkout(monkeypatch):
    monkeypatch.setattr(uc, "_local_commit", lambda: None)
    with pytest.raises(uc.UpdateCheckError, match="git checkout"):
        uc.apply_commit_update(repo="x/y")


def test_apply_release_update_checks_out_tag_on_branch(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    _git(upstream, "tag", "v2.7.0")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name="v2.7.0", html_url="https://github.com/x/y/releases/tag/v2.7.0"))

    result = uc.apply_update(channel="release", repo="x/y")

    assert result.mode == "release" and result.ref == "v2.7.0"
    assert uc._current_branch() == "main"


def test_apply_release_update_checks_out_tag_when_detached(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    _git(upstream, "tag", "v3.0.0")
    sha = _git(local, "rev-parse", "HEAD").stdout.strip()
    _git(local, "checkout", sha)
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name="v3.0.0", html_url="https://github.com/x/y/releases/tag/v3.0.0"))

    result = uc.apply_release_update(repo="x/y")

    assert result.ref == "v3.0.0"
    assert uc._current_branch() is None


def test_apply_release_update_requires_tag_name(repos, monkeypatch):
    _upstream, local = repos
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name=None, html_url="https://github.com/x/y/releases"))
    with pytest.raises(uc.UpdateCheckError, match="no tag name"):
        uc.apply_release_update(repo="x/y")


def test_apply_update_dispatches_to_release_by_default(monkeypatch):
    monkeypatch.setattr(uc, "apply_release_update", lambda *a, **k: "release-called")
    monkeypatch.setattr(uc, "apply_commit_update", lambda *a, **k: pytest.fail("commit path used"))
    assert uc.apply_update() == "release-called"


def test_apply_update_dispatches_to_commit(monkeypatch):
    monkeypatch.setattr(uc, "apply_commit_update", lambda *a, **k: "commit-called")
    monkeypatch.setattr(uc, "apply_release_update", lambda *a, **k: pytest.fail("release path used"))
    assert uc.apply_update(channel="commit") == "commit-called"


def test_resolve_update_channel_defaults_to_release_when_nothing_saved(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    assert uc.resolve_update_channel(None) == "release"


def test_resolve_update_channel_remembers_an_explicit_choice(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    assert uc.resolve_update_channel("commit") == "commit"
    assert uc.resolve_update_channel(None) == "commit"


def test_resolve_update_channel_explicit_choice_overrides_a_saved_one(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    uc.resolve_update_channel("commit")
    assert uc.resolve_update_channel("release") == "release"
    assert uc.resolve_update_channel(None) == "release"
