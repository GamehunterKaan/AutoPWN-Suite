# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Release- and commit-based update checks, without touching the network."""
import io
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from autopwn_suite import __version__
from autopwn_suite import update_checker as uc


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
    # A clone does not inherit the upstream's identity, and a CI runner has no global one.
    _git(local, "config", "user.name", "Update Test")
    _git(local, "config", "user.email", "update@example.test")
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


def test_apply_release_update_never_moves_a_detached_head_back_to_an_older_tag(repos, monkeypatch):
    upstream, local = repos
    _git(upstream, "tag", "v2.7.0")
    _commit(local, "newer.txt", "a commit after the release")
    _git(local, "checkout", "--detach")
    newer = _git(local, "rev-parse", "HEAD").stdout.strip()
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name="v2.7.0"))

    result = uc.apply_release_update(repo="x/y")

    assert _git(local, "rev-parse", "HEAD").stdout.strip() == newer
    assert not result.changed
    assert "Already up to date" in uc.format_result(result)


def test_apply_release_update_refuses_a_detached_head_that_diverged_from_the_tag(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    _git(upstream, "tag", "v2.7.0")
    _commit(local, "local-only.txt", "diverging local commit")
    _git(local, "checkout", "--detach")
    detached = _git(local, "rev-parse", "HEAD").stdout.strip()
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name="v2.7.0"))

    with pytest.raises(uc.UpdateCheckError, match="diverged"):
        uc.apply_release_update(repo="x/y")
    assert _git(local, "rev-parse", "HEAD").stdout.strip() == detached


def test_apply_reports_already_up_to_date_when_nothing_moved(repos, monkeypatch):
    upstream, local = repos
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))

    result = uc.apply_update(channel="commit", branch="main", repo="x/y")

    assert not result.changed
    assert result.previous == result.new
    assert "Already up to date (commit)" in uc.format_result(result)
    assert "Restart" not in uc.format_result(result)


@pytest.mark.parametrize("name, changed", [
    ("requirements.txt", True), ("pyproject.toml", True), ("poetry.lock", True), ("requirements-locked.txt", True),
    ("README.md", False), ("autopwn_suite_module.py", False)])
def test_an_update_that_changes_dependencies_says_to_install_them_again(repos, monkeypatch, name, changed):
    upstream, local = repos
    _commit(upstream, name, "changed by the update")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))

    result = uc.apply_update(channel="commit", branch="main", repo="x/y")

    assert result.changed and result.dependencies_changed is changed
    assert ("install them again" in uc.format_result(result)) is changed


def test_a_dependency_diff_that_fails_counts_as_changed(monkeypatch):
    monkeypatch.setattr(uc, "_run_git", lambda *a, **k: SimpleNamespace(returncode=128, stdout=""))
    assert uc._dependencies_changed("a" * 40, "b" * 40)
    assert not uc._dependencies_changed("a" * 40, "a" * 40)


def test_commit_check_is_up_to_date_when_the_checkout_is_ahead_of_the_branch(repos, monkeypatch):
    upstream, local = repos
    remote_head = _git(upstream, "rev-parse", "HEAD").stdout.strip()
    _commit(local, "unpushed.txt", "a local commit the branch does not have yet")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(sha=remote_head))

    status = uc.check_commit(repo="x/y")

    assert not status.update_available
    assert "Up to date" in uc.format_status(status)


def test_commit_check_reports_a_branch_commit_the_checkout_does_not_have(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        sha=_git(upstream, "rev-parse", "HEAD").stdout.strip()))
    assert uc.check_commit(repo="x/y").update_available


@pytest.mark.parametrize("sha", ["--all", "HEAD", "main", "b" * 39, "B" * 40, "b" * 40 + "\n"])
def test_a_commit_id_that_is_not_hex_never_reaches_git(monkeypatch, sha):
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(uc, "_run_git", lambda *a, **k: pytest.fail("ran git with " + repr(sha)))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(sha=sha))
    assert uc.check_commit(repo="x/y").update_available


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


def test_resolve_update_channel_creates_a_missing_data_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path / "not" / "yet" / "created"))
    assert uc.resolve_update_channel("commit") == "commit"
    assert uc.resolve_update_channel(None) == "commit"


def test_resolve_update_channel_explicit_choice_overrides_a_saved_one(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    uc.resolve_update_channel("commit")
    assert uc.resolve_update_channel("release") == "release"
    assert uc.resolve_update_channel(None) == "release"


def test_a_copy_inside_another_repository_is_not_a_checkout(tmp_path, monkeypatch):
    """A venv under a dotfiles repository must not report or update that repository."""
    outer = _init_repo(tmp_path / "outer")
    installed = outer / "venv" / "site-packages"
    installed.mkdir(parents=True)
    monkeypatch.setattr(uc, "_repo_root", lambda: installed)
    monkeypatch.setattr(uc, "_fetch", lambda *a, **k: pytest.fail("fetched into an unrelated repository"))
    assert uc._local_commit() is None
    with pytest.raises(uc.UpdateCheckError, match="git checkout"):
        uc.check_commit(repo="x/y")
    with pytest.raises(uc.UpdateCheckError, match="git checkout"):
        uc.apply_update(channel="commit", repo="x/y")
    with pytest.raises(uc.UpdateCheckError, match="git checkout"):
        uc.apply_update(channel="release", repo="x/y")


def test_network_error_text_is_not_repeated(monkeypatch):
    def refuse(*a, **k):
        raise uc.requests.RequestException("proxy http://user:hunter2@proxy.test:3128 refused")
    monkeypatch.setattr(uc.requests, "get", refuse)
    with pytest.raises(uc.UpdateCheckError) as caught:
        uc.check_release("2.6.1", repo="x/y")
    assert "hunter2" not in str(caught.value)
    assert "RequestException" in str(caught.value)


def test_a_failed_fetch_reports_the_exit_status_not_git_output(repos, monkeypatch):
    upstream, local = repos
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream / "missing"))
    with pytest.raises(uc.UpdateCheckError, match=r"git fetch from x/y failed \(exit status \d+\)\.$") as caught:
        uc.apply_update(channel="commit", repo="x/y")
    assert "missing" not in str(caught.value)


@pytest.fixture
def session(monkeypatch, tmp_path):
    """``main()`` with a recording console and logger, and a data directory of its own."""
    import autopwn_suite.cli as cli
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    printed, logged = io.StringIO(), MagicMock()
    monkeypatch.setattr(cli, "Console", lambda **kwargs: Console(file=printed, width=200, **kwargs))
    monkeypatch.setattr(cli, "Logger", lambda console: logged)
    monkeypatch.setattr(cli, "StartScanning", lambda *a, **k: pytest.fail("an update command started a scan"))

    def run(*argv):
        monkeypatch.setattr("sys.argv", ["autopwn.py", "--no-color", *argv])
        cli.main()
        return printed.getvalue()

    return SimpleNamespace(run=run, logged=logged)


def test_check_update_prints_the_status_and_passes_the_options_through(monkeypatch, session):
    status = uc.UpdateStatus("commit", "x/y", "a" * 12, "b" * 12, "https://example.test/c", True)
    check = MagicMock(return_value=status)
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", check)
    printed = session.run("--check-update", "--update-channel", "commit", "--update-branch", "dev",
                          "--update-repo", "x/y")
    assert "Update available (commit)" in printed
    assert "b" * 12 in printed
    check.assert_called_once_with(__version__, channel="commit", branch="dev", repo="x/y")
    assert uc.resolve_update_channel(None) == "commit"


def test_apply_update_prints_the_result_and_wins_over_check_update(monkeypatch, session):
    result = uc.UpdateResult("release", "x/y", "a" * 12, "b" * 12, "v9.9.9")
    apply = MagicMock(return_value=result)
    monkeypatch.setattr("autopwn_suite.cli.apply_update", apply)
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", lambda *a, **k: pytest.fail("checked instead"))
    printed = session.run("--check-update", "--apply-update")
    assert "Updated (release)" in printed
    apply.assert_called_once_with(channel="release", branch="main", repo=None)


def test_an_update_error_exits_with_status_one_and_logs_cleaned_text(monkeypatch, session):
    error = uc.UpdateCheckError("Nothing found at v1\x1b[31m\nforged line")
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", MagicMock(side_effect=error))
    with pytest.raises(SystemExit) as caught:
        session.run("--check-update")
    assert caught.value.code == 1
    (level, text), _ = session.logged.logger.call_args
    assert level == "error"
    assert "\x1b" not in text
    assert "\n" not in text


def test_text_from_github_cannot_drive_the_terminal(monkeypatch, session):
    status = uc.UpdateStatus("release", "x/y", "2.7.0", "v9\x1b[2J[bold red]x[/]\nforged",
                             "https://example.test/\x1b]0;t\x07", True)
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", MagicMock(return_value=status))
    printed = session.run("--check-update")
    assert "\x1b" not in printed
    assert "\x07" not in printed
    assert "[bold red]" in printed  # shown as text, not applied as markup
    lines = printed.splitlines()
    assert len(lines) == 2 and "forged" in lines[0]  # the status, with no line of its own for the forged text
    assert lines[1] == uc.update_hint(uc.install_method())  # and how to apply the update


@pytest.mark.parametrize("repo", ["x/y", "GamehunterKaan/AutoPWN-Suite", "a.b/c_d-e", "x/y.js", "x" * 100 + "/" + "y" * 100])
def test_plain_repository_names_are_accepted(repo):
    assert uc._checked_repo(repo) == repo


@pytest.mark.parametrize("repo", [
    "x", "x/y/z", "/y", "x/", "../y", "x/..", "./y", "x/.", "x y/z", "x/y\n", "x/y?z=1", "x/y#f", "x@evil.test/y",
    "x/y:z", "x/\u00e9", "x" * 101 + "/y", 5, ["x/y"], b"x/y"])
def test_other_repository_names_are_refused(repo):
    with pytest.raises(uc.UpdateCheckError, match="OWNER/REPO"):
        uc._checked_repo(repo)


@pytest.mark.parametrize("name", ["main", "v2.7.0", "v1.0.0+build.5", "release/2.7", "feature/a_b-c.d", "1.0", "a" * 255])
def test_plain_branch_and_tag_names_are_accepted(name):
    assert uc._checked_ref(name, "branch") == name


@pytest.mark.parametrize("name", [
    "", "-main", "--upload-pack=x", "--abort", "-", "main:refs/heads/other", "a..b", "a//b", "a/", "a.", "a.lock",
    "a.lock/b", "a/.hidden", ".hidden", "a b", "a\n", "a~1", "a^", "a*", "a?", "a[", "a\\b", "a@{u}", "\u00e9",
    "a" * 256, None, 5, ["main"]])
def test_other_branch_and_tag_names_are_refused(name):
    with pytest.raises(uc.UpdateCheckError, match="not a plain git name"):
        uc._checked_ref(name, "branch")


REFUSED_CALLS = {
    "release check, path-like repository": lambda: uc.check_release("2.7.0", repo="../y"),
    "commit check, option-like branch": lambda: uc.check_commit(branch="--abort", repo="x/y"),
    "commit check, bad repository": lambda: uc.check_commit(repo="x/y/z"),
    "commit apply, option-like branch": lambda: uc.apply_update(channel="commit", branch="--upload-pack=x", repo="x/y"),
    "commit apply, refspec as branch": lambda: uc.apply_update(channel="commit", branch="main:refs/heads/other", repo="x/y"),
    "release apply, bad repository": lambda: uc.apply_update(channel="release", repo="x@evil.test/y"),
}


@pytest.mark.parametrize("call", REFUSED_CALLS.values(), ids=REFUSED_CALLS)
def test_refused_names_reach_neither_the_network_nor_git(monkeypatch, call):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: pytest.fail("contacted GitHub"))
    monkeypatch.setattr(uc, "_run_git", lambda *a, **k: pytest.fail("ran git"))
    monkeypatch.setattr(uc, "_local_commit", lambda: pytest.fail("looked at the checkout"))
    with pytest.raises(uc.UpdateCheckError, match="OWNER/REPO|plain git name"):
        call()


@pytest.mark.parametrize("tag", ["--abort", "-f", "v1:refs/heads/main", "v1..v2", "v1\nx", "v1 x"])
def test_a_hostile_release_tag_never_reaches_git(monkeypatch, tag):
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(uc, "_ensure_clean_worktree", lambda: None)
    monkeypatch.setattr(uc, "_run_git", lambda *a, **k: pytest.fail("ran git with a hostile tag"))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name=tag))
    with pytest.raises(uc.UpdateCheckError, match="not a plain git name"):
        uc.apply_update(channel="release", repo="x/y")


@pytest.mark.parametrize("tag", [7, ["v1"], None])
def test_a_release_tag_that_is_not_text_counts_as_missing(monkeypatch, tag):
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    monkeypatch.setattr(uc, "_ensure_clean_worktree", lambda: None)
    monkeypatch.setattr(uc, "_run_git", lambda *a, **k: pytest.fail("ran git"))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name=tag))
    with pytest.raises(uc.UpdateCheckError, match="no tag name"):
        uc.apply_update(channel="release", repo="x/y")


@pytest.mark.parametrize("body", [["v1"], "v1", 7, None])
def test_a_response_that_is_not_an_object_is_an_unexpected_response(monkeypatch, body):
    reply = MagicMock(status_code=200, ok=True)
    reply.json.return_value = body
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: reply)
    with pytest.raises(uc.UpdateCheckError, match="unexpected response"):
        uc.check_release("2.7.0", repo="x/y")


def test_json_nested_beyond_the_recursion_limit_is_an_unexpected_response(monkeypatch):
    reply = MagicMock(status_code=200, ok=True)
    reply.json.side_effect = RecursionError()
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: reply)
    with pytest.raises(uc.UpdateCheckError, match="unexpected response"):
        uc.check_release("2.7.0", repo="x/y")


def test_fields_of_the_wrong_type_count_as_missing(monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name=7, html_url=["x"]))
    status = uc.check_release("2.7.0", repo="x/y")
    assert (status.latest, status.url) == ("", "https://github.com/x/y/releases")
    assert not status.update_available


def test_a_tag_of_thousands_of_digits_is_compared_without_error(monkeypatch):
    # int() refuses more than 4300 digits on Python 3.11 and later; a tag is text that the repository's publisher chooses.
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name="9" * 5000))
    assert uc.check_release("2.7.0", repo="x/y").update_available


def test_a_detached_release_update_checks_out_the_tag_not_a_branch_of_the_same_name(repos, monkeypatch):
    upstream, local = repos
    old = _git(local, "rev-parse", "HEAD").stdout.strip()
    _commit(upstream, "two.txt", "two")
    _git(upstream, "tag", "v2.7.0")
    _git(local, "branch", "v2.7.0", old)  # a local branch named like the release, at an older commit
    _git(local, "checkout", "--detach")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(tag_name="v2.7.0"))

    result = uc.apply_release_update(repo="x/y")

    assert _git(local, "rev-parse", "HEAD").stdout.strip() == _git(upstream, "rev-parse", "v2.7.0").stdout.strip()
    assert uc._current_branch() is None
    assert result.changed


def test_a_merge_blocked_by_a_lock_file_is_a_git_failure_not_a_divergence(repos, monkeypatch):
    upstream, local = repos
    _commit(upstream, "two.txt", "two")
    (local / ".git" / "index.lock").write_text("")
    monkeypatch.setattr(uc, "_repo_root", lambda: local)
    monkeypatch.setattr(uc, "_remote_url", lambda repo: str(upstream))
    with pytest.raises(uc.UpdateCheckError, match="index.lock") as caught:
        uc.apply_update(channel="commit", branch="main", repo="x/y")
    assert caught.value.code == "update_git_failed"


def test_output_git_prints_that_the_locale_cannot_decode_means_no_checkout(monkeypatch):
    def undecodable(*a, **k):
        raise UnicodeDecodeError("cp1252", b"\x81", 0, 1, "character maps to <undefined>")
    monkeypatch.setattr(uc.subprocess, "run", undecodable)
    assert uc.current_commit() is None


# ── Installations other than a git checkout ──


@pytest.fixture
def installed(monkeypatch, tmp_path):
    """A copy that is not a git checkout, in a virtual environment at tmp_path that this account may change."""
    monkeypatch.setattr(uc, "_local_commit", lambda: None)
    monkeypatch.setattr(uc, "_DOCKER_MARKER", tmp_path / "no-dockerenv")
    monkeypatch.delattr(uc.sys, "frozen", raising=False)
    monkeypatch.setattr(uc.sys, "prefix", str(tmp_path))
    monkeypatch.setattr(uc.sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(uc, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(uc.shutil, "which", lambda name: f"/tools/{name}")
    monkeypatch.setattr(uc, "_FILES_LOCKED_WHILE_RUNNING", False)  # as on Linux and macOS
    return tmp_path


@pytest.mark.parametrize("marker, method", [("pipx_metadata.json", "pipx"), ("uv-receipt.toml", "uv")])
def test_a_pipx_or_uv_tool_environment_is_recognized(installed, marker, method):
    (installed / marker).write_text("{}")
    assert uc.install_method() == method


def test_a_virtual_environment_holding_the_package_is_a_pip_installation(installed, monkeypatch):
    monkeypatch.setattr(uc, "_installed_in", lambda prefix: True)
    assert uc.install_method() == "pip"
    monkeypatch.setattr(uc, "_installed_in", lambda prefix: False)  # a copy run from a folder
    assert uc.install_method() == "other"
    monkeypatch.setattr(uc, "_installed_in", lambda prefix: True)
    monkeypatch.setattr(uc.sys, "base_prefix", str(installed))  # the system Python, not a virtual environment
    assert uc.install_method() == "other"


def test_a_binary_a_container_and_a_checkout_are_recognized_first(installed, monkeypatch):
    (installed / "pipx_metadata.json").write_text("{}")
    marker = installed / ".dockerenv"
    marker.write_text("")
    monkeypatch.setattr(uc, "_DOCKER_MARKER", marker)
    assert uc.install_method() == "docker"
    monkeypatch.setattr(uc, "_local_commit", lambda: "a" * 40)
    assert uc.install_method() == "checkout"
    monkeypatch.setattr(uc.sys, "frozen", True, raising=False)
    assert uc.install_method() == "binary"


def test_only_this_package_installed_in_the_environment_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(uc.metadata, "distribution", lambda name: object())
    assert uc._installed_in(uc.Path(uc.__file__).parent.parent) is True
    assert uc._installed_in(tmp_path) is False

    def missing(name):
        raise uc.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(uc.metadata, "distribution", missing)
    assert uc._installed_in(uc.Path(uc.__file__).parent.parent) is False


@pytest.mark.parametrize("method, tool, writable, expected", [
    ("checkout", None, False, True), ("pip", None, True, True), ("pip", None, False, False),
    ("pipx", "/tools/pipx", True, True), ("pipx", None, True, False), ("uv", "/tools/uv", False, False),
    ("binary", "/tools/x", True, False), ("docker", "/tools/x", True, False), ("other", "/tools/x", True, False)])
def test_only_a_checkout_or_a_package_installation_this_account_may_change_applies(
        installed, monkeypatch, method, tool, writable, expected):
    monkeypatch.setattr(uc.shutil, "which", lambda name: tool)
    monkeypatch.setattr(uc.os, "access", lambda path, mode: writable)
    assert uc.can_apply(method) is expected


def test_each_installation_is_told_how_to_update(installed, monkeypatch):
    assert uc.update_command("pipx") == "pipx upgrade autopwn-suite"
    assert uc.update_command("uv") == "uv tool upgrade autopwn-suite"
    assert uc.update_command("docker") == "docker compose pull && docker compose up -d"
    assert uc.update_command("binary") == "https://github.com/GamehunterKaan/AutoPWN-Suite/releases/latest"
    assert uc.update_command("pip") == "autopwn-suite --apply-update"
    assert uc.update_command("other") is None
    assert uc.update_hint("pipx") == "Run --apply-update to install it."
    assert "releases/latest" in uc.update_hint("binary") and "docker compose pull" in uc.update_hint("docker")
    monkeypatch.setattr(uc.os, "access", lambda path, mode: False)  # install.sh's root-owned environment
    assert uc.update_command("pip") == "sudo autopwn-suite --apply-update"
    assert uc.update_hint("pip") == "Update it with: sudo autopwn-suite --apply-update"


def _release_tag(monkeypatch, tag="v9.9.9"):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: response(
        tag_name=tag, html_url="https://github.com/GamehunterKaan/AutoPWN-Suite/releases/tag/" + str(tag)))


def _installer(monkeypatch, returncode=0, versions=("2.8.0", "9.9.9")):
    """Record what would run, and have the installed version change once it has run."""
    runs = []
    state = {"version": versions[0]}

    def run(argv, **kwargs):
        runs.append((argv, kwargs))
        if returncode == 0:
            state["version"] = versions[1]
        return SimpleNamespace(returncode=returncode, stdout="secret output", stderr="secret error")
    monkeypatch.setattr(uc.subprocess, "run", run)
    monkeypatch.setattr(uc, "installed_version", lambda: state["version"])
    return runs


@pytest.mark.parametrize("method, argv", [
    ("pip", [uc.sys.executable, "-m", "pip", "install", "--upgrade", "--only-binary=:all:", "--no-input",
             "--disable-pip-version-check", "autopwn-suite==9.9.9"]),
    ("pipx", ["/tools/pipx", "upgrade", "autopwn-suite", "--pip-args=--only-binary=:all:"]),
    ("uv", ["/tools/uv", "tool", "upgrade", "autopwn-suite", "--no-build"])])
def test_a_package_installation_updates_from_pypi_with_wheels_only(installed, monkeypatch, method, argv):
    _release_tag(monkeypatch)
    runs = _installer(monkeypatch)
    result = uc.apply_package_update(method)
    assert [run[0] for run in runs] == [argv]
    assert runs[0][1]["timeout"] and runs[0][1]["check"] is False and "shell" not in runs[0][1]
    assert (result.mode, result.previous, result.new, result.ref, result.changed) == (
        "release", "2.8.0", "9.9.9", "v9.9.9", True)
    assert "Restart AutoPWN Suite" in uc.format_result(result)


def test_apply_update_sends_a_package_installation_to_its_package_manager(installed, monkeypatch):
    (installed / "uv-receipt.toml").write_text("")
    monkeypatch.setattr(uc, "apply_package_update", lambda method, repo=None: (method, repo))
    monkeypatch.setattr(uc, "apply_release_update", lambda *a, **k: pytest.fail("ran git"))
    assert uc.apply_update(repo="GamehunterKaan/AutoPWN-Suite") == ("uv", "GamehunterKaan/AutoPWN-Suite")


def test_a_package_installation_never_moves_back(installed, monkeypatch):
    _release_tag(monkeypatch, "v2.8.0")
    runs = _installer(monkeypatch, versions=("2.8.1", "2.8.0"))
    result = uc.apply_package_update("pip")
    assert not runs and not result.changed and uc.format_result(result).startswith("Already up to date")


@pytest.mark.parametrize("tag", ["v9.9.9 --index-url=https://evil.test", "--index-url=x", "9.9.9;x", "v9", "", None,
                                 "v1.2.3.4.5", "v1.2.3rc1", "v" + "9" * 7 + ".0"])
def test_a_release_tag_that_is_not_a_plain_version_reaches_no_package_manager(installed, monkeypatch, tag):
    _release_tag(monkeypatch, tag)
    runs = _installer(monkeypatch)
    with pytest.raises(uc.UpdateCheckError) as caught:
        uc.apply_package_update("pip")
    assert caught.value.code == "update_bad_response" and not runs


def test_a_failed_package_update_reports_the_exit_status_not_the_output(installed, monkeypatch):
    _release_tag(monkeypatch)
    _installer(monkeypatch, returncode=2)
    with pytest.raises(uc.UpdateCheckError, match=r"pip could not update AutoPWN Suite \(exit status 2\)\.$") as caught:
        uc.apply_package_update("pip")
    assert caught.value.code == "update_install_failed" and "secret" not in str(caught.value)


def test_a_package_manager_that_cannot_run_is_reported(installed, monkeypatch):
    _release_tag(monkeypatch)
    monkeypatch.setattr(uc, "installed_version", lambda: "2.8.0")

    def cannot_run(*a, **k):
        raise OSError("no such file /secret/path")
    monkeypatch.setattr(uc.subprocess, "run", cannot_run)
    with pytest.raises(uc.UpdateCheckError) as caught:
        uc.apply_package_update("pip")
    assert caught.value.code == "update_install_failed" and "secret" not in str(caught.value)


def test_a_missing_pipx_or_uv_is_reported_with_its_command(installed, monkeypatch):
    _release_tag(monkeypatch)
    runs = _installer(monkeypatch)
    monkeypatch.setattr(uc.shutil, "which", lambda name: None)
    with pytest.raises(uc.UpdateCheckError, match="pipx upgrade autopwn-suite") as caught:
        uc.apply_package_update("pipx")
    assert caught.value.code == "update_tool_missing" and not runs


def test_a_package_installation_follows_only_the_upstream_releases(installed, monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: pytest.fail("contacted GitHub"))
    runs = _installer(monkeypatch)
    with pytest.raises(uc.UpdateCheckError) as caught:
        uc.apply_package_update("pip", repo="someone/fork")
    assert caught.value.code == "update_repo_not_pypi" and not runs


def test_an_installation_of_another_account_needs_sudo(installed, monkeypatch):
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: pytest.fail("contacted GitHub"))
    monkeypatch.setattr(uc.os, "access", lambda path, mode: False)
    runs = _installer(monkeypatch)
    with pytest.raises(uc.UpdateCheckError, match="sudo autopwn-suite --apply-update") as caught:
        uc.apply_package_update("pip")
    assert caught.value.code == "update_needs_root" and not runs


@pytest.mark.parametrize("marker, code, text", [
    (None, "update_binary", "releases/latest"), (".dockerenv", "update_docker", "docker compose pull"),
    ("", "update_not_checkout", "git checkout")])
def test_an_installation_that_cannot_update_itself_says_how_to(installed, monkeypatch, marker, code, text):
    if marker is None:
        monkeypatch.setattr(uc.sys, "frozen", True, raising=False)
    elif marker:
        (installed / marker).write_text("")
        monkeypatch.setattr(uc, "_DOCKER_MARKER", installed / marker)
    monkeypatch.setattr(uc.subprocess, "run", lambda *a, **k: pytest.fail("ran a command"))
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: pytest.fail("contacted GitHub"))
    with pytest.raises(uc.UpdateCheckError, match=text) as caught:
        uc.apply_update(repo="GamehunterKaan/AutoPWN-Suite")
    assert caught.value.code == code


def test_check_update_says_how_to_apply_an_available_update(monkeypatch, session):
    status = uc.UpdateStatus("release", "x/y", "2.8.0", "v9.9.9", "https://example.test/r", True)
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", MagicMock(return_value=status))
    monkeypatch.setattr("autopwn_suite.cli.install_method", lambda: "docker")
    printed = session.run("--check-update")
    assert "docker compose pull && docker compose up -d" in printed


def test_check_update_prints_no_hint_when_nothing_is_newer(monkeypatch, session):
    status = uc.UpdateStatus("release", "x/y", "9.9.9", "v9.9.9", "https://example.test/r", False)
    monkeypatch.setattr("autopwn_suite.cli.check_for_updates", MagicMock(return_value=status))
    monkeypatch.setattr("autopwn_suite.cli.install_method", lambda: pytest.fail("looked at the installation"))
    assert session.run("--check-update").count("\n") == 1


def test_on_windows_a_package_installation_is_updated_after_autopwn_suite_exits(installed, monkeypatch):
    """Windows locks the running autopwn-suite.exe: pipx upgrade failed halfway with the dashboard running and left
    the environment without the package."""
    monkeypatch.setattr(uc, "_FILES_LOCKED_WHILE_RUNNING", True)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: pytest.fail("contacted GitHub"))
    runs = _installer(monkeypatch)
    for method in uc.PACKAGE_MANAGERS:
        assert uc.can_apply(method) is False
        with pytest.raises(uc.UpdateCheckError, match="close AutoPWN Suite") as caught:
            uc.apply_package_update(method)
        assert caught.value.code == "update_windows" and not runs
    assert uc.can_apply("checkout") is True
    assert uc.update_command("pip") == f'"{uc.sys.executable}" -m pip install --upgrade autopwn-suite'
    assert uc.update_hint("pipx") == "Close AutoPWN Suite, then update it with: pipx upgrade autopwn-suite"
