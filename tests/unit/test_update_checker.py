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
    assert printed.count("\n") == 1  # no line of its own for the forged text


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
