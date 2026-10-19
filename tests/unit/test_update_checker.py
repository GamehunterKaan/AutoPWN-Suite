# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Release- and commit-based update checks, without touching the network."""
from unittest.mock import MagicMock

import pytest

from modules import update_checker as uc


def response(status_code=200, **json_body):
    resp = MagicMock(status_code=status_code, ok=status_code < 400)
    resp.json.return_value = json_body
    return resp


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
