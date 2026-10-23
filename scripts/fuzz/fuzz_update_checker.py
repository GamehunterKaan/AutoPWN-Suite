# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Coverage-guided fuzzing of the update checker's input checks: the repository, branch and tag names, and the
JSON that GitHub returns."""
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

import atheris

with atheris.instrument_imports():
    from autopwn_suite import update_checker


def TestOneInput(data):
    provider = atheris.FuzzedDataProvider(data)
    mode = provider.ConsumeIntInRange(0, 2)
    text = provider.ConsumeUnicodeNoSurrogates(len(data))
    try:
        if mode == 0:
            repo = update_checker._checked_repo(text)
            assert repo.count("/") == 1 and ".." not in repo.split("/")
        elif mode == 1:
            name = update_checker._checked_ref(text, "branch")
            assert not name.startswith("-") and ".." not in name and "//" not in name
        else:
            try:
                body = json.loads(text)
            except (ValueError, RecursionError):
                return  # not JSON (or nested too deeply for Python 3.10 and 3.11), so it never reaches the checker
            reply = SimpleNamespace(status_code=200, ok=True, json=lambda: body)
            with patch.object(update_checker.requests, "get", lambda *args, **kwargs: reply):
                status = update_checker.check_release("2.7.0", repo="x/y")
            assert isinstance(status.latest, str) and isinstance(status.url, str)
            assert isinstance(status.update_available, bool)
            # The commit ID that GitHub names reaches git only as a full hexadecimal object name.
            ran = []
            with patch.object(update_checker.requests, "get", lambda *args, **kwargs: reply), \
                    patch.object(update_checker, "_local_commit", lambda: "a" * 40), \
                    patch.object(update_checker, "_run_git",
                                 lambda args, check=True: ran.append(args) or SimpleNamespace(returncode=1)):
                status = update_checker.check_commit(repo="x/y")
            assert isinstance(status.update_available, bool)
            for args in ran:
                assert args[:2] == ["merge-base", "--is-ancestor"] and update_checker._COMMIT_ID.fullmatch(args[2])
    except update_checker.UpdateCheckError:
        return  # the documented rejection


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
