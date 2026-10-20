# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The standalone Linux binary must not hand its bundled libraries to the system programs it starts."""
import sys
from unittest.mock import MagicMock, patch

import pytest

from autopwn_suite import nmap_progress, utils
from autopwn_suite.subprocess_env import child_environment

BUNDLE = "/tmp/_MEIabc123"


@pytest.fixture
def frozen_linux(monkeypatch):
    """What the PyInstaller bootloader leaves behind in a onefile binary on Linux."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("LD_LIBRARY_PATH", f"{BUNDLE}:/usr/local/lib")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/local/lib")
    monkeypatch.setenv("AUTOPWN_TEST_KEEP", "kept")


@pytest.mark.unit
class TestChildEnvironment:
    def test_a_normal_installation_inherits_the_environment(self, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/custom/lib")
        assert child_environment() is None

    @pytest.mark.parametrize("platform", ["win32", "darwin"])
    def test_other_platforms_inherit_the_environment(self, monkeypatch, platform):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", platform)
        assert child_environment() is None

    def test_the_original_library_path_is_given_back(self, frozen_linux):
        environment = child_environment()
        assert environment["LD_LIBRARY_PATH"] == "/usr/local/lib"
        assert BUNDLE not in environment["LD_LIBRARY_PATH"]
        assert environment["AUTOPWN_TEST_KEEP"] == "kept"

    @pytest.mark.parametrize("original", [None, ""])
    def test_without_an_original_value_the_variable_is_removed(self, frozen_linux, monkeypatch, original):
        if original is None:
            monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
        else:
            monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", original)  # an empty entry would mean the current directory
        monkeypatch.setenv("LD_LIBRARY_PATH", BUNDLE)

        assert "LD_LIBRARY_PATH" not in child_environment()

    def test_the_process_environment_itself_is_left_alone(self, frozen_linux):
        import os

        child_environment()

        assert os.environ["LD_LIBRARY_PATH"] == f"{BUNDLE}:/usr/local/lib"


def bundle_free(environment):
    return environment is not None and BUNDLE not in environment.get("LD_LIBRARY_PATH", "")


@pytest.mark.unit
class TestSystemProgramsGetTheOriginalEnvironment:
    def test_nmap_scan(self, frozen_linux):
        process = MagicMock(returncode=0)
        process.stdout.readline.return_value = b""
        process.stderr.readline.return_value = b""
        process.poll.return_value = 0
        scanner = MagicMock()
        scanner._nmap_path = "/usr/bin/nmap"

        with patch.object(nmap_progress.subprocess, "Popen", return_value=process) as spawn:
            nmap_progress.scan_with_progress(scanner, "192.0.2.1", "-sV")

        assert bundle_free(spawn.call_args.kwargs["env"])

    def test_nmap_scan_of_a_normal_installation_inherits(self, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        process = MagicMock(returncode=0)
        process.stdout.readline.return_value = b""
        process.stderr.readline.return_value = b""
        process.poll.return_value = 0
        scanner = MagicMock()
        scanner._nmap_path = "/usr/bin/nmap"

        with patch.object(nmap_progress.subprocess, "Popen", return_value=process) as spawn:
            nmap_progress.scan_with_progress(scanner, "192.0.2.1", "-sV")

        assert spawn.call_args.kwargs["env"] is None

    def test_nmap_presence_check(self, frozen_linux):
        with patch.object(utils, "check_call") as check:
            utils.check_nmap(MagicMock())

        assert check.call_args.args[0] == ["nmap", "-h"]
        assert bundle_free(check.call_args.kwargs["env"])

    def test_ip_address_lookup(self, frozen_linux):
        process = MagicMock()
        process.stdout.read.return_value = b"2: eth0    inet 192.0.2.7/24 brd 192.0.2.255 scope global eth0\n"
        with patch.object(utils, "Popen", return_value=process) as spawn, \
                patch.object(utils, "GetIpAdress", return_value="192.0.2.7"), \
                patch.object(utils, "system", return_value="linux"):
            assert utils.DetectIPRange() == "192.0.2.7/24"

        assert spawn.call_args.args[0][0] == "ip"
        assert bundle_free(spawn.call_args.kwargs["env"])
