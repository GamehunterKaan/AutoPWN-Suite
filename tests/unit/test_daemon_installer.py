# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""
Unit tests for the daemon installer in autopwn_suite/daemon/daemon_installer.py.
"""
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
from configparser import ConfigParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from autopwn_suite.daemon import daemon_installer
from autopwn_suite.daemon.daemon_installer import (
    CopyFiles,
    CreateConfig,
    InstallDaemon,
    UninstallDaemon,
    _exec_start,
    _get_menu_choice,
    _get_non_empty_input,
    _get_validated_email,
    _get_validated_int,
)
from autopwn_suite.utils import InitArgsConf


@pytest.fixture
def mock_console():
    """Fixture for a mocked Rich Console."""
    console = MagicMock()
    console.input = MagicMock()
    console.print = MagicMock()
    return console


@pytest.mark.unit
class TestDaemonHelpers:
    """Tests for the interactive helper functions."""

    def test_get_menu_choice_valid(self, mock_console):
        """Verify a valid choice is returned."""
        mock_console.input.return_value = "1"
        options = {"1": "Option 1", "2": "Option 2"}
        result = _get_menu_choice(mock_console, "Prompt", options)
        assert result == "1"

    def test_get_menu_choice_invalid_then_valid(self, mock_console):
        """Verify it re-prompts after an invalid choice."""
        mock_console.input.side_effect = ["3", "2"]
        options = {"1": "Option 1", "2": "Option 2"}
        result = _get_menu_choice(mock_console, "Prompt", options)
        assert result == "2"
        mock_console.print.assert_any_call(
            "[red]Invalid choice. Please enter one of ['1', '2'].[/red]"
        )

    def test_get_menu_choice_accepts_any_letter_case_like_the_config_loader(self, mock_console):
        """The loader lowercases the output type, so 'HTML' or ' Txt ' must not be rejected by the wizard."""
        options = {"html": "HTML report", "txt": "Plain text"}
        for typed, expected in (("HTML", "html"), (" Txt ", "txt")):
            mock_console.input.return_value = typed
            assert _get_menu_choice(mock_console, "Prompt", options) == expected

    def test_get_menu_choice_default(self, mock_console):
        """Verify the default value is returned on empty input."""
        mock_console.input.return_value = ""
        options = {"1": "Option 1", "2": "Option 2"}
        result = _get_menu_choice(mock_console, "Prompt", options, default="2")
        assert result == "2"

    def test_get_validated_int_valid(self, mock_console):
        """Verify a valid integer is returned."""
        mock_console.input.return_value = "123"
        result = _get_validated_int(mock_console, "Prompt")
        assert result == 123

    def test_get_validated_int_invalid_then_valid(self, mock_console):
        """Verify it re-prompts after invalid integer input."""
        mock_console.input.side_effect = ["abc", "456"]
        result = _get_validated_int(mock_console, "Prompt")
        assert result == 456
        mock_console.print.assert_called_with(
            "[red]Invalid input. Please enter a whole number.[/red]"
        )

    @pytest.mark.parametrize("minimum, maximum, rejected, accepted", [
        (0, 5, ["-1", "6", "99"], "0"),
        (0, 5, ["6"], "5"),
        (1, 65535, ["0", "65536", "-1"], "1"),
        (1, 65535, ["65536"], "65535"),
        (0, None, ["-1", "-3600"], "0"),
    ])
    def test_get_validated_int_re_prompts_outside_its_bounds(self, mock_console, minimum, maximum, rejected, accepted):
        mock_console.input.side_effect = [*rejected, accepted]
        assert _get_validated_int(mock_console, "Prompt", minimum=minimum, maximum=maximum) == int(accepted)
        assert mock_console.input.call_count == len(rejected) + 1
        assert any("Out of range" in str(c) for c in mock_console.print.call_args_list)

    def test_get_validated_int_default_is_returned_without_a_range_check(self, mock_console):
        mock_console.input.return_value = ""
        assert _get_validated_int(mock_console, "Prompt", default=3, minimum=0, maximum=5) == 3

    def test_get_validated_email_valid(self, mock_console):
        """Verify a valid email is returned."""
        mock_console.input.return_value = "test@example.com"
        result = _get_validated_email(mock_console, "Prompt")
        assert result == "test@example.com"

    def test_get_validated_email_invalid_then_valid(self, mock_console):
        """Verify it re-prompts after an invalid email."""
        mock_console.input.side_effect = ["not-an-email", "test@example.com"]
        result = _get_validated_email(mock_console, "Prompt")
        assert result == "test@example.com"
        mock_console.print.assert_called_with(
            "[red]Invalid email format. Please enter a valid email address.[/red]"
        )

    def test_get_non_empty_input(self, mock_console):
        """Verify it re-prompts if the input is empty."""
        mock_console.input.side_effect = ["", "  ", "some value"]
        result = _get_non_empty_input(mock_console, "Prompt")
        assert result == "some value"
        assert mock_console.print.call_count == 2
        mock_console.print.assert_called_with("[red]This field cannot be empty.[/red]")


@pytest.mark.unit
class TestCreateConfig:
    """Tests for the CreateConfig function."""

    @patch("autopwn_suite.daemon.daemon_installer.open", new_callable=MagicMock)
    @patch("autopwn_suite.daemon.daemon_installer.ConfigParser")
    @patch("autopwn_suite.daemon.daemon_installer._write_config")
    def test_create_config_webhook_flow(self, mock_write_config, mock_config_parser, mock_open, mock_console):
        """Verify config creation with webhook notification."""
        # Simulate user inputs for a full config creation
        mock_console.input.side_effect = [
            "3600",  # scan_interval
            "2",  # report_choice (webhook)
            "http://my.webhook.url",  # webhook url
            "192.168.1.0/24",  # target
            "",  # host_file
            "y",  # skip_discovery
            "my-api-key",  # api_key
            "-sC",  # nmap_flags
            "4",  # speed
            "1",  # scan_type (ARP)
            "300",  # host_timeout
            "1",  # scan_method (Normal)
            "my_outputs",  # output_folder
            "svg",  # output_type
            "my_config.conf",  # config_file name
            "y", # Overwrite existing file
        ]

        # Mock ConfigParser instance
        mock_config_instance = MagicMock()
        mock_config_parser.return_value = mock_config_instance

        # To test the overwrite logic, we need open() to succeed on the first check,
        # then succeed again on the write call. A simple mock does this.
        # To test the "file not found" path, we would do this:
        # from unittest.mock import mock_open
        # mock_open.side_effect = [
        #     FileNotFoundError, # First call to check existence
        #     mock_open()() # Second call to write the file
        # ]

        CreateConfig(mock_console)

        # Verify that the config object was populated with the correct sections and data
        # by checking the calls to its __setitem__ method.
        expected_autopwn_section = {
            'scan_interval': '3600',
            'target': '192.168.1.0/24',
            'hostfile': '',
            'apikey': 'my-api-key',
            'scan_type': 'arp',
            'nmapflags': '-sC',
            'speed': '4', # This was correct, but the source code was wrong.
            'auto': True,
            'skip_exploit_download': True,
            'mode': 'normal',
            'skip_discovery': 'True',
            'output_folder': 'my_outputs',
            'output_type': 'svg',
            'host_timeout': '300', # This was correct, but the source code was wrong.
        }
        expected_report_section = {
            'method': 'webhook',
            'webhook': 'http://my.webhook.url'
        }
        mock_config_instance.__setitem__.assert_has_calls([call('AUTOPWN', expected_autopwn_section), call('REPORT', expected_report_section)], any_order=True)

        # Verify the file was written
        mock_write_config.assert_called_once_with(mock_config_instance, "my_config.conf")

    @patch("autopwn_suite.daemon.daemon_installer.open", new_callable=MagicMock)
    @patch("autopwn_suite.daemon.daemon_installer.ConfigParser")
    @patch("autopwn_suite.daemon.daemon_installer._write_config")
    def test_create_config_email_flow(self, mock_write_config, mock_config_parser, mock_open, mock_console):
        """Verify config creation with email notification."""
        # Simulate user inputs for the email notification path
        mock_console.input.side_effect = [
            "0",  # scan_interval
            "1",  # report_choice (email)
            "user@example.com",  # report_email
            "password123",  # report_email_password
            "recipient@example.com",  # report_email_to
            "",  # report_email_from (use default)
            "smtp.example.com",  # report_email_server
            "587",  # report_email_server_port
            "",  # target (auto-detect)
            "",  # host_file
            "n",  # skip_discovery
            "",  # api_key
            "",  # nmap_flags
            "",  # speed (default) -> _get_validated_int
            "2",  # scan_type (Ping)
            "",  # host_timeout (default) -> _get_validated_int
            "2",  # scan_method (Evade)
            "",  # output_folder (default)
            "",  # output_type (default)
            "y", # Overwrite existing file
        ]

        # Mock ConfigParser instance
        mock_config_instance = MagicMock()
        mock_config_parser.return_value = mock_config_instance

        CreateConfig(mock_console)

        # Verify the REPORT section was populated correctly for email
        expected_report_section = {
            'method': 'email',
            'email': 'user@example.com',
            'email_password': 'password123',
            'email_to': 'recipient@example.com',
            'email_from': 'user@example.com', # Fell back to default
            'email_server': 'smtp.example.com',
            'email_port': '587',
        }
        mock_config_instance.__setitem__.assert_any_call('REPORT', expected_report_section)

        # The function first tries to open the file for reading ('r') to see if it exists.
        # Since the mock doesn't raise FileNotFoundError, it then asks to overwrite.
        # After the user says 'y', it writes the configuration.
        # Due to the bug, the filename defaults to "autopwn.conf".

        # Verify the file was written
        mock_write_config.assert_called_once_with(mock_config_instance, "autopwn.conf")

    def test_create_config_keeps_percent_signs_in_a_webhook_url_and_api_key(self, mock_console, tmp_path):
        """A lone '%' is legal in a secret; the writer must accept what InitArgsConf reads."""
        webhook, api_key = "https://hooks.example.test/h?t=a%2Fb", "k%ey%"
        mock_console.input.side_effect = [
            "0", "2", webhook, "", "", api_key, "", "", "1", "", "1", "", "",
        ]
        config_path = tmp_path / "autopwn.conf"

        assert CreateConfig(mock_console, str(config_path)) is True

        args = SimpleNamespace(config=str(config_path))
        InitArgsConf(args, MagicMock())
        assert args.report_webhook == webhook
        assert args.api == api_key

    def test_create_config_keeps_percent_signs_in_an_smtp_password(self, mock_console, tmp_path):
        mock_console.input.side_effect = [
            "0", "1", "user@example.test", "p%ssw0rd", "to@example.test", "", "smtp.example.test", "587",
            "", "", "", "", "", "1", "", "1", "", "",
        ]
        config_path = tmp_path / "autopwn.conf"

        assert CreateConfig(mock_console, str(config_path)) is True

        args = SimpleNamespace(config=str(config_path))
        InitArgsConf(args, MagicMock())
        assert args.report_email_password == "p%ssw0rd"

    @staticmethod
    def _webhook_answers():
        """Answers for a webhook configuration with every optional prompt left empty."""
        return ["0", "2", "https://hooks.example.test/h", "", "", "", "", "", "1", "", "1", "", ""]

    @staticmethod
    def _email_answers():
        """Answers for an email configuration with every optional prompt left empty."""
        return ["0", "1", "user@example.test", "p4ss", "to@example.test", "", "smtp.example.test", "587",
                "", "", "", "", "", "1", "", "1", "", ""]

    @pytest.mark.parametrize("flow, position, rejected, setting", [
        ("webhook", 0, "-1", ("AUTOPWN", "scan_interval", "0")),
        ("webhook", 2, "", ("REPORT", "webhook", "https://hooks.example.test/h")),
        ("webhook", 2, "   ", ("REPORT", "webhook", "https://hooks.example.test/h")),
        ("webhook", 7, "6", ("AUTOPWN", "speed", "3")),
        ("webhook", 7, "-1", ("AUTOPWN", "speed", "3")),
        ("webhook", 9, "-5", ("AUTOPWN", "host_timeout", "240")),
        ("webhook", 12, "pdf", ("AUTOPWN", "output_type", "html")),
        ("email", 7, "0", ("REPORT", "email_port", "587")),
        ("email", 7, "65536", ("REPORT", "email_port", "587")),
    ])
    def test_create_config_asks_again_for_a_value_the_loader_would_reject(
        self, mock_console, tmp_path, flow, position, rejected, setting
    ):
        """The daemon exits on a value InitArgsConf rejects and systemd restarts it every 5 seconds, so the
        wizard must refuse it while the operator is still answering."""
        answers = self._webhook_answers() if flow == "webhook" else self._email_answers()
        answers.insert(position, rejected)  # the wizard must read the same question again
        mock_console.input.side_effect = answers
        config_path = tmp_path / "autopwn-daemon.conf"

        assert CreateConfig(mock_console, str(config_path)) is True

        assert mock_console.input.call_count == len(answers)
        section, option, expected = setting
        args = SimpleNamespace(config=str(config_path))
        InitArgsConf(args, MagicMock())  # the loader accepts what was written
        parser = ConfigParser(interpolation=None)
        parser.read(config_path, encoding="utf-8")
        assert parser[section][option] == expected

    def test_create_config_creates_the_file_for_its_owner_only(self, mock_console, tmp_path):
        """The file holds the SMTP password, NVD key or webhook URL, so it is never created group/world readable."""
        mock_console.input.side_effect = self._webhook_answers()
        config_path = tmp_path / "autopwn-daemon.conf"

        with patch.object(daemon_installer.os, "open", wraps=os.open) as opened:
            assert CreateConfig(mock_console, str(config_path)) is True

        # One new file beside it, never the final name itself: it is created exclusively, with mode 0600, and
        # replaces the final name in one step, so nothing readable by others exists at any moment.
        creations = [c.args for c in opened.call_args_list if Path(c.args[0]).parent == tmp_path]
        assert len(creations) == 1
        created, flags, mode = creations[0]
        assert Path(created) != config_path and mode == 0o600
        assert flags == os.O_WRONLY | os.O_CREAT | os.O_EXCL
        assert "https://hooks.example.test/h" in config_path.read_text(encoding="utf-8")
        assert [entry.name for entry in tmp_path.iterdir()] == [config_path.name]

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")
    @pytest.mark.parametrize("existing", [False, True])
    def test_create_config_file_mode_is_0600_also_when_replacing_a_0644_file(self, mock_console, tmp_path, existing):
        config_path = tmp_path / "autopwn-daemon.conf"
        answers = self._webhook_answers()
        if existing:
            config_path.write_text("old", encoding="utf-8")
            config_path.chmod(0o644)
            answers.append("y")  # overwrite
        mock_console.input.side_effect = answers

        previous_umask = os.umask(0o022)
        try:
            assert CreateConfig(mock_console, str(config_path)) is True
        finally:
            os.umask(previous_umask)

        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="needs hard links and POSIX file modes")
    def test_create_config_never_writes_into_the_file_it_replaces(self, mock_console, tmp_path):
        """The wizard's secrets must not enter an old 0644 file (or one another user has open): the old file is replaced."""
        config_path = tmp_path / "autopwn-daemon.conf"
        config_path.write_text("old", encoding="utf-8")
        config_path.chmod(0o644)
        witness = tmp_path / "witness"
        os.link(config_path, witness)  # the same inode, as a reader who already opened the old file would hold it
        mock_console.input.side_effect = [*self._webhook_answers(), "y"]

        assert CreateConfig(mock_console, str(config_path)) is True

        assert witness.read_text(encoding="utf-8") == "old"
        assert stat.S_IMODE(witness.stat().st_mode) == 0o644
        assert "hooks.example.test" in config_path.read_text(encoding="utf-8")
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_create_config_does_not_write_through_a_dangling_symlink(self, mock_console, tmp_path):
        """A planted link at the file name must not make the wizard create (as root) the file the link points to."""
        target = tmp_path / "elsewhere"
        config_path = tmp_path / "autopwn-daemon.conf"
        config_path.symlink_to(target)
        mock_console.input.side_effect = self._webhook_answers()

        assert CreateConfig(mock_console, str(config_path)) is True

        assert not target.exists()
        assert not config_path.is_symlink() and "hooks.example.test" in config_path.read_text(encoding="utf-8")

    def test_create_config_leaves_no_file_behind_when_it_cannot_finish(self, mock_console, tmp_path):
        config_path = tmp_path / "autopwn-daemon.conf"
        mock_console.input.side_effect = self._webhook_answers()

        with patch.object(daemon_installer.os, "replace", side_effect=OSError("disk full")), pytest.raises(OSError):
            CreateConfig(mock_console, str(config_path))

        assert list(tmp_path.iterdir()) == []  # neither a partial configuration nor the temporary file


@pytest.mark.unit
class TestInstallDaemon:
    """Tests for the InstallDaemon function."""

    @pytest.fixture(autouse=True)
    def installable(self, monkeypatch):
        """The preflight touches /opt and the interpreter; its own tests live in TestCopyFiles and TestCheckInstallable."""
        check = MagicMock(return_value=True)
        monkeypatch.setattr(daemon_installer, "_check_installable", check)
        return check

    @patch("autopwn_suite.daemon.daemon_installer.CopyFiles")
    @patch("autopwn_suite.daemon.daemon_installer.CreateConfig")
    @patch("autopwn_suite.daemon.daemon_installer.print_banner")
    @patch("autopwn_suite.daemon.daemon_installer.system", return_value="Linux")
    @patch("autopwn_suite.daemon.daemon_installer.is_root", return_value=True)
    def test_install_refuses_an_unusable_installation_before_asking_any_question(
        self, mock_is_root, mock_system, mock_banner, mock_create_config, mock_copy_files, mock_console, installable
    ):
        """The wizard writes a configuration that can hold secrets; a refusal must not come after it."""
        installable.return_value = False

        InstallDaemon(mock_console)

        installable.assert_called_once()
        assert str(installable.call_args.args[1]) == str(Path("/opt/autopwn-suite"))
        mock_create_config.assert_not_called()
        mock_copy_files.assert_not_called()

    @patch("autopwn_suite.daemon.daemon_installer.CopyFiles")
    @patch("autopwn_suite.daemon.daemon_installer.CreateConfig")
    @patch("autopwn_suite.daemon.daemon_installer.print_banner")
    @patch("autopwn_suite.daemon.daemon_installer.system", return_value="Linux")
    @patch("autopwn_suite.daemon.daemon_installer.is_root", return_value=True)
    def test_install_daemon_success_path(
        self, mock_is_root, mock_system, mock_banner, mock_create_config, mock_copy_files, mock_console
    ):
        """Verify the main installation flow on a supported system."""
        InstallDaemon(mock_console)
        mock_banner.assert_called_once_with(mock_console)
        mock_create_config.assert_called_once_with(mock_console, "autopwn-daemon.conf")
        mock_copy_files.assert_called_once_with(mock_console)

    @patch("autopwn_suite.daemon.daemon_installer.system", return_value="Windows")
    @patch("autopwn_suite.daemon.daemon_installer.is_root", return_value=True)
    def test_install_daemon_wrong_os(self, mock_is_root, mock_system, mock_console):
        """Verify it aborts on non-Linux systems."""
        InstallDaemon(mock_console)
        mock_console.print.assert_called_with(
            "Daemon can only be installed on [cyan]Linux[/cyan] and as [cyan]root[/cyan]!"
        )

    @patch("autopwn_suite.daemon.daemon_installer.CopyFiles")
    @patch("autopwn_suite.daemon.daemon_installer.CreateConfig", return_value=False)
    @patch("autopwn_suite.daemon.daemon_installer.print_banner")
    @patch("autopwn_suite.daemon.daemon_installer.system", return_value="Linux")
    @patch("autopwn_suite.daemon.daemon_installer.is_root", return_value=True)
    def test_install_cancellation_does_not_use_old_configuration(self, mock_root, mock_system,
            mock_banner, mock_config, mock_copy, mock_console):
        InstallDaemon(mock_console)
        mock_copy.assert_not_called()

    @patch("autopwn_suite.daemon.daemon_installer.system", return_value="Linux")
    @patch("autopwn_suite.daemon.daemon_installer.is_root", return_value=False)
    def test_install_daemon_not_root(self, mock_is_root, mock_system, mock_console):
        """Verify it aborts if not run as root."""
        InstallDaemon(mock_console)
        mock_console.print.assert_called_with(
            "Daemon can only be installed on [cyan]Linux[/cyan] and as [cyan]root[/cyan]!"
        )


@pytest.mark.unit
class TestCopyFiles:
    """Tests for the CopyFiles function."""

    @pytest.fixture(autouse=True)
    def root_controlled(self, monkeypatch):
        monkeypatch.setattr(daemon_installer, "_service_files_are_root_controlled", lambda install_path: True)
        monkeypatch.setattr(daemon_installer, "_service_can_import_package", lambda install_path: True)

    @staticmethod
    def _paths(mock_path, config_exists=True, same_file=False):
        """Mock Path so the install directory, service file and log file are distinguishable."""
        install, service, log, cwd = MagicMock(name="install"), MagicMock(name="service"), MagicMock(name="log"), MagicMock(name="cwd")
        source, target = MagicMock(name="source_conf"), MagicMock(name="target_conf")
        source.exists.return_value = config_exists
        source.resolve.return_value = "same" if same_file else "source"
        target.resolve.return_value = "same" if same_file else "target"
        cwd.__truediv__.side_effect = lambda name: source
        install.__truediv__.side_effect = lambda name: target
        mock_path.side_effect = lambda p: {
            "/opt/autopwn-suite": install,
            "/etc/systemd/system/autopwn-daemon.service": service,
            "/var/log/autopwn-daemon.log": log,
        }[str(p)]
        mock_path.cwd.return_value = cwd
        return install, source, target

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_installs_only_the_config_and_runs_the_installed_program(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console
    ):
        install, source, target = self._paths(mock_path)

        CopyFiles(mock_console)

        install.mkdir.assert_called_once_with(mode=0o755, parents=True, exist_ok=True)  # never 0777 under an odd umask
        mock_install.assert_called_once_with(source, target)
        mock_subprocess.check_call.assert_has_calls(
            [
                call(["systemctl", "daemon-reload"], env=None),
                call(["systemctl", "enable", "autopwn-daemon.service"], env=None),
                call(["systemctl", "restart", "autopwn-daemon.service"], env=None),
            ]
        )
        # `enable --now` would leave a daemon that is already running on the old program and configuration.
        assert all("--now" not in c.args[0] for c in mock_subprocess.check_call.call_args_list)
        # No virtualenv or pip is involved: the unit starts the interpreter that performed the install.
        assert all("pip" not in str(c) for c in mock_subprocess.check_call.call_args_list)
        unit = mock_open.return_value.__enter__.return_value.write.call_args.args[0]
        assert "KillMode=control-group" in unit
        assert re.search(r"^ExecStart=.* -m autopwn_suite -c ", unit, re.MULTILINE)
        assert "autopwn.py" not in unit and ".venv" not in unit

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_installs_the_config_through_the_owner_only_path_and_does_not_chmod_afterwards(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console
    ):
        install, source, target = self._paths(mock_path)

        CopyFiles(mock_console)

        # The copy carries the SMTP password, NVD key and webhook URL: it is created owner-only, not tightened afterwards.
        mock_install.assert_called_once_with(source, target)
        target.chmod.assert_not_called()

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_does_not_copy_a_config_onto_itself(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console
    ):
        install, source, target = self._paths(mock_path, same_file=True)

        CopyFiles(mock_console)

        mock_install.assert_not_called()
        target.chmod.assert_called_once_with(0o600)  # already in place: the wizard created it owner-only
        mock_subprocess.check_call.assert_any_call(["systemctl", "daemon-reload"], env=None)

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_starts_systemctl_without_the_bundle_of_a_standalone_binary(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console, monkeypatch
    ):
        # The binary's bootloader puts its unpacked libraries first in LD_LIBRARY_PATH; systemctl must not load them.
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")
        monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
        self._paths(mock_path)

        CopyFiles(mock_console)

        assert mock_subprocess.check_call.call_count == 3
        for systemctl in mock_subprocess.check_call.call_args_list:
            assert systemctl.args[0][0] == "systemctl"
            assert "LD_LIBRARY_PATH" not in systemctl.kwargs["env"]

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_does_not_report_success_when_the_restart_fails(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console
    ):
        self._paths(mock_path)
        mock_subprocess.CalledProcessError = subprocess.CalledProcessError
        mock_subprocess.check_call.side_effect = [None, None, subprocess.CalledProcessError(1, "systemctl")]

        CopyFiles(mock_console)

        printed = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "systemctl restart autopwn-daemon.service" in printed
        assert "installation complete" not in printed

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_refuses_a_service_that_an_unprivileged_user_could_modify(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console, monkeypatch
    ):
        self._paths(mock_path)
        monkeypatch.setattr(daemon_installer, "_service_files_are_root_controlled", lambda install_path: False)

        CopyFiles(mock_console)

        mock_install.assert_not_called()
        mock_subprocess.check_call.assert_not_called()
        mock_open.assert_not_called()
        assert any("Refusing to install the daemon" in str(c) for c in mock_console.print.call_args_list)

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_refuses_a_unit_that_could_not_import_the_package(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console, monkeypatch
    ):
        # A source checkout run as `python autopwn.py`: root-owned and importable here, not from /opt/autopwn-suite.
        self._paths(mock_path)
        monkeypatch.setattr(daemon_installer, "_service_can_import_package", lambda install_path: False)

        CopyFiles(mock_console)

        mock_install.assert_not_called()
        mock_subprocess.check_call.assert_not_called()
        mock_open.assert_not_called()
        assert any("cannot import autopwn_suite" in str(c) for c in mock_console.print.call_args_list)

    @patch("autopwn_suite.daemon.daemon_installer.subprocess")
    @patch("autopwn_suite.daemon.daemon_installer._install_config")
    @patch("autopwn_suite.daemon.daemon_installer.Path")
    @patch("autopwn_suite.daemon.daemon_installer.open")
    def test_copy_files_stops_when_the_config_is_missing(
        self, mock_open, mock_path, mock_install, mock_subprocess, mock_console
    ):
        self._paths(mock_path, config_exists=False)

        CopyFiles(mock_console)

        mock_install.assert_not_called()
        mock_subprocess.check_call.assert_not_called()
        mock_open.assert_not_called()
        assert any("does not exist" in str(c) for c in mock_console.print.call_args_list)


@pytest.mark.unit
class TestOwnerOnlyConfigInstall:
    """AUTOPWN-SA-2026-013: the installed configuration (SMTP password, NVD key, webhook URL) is never readable by
    others, not even while `--daemon-install` creates it for the first time. These run CopyFiles on a real
    directory; only systemd, the unit file's writer, the log file and the root-ownership probes are replaced."""

    SECRET = "email_password = synthetic-secret-for-tests\n"

    @pytest.fixture
    def installation(self, tmp_path, monkeypatch, mock_console):
        opt, cwd = tmp_path / "opt" / "autopwn-suite", tmp_path / "work"
        cwd.mkdir()
        (cwd / "autopwn-daemon.conf").write_text(self.SECRET, encoding="utf-8")
        (cwd / "autopwn-daemon.conf").chmod(0o600)  # as the wizard writes it
        monkeypatch.chdir(cwd)
        monkeypatch.setattr(daemon_installer, "INSTALL_DIR", str(opt))
        monkeypatch.setattr(daemon_installer, "SERVICE_FILE", str(tmp_path / "autopwn-daemon.service"))
        monkeypatch.setattr(daemon_installer, "_service_files_are_root_controlled", lambda install_path: True)
        monkeypatch.setattr(daemon_installer, "_service_can_import_package", lambda install_path: True)
        systemctl = MagicMock()
        monkeypatch.setattr(daemon_installer.subprocess, "check_call", systemctl)
        log = MagicMock()
        log.exists.return_value = True  # nothing is created under /var/log

        def path(*parts):
            return log if parts == ("/var/log/autopwn-daemon.log",) else Path(*parts)

        path.cwd = Path.cwd
        monkeypatch.setattr(daemon_installer, "Path", path)
        return SimpleNamespace(opt=opt, installed=opt / "autopwn-daemon.conf", console=mock_console, systemctl=systemctl)

    @staticmethod
    def _install_under_umask(installation, umask):
        previous = os.umask(umask)
        try:
            CopyFiles(installation.console)
        finally:
            os.umask(previous)

    def test_the_installed_config_is_never_copied_onto_its_final_name(self, installation, monkeypatch):
        """shutil.copy2 created the file with the process umask and tightened it afterwards."""
        def forbidden(*args, **kwargs):
            raise AssertionError("the configuration must not be copied with shutil")

        for name in ("copy", "copy2", "copyfile", "copyfileobj", "move"):
            monkeypatch.setattr(shutil, name, forbidden)

        CopyFiles(installation.console)

        assert installation.installed.read_text(encoding="utf-8") == self.SECRET
        installation.systemctl.assert_called()

    def test_the_installed_config_is_created_exclusively_with_mode_0600_and_replaces_the_final_name(self, installation):
        real_open, real_replace = os.open, os.replace
        opened, replaced = [], []

        def recording_open(path, flags, mode=0o777, **kwargs):
            opened.append((Path(path), flags, mode))
            return real_open(path, flags, mode, **kwargs)

        def recording_replace(source, destination):
            replaced.append((Path(source), Path(destination)))
            return real_replace(source, destination)

        with patch.object(daemon_installer.os, "open", recording_open), \
                patch.object(daemon_installer.os, "replace", recording_replace):
            CopyFiles(installation.console)

        creations = [entry for entry in opened if entry[0].parent == installation.opt]
        assert len(creations) == 1
        temporary, flags, mode = creations[0]
        assert temporary != installation.installed
        assert flags == os.O_WRONLY | os.O_CREAT | os.O_EXCL and mode == 0o600
        assert replaced == [(temporary, installation.installed)]
        assert [entry.name for entry in installation.opt.iterdir()] == ["autopwn-daemon.conf"]
        assert installation.installed.read_text(encoding="utf-8") == self.SECRET

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")
    @pytest.mark.parametrize("umask, source_mode", [(0o022, 0o600), (0o022, 0o644), (0o000, 0o666)])
    def test_nothing_in_the_install_directory_is_readable_by_others_when_the_file_is_put_in_place(
        self, installation, umask, source_mode
    ):
        (Path.cwd() / "autopwn-daemon.conf").chmod(source_mode)  # a wizard file an earlier release left readable
        real_replace = os.replace
        seen = []

        def inspecting_replace(source, destination):
            seen.append({entry.name: stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) for entry in os.scandir(installation.opt)})
            return real_replace(source, destination)

        with patch.object(daemon_installer.os, "replace", inspecting_replace):
            self._install_under_umask(installation, umask)

        assert len(seen) == 1, "the configuration must be put in place with one atomic replacement"
        assert len(seen[0]) == 1 and all(mode & 0o077 == 0 for mode in seen[0].values())
        assert stat.S_IMODE(installation.installed.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")
    def test_a_local_user_polling_the_directory_never_sees_a_readable_file(self, installation):
        """The attack: watch the directory and open the file the moment it appears."""
        (Path.cwd() / "autopwn-daemon.conf").write_text(self.SECRET + "# " + "x" * (24 * 1024 * 1024) + "\n", encoding="utf-8")
        installation.opt.mkdir(parents=True)
        stop, exposed = threading.Event(), []

        def poll():
            while not stop.is_set():
                try:
                    for entry in os.scandir(installation.opt):
                        mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                        if mode & 0o077:
                            exposed.append((entry.name, oct(mode)))
                except OSError:
                    pass

        poller = threading.Thread(target=poll)
        poller.start()
        try:
            self._install_under_umask(installation, 0o022)
        finally:
            stop.set()
            poller.join()

        assert exposed == []
        assert installation.installed.stat().st_size > 24 * 1024 * 1024

    @pytest.mark.skipif(os.name == "nt", reason="needs hard links and POSIX file modes")
    def test_an_existing_0644_installed_config_is_replaced_not_written_into(self, installation):
        installation.opt.mkdir(parents=True)
        installation.installed.write_text("old secrets", encoding="utf-8")
        installation.installed.chmod(0o644)
        witness = installation.opt.parent / "witness"
        os.link(installation.installed, witness)  # the old inode, as a reader that already opened it holds it

        self._install_under_umask(installation, 0o022)

        assert witness.read_text(encoding="utf-8") == "old secrets"  # the new content never entered the old file
        assert installation.installed.read_text(encoding="utf-8") == self.SECRET
        assert stat.S_IMODE(installation.installed.stat().st_mode) == 0o600

    def test_a_failed_installation_leaves_the_old_config_and_no_temporary_file(self, installation):
        installation.opt.mkdir(parents=True)
        installation.installed.write_text("old secrets", encoding="utf-8")

        with patch.object(daemon_installer.os, "replace", side_effect=OSError("disk full")):
            CopyFiles(installation.console)

        assert installation.installed.read_text(encoding="utf-8") == "old secrets"
        assert [entry.name for entry in installation.opt.iterdir()] == ["autopwn-daemon.conf"]
        assert "Error copying" in str(installation.console.print.call_args_list)
        installation.systemctl.assert_not_called()  # the service is not (re)started on a configuration that is not there

    def test_a_write_that_fails_halfway_leaves_no_temporary_file(self, installation):
        with patch.object(daemon_installer.os, "fsync", side_effect=OSError("I/O error")):
            CopyFiles(installation.console)

        assert list(installation.opt.iterdir()) == []
        assert "Error copying" in str(installation.console.print.call_args_list)
        installation.systemctl.assert_not_called()

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")
    def test_a_config_already_in_the_install_directory_is_made_owner_only_and_not_copied(self, installation, monkeypatch):
        installation.opt.mkdir(parents=True)
        installation.installed.write_text(self.SECRET, encoding="utf-8")
        installation.installed.chmod(0o644)
        monkeypatch.chdir(installation.opt)

        with patch.object(daemon_installer.os, "replace") as replace:
            CopyFiles(installation.console)

        replace.assert_not_called()
        assert stat.S_IMODE(installation.installed.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX file modes")
    @pytest.mark.parametrize("umask, expected", [(0o000, 0o755), (0o022, 0o755), (0o027, 0o750), (0o077, 0o700)],
                             ids=["umask-000", "umask-022", "umask-027", "umask-077"])
    def test_a_new_install_directory_is_0755_less_what_the_umask_removes(self, installation, umask, expected):
        """Never wider than 0755 (the umask can only remove bits), so not 0777 under umask 000, which the
        root-ownership check would refuse."""
        self._install_under_umask(installation, umask)

        assert stat.S_IMODE(installation.opt.stat().st_mode) == expected


CONFIG = str(Path("/opt/autopwn-suite") / "autopwn-daemon.conf")


@pytest.mark.unit
class TestRootControlled:
    """The root service must not execute or read anything an unprivileged user can replace."""

    @staticmethod
    def table(monkeypatch, entries):
        monkeypatch.setattr(daemon_installer.os.path, "realpath", lambda path: str(path))

        def lstat(part):
            uid, mode = entries[Path(part).as_posix()]
            return SimpleNamespace(st_uid=uid, st_mode=mode)

        return lstat

    DIR_755 = stat.S_IFDIR | 0o755

    def chain(self, **overrides):
        entries = {"/": (0, self.DIR_755), "/opt": (0, self.DIR_755), "/opt/autopwn-suite": (0, self.DIR_755),
                   "/opt/autopwn-suite/python": (0, stat.S_IFREG | 0o755)}
        entries.update(overrides)
        return entries

    def test_root_owned_unwritable_chain_is_accepted(self, monkeypatch):
        lstat = self.table(monkeypatch, self.chain())
        assert daemon_installer._root_controlled("/opt/autopwn-suite/python", lstat)

    @pytest.mark.parametrize("override", [
        {"/opt/autopwn-suite": (1000, DIR_755)},  # directory owned by a user
        {"/opt/autopwn-suite": (0, stat.S_IFDIR | 0o775)},  # group-writable directory
        {"/opt": (0, stat.S_IFDIR | 0o757)},  # world-writable parent
        {"/opt/autopwn-suite/python": (1000, stat.S_IFREG | 0o755)},  # user-owned file
        {"/opt/autopwn-suite/python": (0, stat.S_IFREG | 0o777)},  # world-writable file
    ])
    def test_anything_a_user_could_replace_is_rejected(self, monkeypatch, override):
        lstat = self.table(monkeypatch, self.chain(**override))
        assert not daemon_installer._root_controlled("/opt/autopwn-suite/python", lstat)

    def test_symlink_is_judged_by_owner_not_by_its_always_open_mode(self, monkeypatch):
        link = stat.S_IFLNK | 0o777
        assert daemon_installer._root_controlled(
            "/opt/autopwn-suite/python", self.table(monkeypatch, self.chain(**{"/opt/autopwn-suite/python": (0, link)})))
        assert not daemon_installer._root_controlled(
            "/opt/autopwn-suite/python", self.table(monkeypatch, self.chain(**{"/opt/autopwn-suite/python": (1000, link)})))

    def test_service_check_covers_interpreter_config_directory_and_package(self, monkeypatch):
        checked = []
        monkeypatch.setattr(daemon_installer, "_root_controlled", lambda path: checked.append(Path(path)) or True)
        assert daemon_installer._service_files_are_root_controlled(Path("/opt/autopwn-suite"))
        assert Path(sys.executable) in checked and Path("/opt/autopwn-suite") in checked
        assert any(path.name == "autopwn_suite" for path in checked)

    def test_a_frozen_binary_has_no_separate_package_directory(self, monkeypatch):
        checked = []
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(daemon_installer, "_root_controlled", lambda path: checked.append(Path(path)) or True)
        daemon_installer._service_files_are_root_controlled(Path("/opt/autopwn-suite"))
        assert not any(path.name == "autopwn_suite" for path in checked)

    def test_one_unsafe_location_fails_the_whole_check(self, monkeypatch):
        monkeypatch.setattr(daemon_installer, "_root_controlled", lambda path: Path(path) != Path("/opt/autopwn-suite"))
        assert not daemon_installer._service_files_are_root_controlled(Path("/opt/autopwn-suite"))


@pytest.mark.unit
class TestExecStart:
    def test_source_or_wheel_install_runs_the_module_with_the_installing_interpreter(self):
        line = _exec_start(Path("/opt/autopwn-suite"))
        assert line == f"{shlex.quote(sys.executable)} -m autopwn_suite -c {shlex.quote(CONFIG)}"

    def test_frozen_binary_runs_itself(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        line = _exec_start(Path("/opt/autopwn-suite"))
        assert line == f"{shlex.quote(sys.executable)} -c {shlex.quote(CONFIG)}"

    def test_paths_with_spaces_are_quoted(self, monkeypatch):
        monkeypatch.setattr(sys, "executable", "/opt/my tools/python")
        assert _exec_start(Path("/opt/autopwn-suite")).startswith("'/opt/my tools/python' -m autopwn_suite")


@pytest.mark.unit
class TestPackageImportCheck:
    """The unit runs `python -m autopwn_suite` from /opt/autopwn-suite: a source checkout that only works
    because `python autopwn.py` has it next to the script would give a service that restarts forever."""

    @staticmethod
    def probe_result(monkeypatch, **outcome):
        run = MagicMock(**outcome)
        monkeypatch.setattr(daemon_installer.subprocess, "run", run)
        return run

    def test_the_probe_starts_the_interpreter_the_way_the_unit_does(self, monkeypatch):
        run = self.probe_result(monkeypatch, return_value=SimpleNamespace(returncode=0))

        assert daemon_installer._service_can_import_package(Path("/opt/autopwn-suite")) is True

        command = run.call_args.args[0]
        assert command[:3] == [sys.executable, "-E", "-c"]  # no PYTHONPATH of the person running the installer
        assert "find_spec('autopwn_suite')" in command[3]
        assert run.call_args.kwargs["cwd"] == Path("/opt/autopwn-suite")

    @pytest.mark.parametrize("outcome", [
        {"return_value": SimpleNamespace(returncode=1)},
        {"side_effect": OSError("interpreter vanished")},
        {"side_effect": subprocess.TimeoutExpired("python", 60)},
    ])
    def test_a_package_the_service_cannot_import_is_reported(self, monkeypatch, outcome):
        self.probe_result(monkeypatch, **outcome)
        assert daemon_installer._service_can_import_package(Path("/opt/autopwn-suite")) is False

    def test_a_frozen_binary_needs_no_probe(self, monkeypatch):
        run = self.probe_result(monkeypatch, return_value=SimpleNamespace(returncode=1))
        monkeypatch.setattr(sys, "frozen", True, raising=False)

        assert daemon_installer._service_can_import_package(Path("/opt/autopwn-suite")) is True
        run.assert_not_called()


@pytest.mark.unit
class TestCheckInstallable:
    @pytest.fixture
    def install_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(daemon_installer, "_service_files_are_root_controlled", lambda path: True)
        monkeypatch.setattr(daemon_installer, "_service_can_import_package", lambda path: True)
        return tmp_path / "opt" / "autopwn-suite"

    def test_a_usable_installation_creates_the_directory_once(self, install_path, mock_console):
        assert daemon_installer._check_installable(mock_console, install_path) is True
        assert install_path.is_dir()
        assert daemon_installer._check_installable(mock_console, install_path) is True  # InstallDaemon, then CopyFiles
        creating = [c for c in mock_console.print.call_args_list if "Creating install directory" in str(c)]
        assert len(creating) == 1

    def test_a_directory_another_user_can_modify_is_refused_with_the_reason(self, install_path, mock_console, monkeypatch):
        monkeypatch.setattr(daemon_installer, "_service_files_are_root_controlled", lambda path: False)
        assert daemon_installer._check_installable(mock_console, install_path) is False
        assert "can be modified by another user" in str(mock_console.print.call_args_list)

    def test_a_package_the_service_cannot_import_is_refused_with_the_reason(self, install_path, mock_console, monkeypatch):
        monkeypatch.setattr(daemon_installer, "_service_can_import_package", lambda path: False)
        assert daemon_installer._check_installable(mock_console, install_path) is False
        printed = str(mock_console.print.call_args_list)
        assert "cannot import autopwn_suite" in printed and "python autopwn.py" in printed

    def test_an_uncreatable_directory_is_refused(self, install_path, mock_console):
        install_path.parent.write_text("a file where a directory is needed")
        assert daemon_installer._check_installable(mock_console, install_path) is False
        assert "Failed to create install directory" in str(mock_console.print.call_args_list)


@pytest.mark.unit
class TestUninstallDaemon:
    """--daemon-uninstall removes the service and the configuration that --daemon-install created."""

    @pytest.fixture
    def layout(self, tmp_path, monkeypatch):
        service = tmp_path / "systemd" / "autopwn-daemon.service"
        service.parent.mkdir()
        service.write_text("[Unit]\n")
        install = tmp_path / "opt" / "autopwn-suite"
        install.mkdir(parents=True)
        (install / "autopwn-daemon.conf").write_text("[AUTOPWN]\n")
        (install / "keep.txt").write_text("keep\n")
        monkeypatch.setattr(daemon_installer, "SERVICE_FILE", str(service))
        monkeypatch.setattr(daemon_installer, "INSTALL_DIR", str(install))
        monkeypatch.setattr(daemon_installer, "is_root", lambda: True)
        monkeypatch.setattr(daemon_installer, "system", lambda: "Linux")
        monkeypatch.setattr(daemon_installer, "print_banner", MagicMock())
        layout = SimpleNamespace(service=service, install=install, calls=[], returncode=0, environments=[])

        def run(command, **kwargs):
            # Record whether the unit file still existed when systemctl was asked.
            layout.calls.append((command[1:], service.exists()))
            layout.environments.append(kwargs.get("env"))
            return SimpleNamespace(returncode=layout.returncode)

        monkeypatch.setattr(daemon_installer.subprocess, "run", run)
        return layout

    def test_removes_the_service_and_the_configuration_and_leaves_the_rest(self, layout, mock_console):
        UninstallDaemon(mock_console)

        assert not layout.service.exists()
        assert not (layout.install / "autopwn-daemon.conf").exists()  # it can hold an SMTP password or a webhook URL
        assert (layout.install / "keep.txt").read_text() == "keep\n"
        # Stopped while the unit still exists, and systemd told after the file is gone.
        assert layout.calls == [
            (["disable", "--now", "autopwn-daemon.service"], True),
            (["daemon-reload"], False),
        ]
        assert "Left in place" in str(mock_console.print.call_args_list)

    def test_nothing_installed_is_not_an_error(self, layout, mock_console):
        layout.service.unlink()
        (layout.install / "autopwn-daemon.conf").unlink()
        layout.returncode = 1  # systemctl: the unit does not exist

        UninstallDaemon(mock_console)

        assert [command for command, _ in layout.calls] == [["disable", "--now", "autopwn-daemon.service"]]
        assert (layout.install / "keep.txt").exists()

    @pytest.mark.parametrize("root, platform", [(False, "Linux"), (True, "Windows"), (True, "Darwin")])
    def test_only_root_on_linux_can_remove_it(self, layout, mock_console, monkeypatch, root, platform):
        monkeypatch.setattr(daemon_installer, "is_root", lambda: root)
        monkeypatch.setattr(daemon_installer, "system", lambda: platform)

        with pytest.raises(SystemExit) as stopped:
            UninstallDaemon(mock_console)

        assert stopped.value.code == 1
        assert layout.calls == [] and layout.service.exists()
        assert (layout.install / "autopwn-daemon.conf").exists()

    def test_a_unit_that_cannot_be_removed_keeps_the_configuration(self, layout, mock_console):
        # A unit that stays would start without its configuration and restart every 5 seconds.
        layout.service.unlink()
        layout.service.mkdir()  # unlink() of a directory fails

        with pytest.raises(SystemExit) as stopped:
            UninstallDaemon(mock_console)

        assert stopped.value.code == 1
        assert (layout.install / "autopwn-daemon.conf").exists()
        assert "Could not remove" in str(mock_console.print.call_args_list)

    def test_systemctl_errors_do_not_stop_the_removal(self, layout, mock_console):
        layout.returncode = 1

        UninstallDaemon(mock_console)

        assert not layout.service.exists() and not (layout.install / "autopwn-daemon.conf").exists()
        assert "sudo systemctl daemon-reload" in str(mock_console.print.call_args_list)

    def test_a_missing_systemctl_does_not_stop_the_removal(self, layout, mock_console, monkeypatch):
        monkeypatch.setattr(daemon_installer.subprocess, "run", MagicMock(side_effect=FileNotFoundError("systemctl")))

        UninstallDaemon(mock_console)

        assert not layout.service.exists() and not (layout.install / "autopwn-daemon.conf").exists()
        assert "systemctl could not be run" in str(mock_console.print.call_args_list)

    def test_systemctl_starts_without_the_bundle_of_a_standalone_binary(self, layout, mock_console, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")
        monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)

        UninstallDaemon(mock_console)

        assert len(layout.environments) == 2
        assert all("LD_LIBRARY_PATH" not in environment for environment in layout.environments)
