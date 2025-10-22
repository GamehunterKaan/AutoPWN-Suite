"""
Unit tests for the utility functions in modules/utils.py.
"""
import argparse
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch, call
from subprocess import CalledProcessError

import pytest

from modules.utils import (
    InitAutomation,
    InitArgsConf,
    InitArgsScanType,
    InitArgsTarget,
    InitArgsMode,
    InitReport,
    ParamPrint,
    GetHostsToScan,
    Confirmation,
    DetectIPRange,
    UserConfirmation,
    SaveOutput,
    check_nmap,
    InitArgsAPI,
    read_file_any_encoding,
    CheckConnection,
    ScanMode,
    ReportType,
    DEVNULL,
    ScanType,
    is_root,
)


@pytest.fixture
def mock_console():
    """Fixture for a mocked Rich Console."""
    console = MagicMock()
    console.save_html = MagicMock()
    console.save_svg = MagicMock()
    console.save_text = MagicMock()
    console.print = MagicMock()
    return console


@pytest.mark.unit
class TestSaveOutput:
    """Tests for the SaveOutput function."""

    def test_save_with_specified_output_file(self, mock_console, temp_dir):
        """
        Verify file is saved to the specified path when output_file is provided.
        """
        output_path = temp_dir / "my_report.html"
        target = "127.0.0.1"

        SaveOutput(mock_console, "html", str(output_path), None, target)

        # Verify the correct save method was called with the absolute path
        mock_console.save_html.assert_called_once_with(str(output_path))

        # Verify the confirmation message is printed with the correct path
        mock_console.print.assert_called_once()
        call_args, _ = mock_console.print.call_args
        assert f"Report saved to [cyan]{output_path}[/cyan]" in call_args[0]

    @patch("modules.utils.datetime")
    def test_save_with_automatic_filename(self, mock_datetime, mock_console, temp_dir):
        """
        Verify file is saved with an automatic name (DATE-HOST.ext) in the 'outputs'
        directory when no output_file is provided.
        """
        # Mock datetime.now() to return a fixed date
        mock_datetime.now.return_value = datetime(2023, 10, 27)
        target = "192.168.1.10"
        expected_filename = "2023-10-27_192.168.1.10.txt"

        # Change current directory to temp_dir to isolate file creation
        os.chdir(temp_dir)

        SaveOutput(mock_console, "txt", None, "outputs", target)

        expected_relative_path = os.path.join("outputs", expected_filename)

        # Verify the correct save method was called
        mock_console.save_text.assert_called_once_with(expected_relative_path)

        # Verify the confirmation message is printed
        mock_console.print.assert_called_once()
        call_args, _ = mock_console.print.call_args
        assert f"Report saved to [cyan]{expected_relative_path}[/cyan]" in call_args[0]

    def test_save_adds_correct_extension(self, mock_console, temp_dir):
        """
        Verify that the correct file extension is added if not present.
        """
        output_path = temp_dir / "my_report"  # No extension
        target = "127.0.0.1"

        SaveOutput(mock_console, "svg", str(output_path), None, target)

        # Verify it was called with the extension added
        mock_console.save_svg.assert_called_once_with(str(output_path) + ".svg")

    @patch("modules.utils.datetime")
    def test_save_with_multihost_target(self, mock_datetime, mock_console, temp_dir):
        """
        Verify an automatic filename with 'multihost' is created for a list of targets.
        """
        # Mock datetime.now() to return a fixed date
        mock_datetime.now.return_value = datetime(2023, 10, 27)
        targets = ["192.168.1.10", "192.168.1.11"]
        expected_filename = "2023-10-27_multihost.html"

        # Change current directory to temp_dir to isolate file creation
        os.chdir(temp_dir)

        SaveOutput(mock_console, "html", None, "outputs", targets)

        expected_relative_path = os.path.join("outputs", expected_filename)

        # Verify the correct save method was called
        mock_console.save_html.assert_called_once_with(expected_relative_path)
        # Verify the confirmation message is printed
        mock_console.print.assert_called_with(f"Report saved to [cyan]{expected_relative_path}[/cyan]")


@pytest.mark.unit
class TestInitArgsConf:
    """Tests for the InitArgsConf function."""

    def test_read_config_file(self, temp_file):
        """Verify that arguments are correctly read from a config file."""
        config_content = """
[AUTOPWN]
target = 192.168.1.0/24
speed = 5
auto = true

[REPORT]
output = test_report
method = email
"""
        config_path = temp_file("test.ini", config_content)
        args = argparse.Namespace(config=str(config_path))
        mock_log = MagicMock()

        InitArgsConf(args, mock_log)

        assert args.target == "192.168.1.0/24"
        assert args.speed == 5
        assert args.yes_please is True
        assert args.output == "test_report"
        assert args.report == "email"

    def test_no_config_arg(self):
        """Verify the function returns immediately if no config arg is passed."""
        args = argparse.Namespace(config=None)
        # We can patch something inside the function to see if it's called
        with patch("modules.utils.ConfigParser") as mock_parser:
            InitArgsConf(args, MagicMock())
            mock_parser.assert_not_called()

    @patch("modules.utils.ConfigParser.read", side_effect=FileNotFoundError)
    def test_config_file_not_found(self, mock_read):
        """Verify SystemExit is raised if the config file is not found."""
        args = argparse.Namespace(config="nonexistent.ini")
        mock_log = MagicMock()
        with pytest.raises(SystemExit):
            InitArgsConf(args, mock_log)
        mock_log.logger.assert_called_with("error", "Config file not found!")

    @patch("modules.utils.ConfigParser.read", side_effect=PermissionError)
    def test_config_permission_error(self, mock_read):
        """Verify SystemExit is raised on a permission error."""
        args = argparse.Namespace(config="no_access.ini")
        mock_log = MagicMock()
        with pytest.raises(SystemExit):
            InitArgsConf(args, mock_log)
        mock_log.logger.assert_called_with("error", "Permission denied while trying to read config file!")


@pytest.mark.unit
class TestInitArgsTarget:
    """Tests for the InitArgsTarget function."""

    def test_target_from_args(self):
        """Verify target is taken directly from args."""
        args = argparse.Namespace(target="10.0.0.1", host_file=None)
        mock_log = MagicMock()
        target = InitArgsTarget(args, mock_log)
        assert target == "10.0.0.1"

    def test_target_from_host_file(self, temp_file):
        """Verify targets are read from a host file."""
        host_file_content = "10.0.0.2\n10.0.0.3"
        host_file_path = temp_file("hosts.txt", host_file_content)
        args = argparse.Namespace(target=None, host_file=str(host_file_path))
        mock_log = MagicMock()

        target = InitArgsTarget(args, mock_log)
        assert target == ["10.0.0.2", "10.0.0.3"]

    def test_target_from_host_file_not_found(self):
        """Verify error is logged if host file is not found."""
        args = argparse.Namespace(target=None, host_file="nonexistent.txt")
        mock_log = MagicMock()

        # This will log an error and then fall back to auto-detection,
        # which we can ignore for this unit test's purpose.
        # We just want to check the log call.
        with patch("modules.utils.DetectIPRange", return_value="192.168.1.1/24"):
            InitArgsTarget(args, mock_log)

        mock_log.logger.assert_called_with("error", "Host file not found!")

    @patch("builtins.open", side_effect=PermissionError)
    def test_target_from_host_file_permission_error(self, mock_open):
        """Verify a permission error is logged if the host file is unreadable."""
        args = argparse.Namespace(target=None, host_file="unreadable.txt")
        mock_log = MagicMock()

        with patch("modules.utils.DetectIPRange", return_value="192.168.1.1/24"):
            InitArgsTarget(args, mock_log)

        mock_log.logger.assert_called_with("error", "Permission denied while trying to read host file!")

    @patch("builtins.open", side_effect=Exception("Generic file error"))
    def test_target_from_host_file_generic_exception(self, mock_open):
        """Verify a generic exception is logged if the host file is unreadable."""
        args = argparse.Namespace(target=None, host_file="badfile.txt")
        mock_log = MagicMock()

        with patch("modules.utils.DetectIPRange", return_value="192.168.1.1/24"):
            InitArgsTarget(args, mock_log)

        mock_log.logger.assert_called_with("error", "Unknown error while trying to read host file!")

    @patch("builtins.input", return_value="10.0.1.0/24")
    def test_target_from_interactive_input(self, mock_input, monkeypatch):
        """Verify target is taken from user input when no other options are provided."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        args = argparse.Namespace(target=None, host_file=None)
        mock_log = MagicMock()
        target = InitArgsTarget(args, mock_log)
        assert target == "10.0.1.0/24"
        mock_input.assert_called_once_with("Enter target range to scan : ")

    @patch("modules.utils.DetectIPRange", return_value="192.168.1.1/24")
    def test_target_from_auto_detection(self, mock_detect, monkeypatch):
        """Verify target is auto-detected in automatic mode."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", True)
        args = argparse.Namespace(target=None, host_file=None)
        target = InitArgsTarget(args, MagicMock())
        assert target == "192.168.1.1/24"
        mock_detect.assert_called_once()

    @patch("builtins.input", return_value="10.0.2.0/24")
    @patch("modules.utils.DetectIPRange", side_effect=Exception("Detection failed"))
    def test_target_fallback_to_input_on_detection_error(self, mock_detect, mock_input, monkeypatch):
        """Verify it falls back to input if auto-detection fails in automatic mode."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", True)
        args = argparse.Namespace(target=None, host_file=None)
        target = InitArgsTarget(args, MagicMock())
        assert target == "10.0.2.0/24"


@pytest.mark.unit
class TestInitArgsScanType:
    """Tests for the InitArgsScanType function."""

    @patch("modules.utils.is_root", return_value=True)
    def test_arp_scan_as_root(self, mock_is_root):
        """Verify ARP scan is selected when root."""
        args = argparse.Namespace(scan_type="arp")
        scan_type = InitArgsScanType(args, MagicMock())
        assert scan_type == ScanType.ARP

    @patch("modules.utils.is_root", return_value=False)
    def test_arp_scan_as_non_root(self, mock_is_root):
        """Verify Ping scan is used with a warning when not root."""
        args = argparse.Namespace(scan_type="arp")
        mock_log = MagicMock()
        scan_type = InitArgsScanType(args, mock_log)
        assert scan_type == ScanType.Ping
        mock_log.logger.assert_called_with(
            "warning",
            "You need to be root in order to run arp scan.\n"
            + "Changed scan mode to Ping Scan.",
        )


@pytest.mark.unit
class TestIsRoot:
    """Tests for the is_root function."""

    @patch("modules.utils.getuid", create=True)
    def test_is_root_linux_true(self, mock_getuid):
        """Test root on Linux."""
        mock_getuid.return_value = 0
        assert is_root() is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    @patch("modules.utils.windll", create=True)
    def test_is_root_windows_true(self, mock_windll):
        """Test admin on Windows."""
        # Simulate being on Windows by creating a mock for getuid that raises an error
        with patch("modules.utils.getuid", side_effect=NameError, create=True):
            mock_windll.shell32.IsUserAnAdmin.return_value = 1
            assert is_root() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux specific test")
    @patch("modules.utils.getuid", create=True)
    def test_is_root_linux_false(self, mock_getuid):
        """Test non-root on Linux."""
        mock_getuid.return_value = 1000  # Non-zero UID
        assert is_root() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific test")
    @patch("modules.utils.windll", create=True)
    def test_is_root_windows_false(self, mock_windll):
        """Test non-admin on Windows."""
        # Simulate being on Windows by creating a mock for getuid that raises an error
        with patch("modules.utils.getuid", side_effect=NameError, create=True):
            mock_windll.shell32.IsUserAnAdmin.return_value = 0
            assert is_root() is False


@pytest.mark.unit
@patch("modules.utils.get_terminal_width", return_value=80)
def test_param_print(mock_width, mock_console):
    """Verify the parameter print function formats output correctly."""
    args = argparse.Namespace(
        output=None,
        output_folder="outputs",
        skip_discovery=True,
        host_file="hosts.txt",
        host_timeout=300,
        speed=4,
        nmap_flags="-sC",
        report="webhook",
        yes_please=True,
    )
    targetarg = "192.168.1.0/24"
    scantype = ScanType.ARP
    scanmode = ScanMode.Normal
    apiKey = "test-key"
    mock_log = MagicMock()
    
    # Call InitAutomation to create the global variable that ParamPrint depends on
    InitAutomation(args)

    ParamPrint(args, targetarg, scantype, scanmode, apiKey, mock_console, mock_log)

    mock_console.print.assert_called_once()
    output = mock_console.print.call_args[0][0]
    assert "Target : 192.168.1.0/24" in output
    assert "Output folder : [yellow]outputs[/yellow]" in output
    assert "Skip discovery: True" in output
    assert "Scan type : [red]ARP[/red]" in output
    assert "Nmap flags : [blue]-sC[/blue]" in output
    assert "Reporting method : webhook" in output

    @patch("modules.utils.get_terminal_width", return_value=80)
    def test_param_print_evade_mode(self, mock_width, mock_console):
        """Verify ParamPrint formats correctly for Evade mode."""
        args = argparse.Namespace(
            output="evade_report.txt",
            skip_discovery=False,
            host_file=None,
            host_timeout=240, # Default, should not be printed
            speed=3,
            nmap_flags="",
            report=None,
            yes_please=False,
        )
        InitAutomation(args)

        ParamPrint(args, "target", ScanType.ARP, ScanMode.Evade, None, mock_console, MagicMock())

        mock_console.print.assert_called_once()
        output = mock_console.print.call_args[0][0]
        assert "Scan mode : Evade" in output
        assert "Scan type : [red]ARP[/red]" in output

    @patch("modules.utils.get_terminal_width", return_value=80)
    def test_param_print_noise_mode(self, mock_width, mock_console):
        """Verify ParamPrint formats correctly for Noise mode."""
        args = argparse.Namespace(
            output=None,
            skip_discovery=False,
            host_file=None,
            host_timeout=240,
            speed=3,
            nmap_flags="",
            report=None,
            yes_please=False,
        )
        InitAutomation(args)

        ParamPrint(args, "target", ScanType.Ping, ScanMode.Noise, "api-key", mock_console, MagicMock())

        mock_console.print.assert_called_once()
        output = mock_console.print.call_args[0][0]
        assert "Scan mode : Noise" in output
        assert "Scan type" not in output # Should not be printed in noise mode
        assert "Scan speed" not in output # Should not be printed in noise mode


@pytest.mark.unit
class TestUserConfirmation:
    """Tests for the UserConfirmation function."""

    def test_automatic_mode_returns_all_true(self):
        """Verify it returns (True, True, True) when DontAskForConfirmation is True."""
        mock_args = argparse.Namespace(yes_please=True, skip_exploit_download=False)
        InitAutomation(mock_args) # Initialize the global DontAskForConfirmation
        result = UserConfirmation(mock_args)
        assert result == (True, True, True)

    @patch("modules.utils.Confirmation")
    def test_interactive_mode_all_yes(self, mock_confirmation):
        """Verify it returns (True, True, True) when user answers 'y' to all prompts."""
        mock_args = argparse.Namespace(yes_please=False, skip_exploit_download=False)
        InitAutomation(mock_args) # Initialize the global DontAskForConfirmation
        mock_confirmation.return_value = True  # Simulate user always saying 'y'

        result = UserConfirmation(mock_args)

        assert result == (True, True, True)
        assert mock_confirmation.call_count == 3

    @patch("modules.utils.Confirmation", return_value=False)
    def test_interactive_mode_no_to_portscan(self, mock_confirmation):
        """Verify it returns (False, False, False) if user says 'n' to portscan."""
        mock_args = argparse.Namespace(yes_please=False, skip_exploit_download=False)
        InitAutomation(mock_args) # Initialize the global DontAskForConfirmation

        result = UserConfirmation(mock_args)

        assert result == (False, False, False)
        mock_confirmation.assert_called_once()  # Should exit after the first question

    @patch("modules.utils.Confirmation", side_effect=[True, False])
    def test_interactive_mode_no_to_vulnscan(self, mock_confirmation):
        """Verify it returns (True, False, False) if user says 'n' to vulnscan."""
        mock_args = argparse.Namespace(yes_please=False, skip_exploit_download=False)
        InitAutomation(mock_args) # Initialize the global DontAskForConfirmation

        result = UserConfirmation(mock_args)

        assert result == (True, False, False)
        assert mock_confirmation.call_count == 2  # Should exit after the second question

    @patch("modules.utils.Confirmation", return_value=True)
    def test_interactive_mode_skip_exploit_download(self, mock_confirmation):
        """Verify it returns (True, True, False) when skip_exploit_download is True."""
        mock_args = argparse.Namespace(yes_please=False, skip_exploit_download=True)
        InitAutomation(mock_args)
        result = UserConfirmation(mock_args) # This will call Confirmation twice
        assert result == (True, True, False)


@pytest.mark.unit
class TestDetectIPRange:
    """Tests for the DetectIPRange function."""

    @patch("modules.utils.Popen")
    @patch("modules.utils.GetIpAdress", return_value="192.168.1.100")
    @patch("modules.utils.system", return_value="windows")
    def test_detect_ip_range_windows(self, mock_system, mock_get_ip, mock_popen):
        """Verify IP range detection on Windows."""
        mock_proc = MagicMock()
        # Simulate the output of 'ipconfig'
        mock_proc.stdout.readline.side_effect = [
            b"   IPv4 Address. . . . . . . . . . . : 192.168.1.100\r\n",
            b"   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n",
        ]
        mock_popen.return_value = mock_proc

        ip_range = DetectIPRange()

        assert ip_range == "192.168.1.100/24"

    @patch("modules.utils.Popen")
    @patch("modules.utils.GetIpAdress", return_value="10.0.2.15")
    @patch("modules.utils.system", return_value="linux")
    def test_detect_ip_range_linux(self, mock_system, mock_get_ip, mock_popen):
        """Verify IP range detection on Linux."""
        mock_proc = MagicMock()
        # Simulate the output of 'ip addr show'
        mock_proc.stdout.read.return_value = (
            b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc ...\n"
            b"    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0\n"
        )
        mock_popen.return_value = mock_proc

        ip_range = DetectIPRange()

        assert ip_range == "10.0.2.15/24"


@pytest.mark.unit
class TestNmapInstallation:
    """Tests for the nmap installation functions."""

    @patch("modules.utils.check_call")
    def test_check_nmap_already_installed(self, mock_check_call):
        """Verify that no installation is attempted if nmap is found."""
        mock_check_call.return_value = 0  # Simulate nmap -h succeeding
        mock_log = MagicMock()
        check_nmap(mock_log)
        mock_check_call.assert_called_once_with(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)

    @patch("modules.utils.install_nmap_linux")
    @patch("modules.utils.system", return_value="linux")
    @patch("builtins.input", return_value="y")
    @patch("modules.utils.check_call")
    def test_check_nmap_install_on_linux(self, mock_check_call, mock_input, mock_system, mock_install_linux):
        """Verify that installation is triggered on Linux if nmap is not found."""
        # The first call for 'nmap -h' fails, the rest succeed.
        mock_check_call.side_effect = [FileNotFoundError, 0]
        mock_log = MagicMock()

        check_nmap(mock_log)

        mock_log.logger.assert_any_call("warning", "Nmap is not installed.")
        mock_install_linux.assert_called_once_with(mock_log)

    @patch("modules.utils.check_call")
    @pytest.mark.parametrize(
        "distro_name, expected_command",
        [
            ("ubuntu", ["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"]),
            ("arch", ["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"]),
            ("fedora", ["/usr/bin/sudo", "dnf", "install", "nmap", "-y"]),
            ("centos", ["/usr/bin/sudo", "yum", "install", "nmap", "-y"]),
            ("opensuse", ["/usr/bin/sudo", "zypper", "install", "nmap", "--non-interactive"]),
        ]
    )
    def test_install_nmap_linux_distros(self, mock_check_call, distro_name, expected_command):
        """Verify the correct install command is used for various Linux distros."""
        with patch("modules.utils.distro", create=True) as mock_distro:
            mock_distro.id.return_value = distro_name
            mock_log = MagicMock()
            from modules.utils import install_nmap_linux
            install_nmap_linux(mock_log)
            mock_check_call.assert_called_once_with(expected_command, stderr=DEVNULL)

    @patch("modules.utils.check_call")
    @patch("builtins.input", return_value="1") # User selects 'apt-get'
    def test_install_nmap_linux_interactive_fallback(self, mock_input, mock_check_call):
        """Verify interactive fallback for unrecognized distros."""
        # Mock distro.id() to return an unknown distro
        with patch("modules.utils.distro", create=True) as mock_distro:
            # First call is unknown, second (recursive) call is the user's choice
            mock_distro.id.side_effect = ["unknown_distro", "ubuntu"]
            # The function will now call check_call once with the selected package manager

            from modules.utils import install_nmap_linux
            mock_log = MagicMock()
            install_nmap_linux(mock_log)

            # Verify it called the apt-get command after user input
            mock_check_call.assert_called_once_with(
                ["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"], stderr=DEVNULL
            )

    @patch("modules.utils.check_call")
    def test_install_nmap_windows(self, mock_check_call):
        """Verify the correct install command is used for Windows."""
        mock_log = MagicMock()
        from modules.utils import install_nmap_windows
        with pytest.raises(SystemExit):  # The function exits after logging
            install_nmap_windows(mock_log)
        mock_check_call.assert_called_once_with(
            ["C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", "winget", "install", "nmap", "--silent"], stderr=DEVNULL
        )

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS specific test")
    @patch("modules.utils.check_call")
    def test_install_nmap_mac(self, mock_check_call):
        """Verify the correct install command is used for macOS."""
        mock_log = MagicMock()
        from modules.utils import install_nmap_mac
        install_nmap_mac(mock_log)
        mock_check_call.assert_called_once_with(
            ["/usr/bin/sudo", "brew", "install", "nmap"], stderr=DEVNULL
        )


@pytest.mark.unit
class TestGetHostsToScan:
    """Tests for the GetHostsToScan function."""

    def test_get_hosts_no_hosts_found(self, mock_console):
        """Verify it raises SystemExit if no hosts are provided."""
        with pytest.raises(SystemExit):
            GetHostsToScan([], mock_console)

    def test_get_hosts_automatic_mode(self, mock_console, monkeypatch):
        """Verify it returns all hosts in automatic mode without asking for input."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", True)
        hosts = ["192.168.1.1", "192.168.1.2"]
        
        with patch("builtins.input") as mock_input:
            result = GetHostsToScan(hosts, mock_console)
            assert result == hosts
            mock_input.assert_not_called()

    @patch("builtins.input", return_value="all")
    def test_get_hosts_interactive_all(self, mock_input, mock_console, monkeypatch):
        """Verify it returns all hosts when the user enters 'all'."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        hosts = ["192.168.1.1", "192.168.1.2"]
        result = GetHostsToScan(hosts, mock_console)
        assert result == hosts

    @patch("builtins.input", return_value="0")
    def test_get_hosts_interactive_by_index(self, mock_input, mock_console, monkeypatch):
        """Verify it returns a single host when selected by index."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        hosts = ["192.168.1.1", "192.168.1.2"]
        result = GetHostsToScan(hosts, mock_console)
        assert result == ["192.168.1.1"]

    @patch("builtins.input", return_value="exit")
    def test_get_hosts_interactive_exit(self, mock_input, mock_console, monkeypatch):
        """Verify it raises SystemExit when the user enters 'exit'."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        hosts = ["192.168.1.1"]
        with pytest.raises(SystemExit):
            GetHostsToScan(hosts, mock_console)


@pytest.mark.unit
class TestInitArgsAPI:
    """Tests for the InitArgsAPI function."""

    @patch("modules.utils.read_file_any_encoding")
    def test_api_key_from_args(self, mock_read_file):
        """Verify API key is taken directly from args if provided."""
        args = argparse.Namespace(api="key_from_args")
        api_key = InitArgsAPI(args, MagicMock())
        assert api_key == "key_from_args"
        mock_read_file.assert_not_called()

    @patch("modules.utils.read_file_any_encoding", return_value="key_from_file")
    def test_api_key_from_file(self, mock_read_file):
        """Verify API key is read from api.txt if not in args."""
        args = argparse.Namespace(api=None)
        api_key = InitArgsAPI(args, MagicMock())
        assert api_key == "key_from_file"
        mock_read_file.assert_called_once_with("api.txt")

    @patch("modules.utils.read_file_any_encoding", side_effect=FileNotFoundError)
    def test_api_key_file_not_found(self, mock_read_file):
        """Verify a warning is logged if api.txt is not found."""
        args = argparse.Namespace(api=None)
        mock_log = MagicMock()
        api_key = InitArgsAPI(args, mock_log)
        assert api_key is None
        mock_log.logger.assert_called_with("warning", "No API key specified and no api.txt file found. Vulnerability detection is going to be slower! You can get your own NIST API key from https://nvd.nist.gov/developers/request-an-api-key")

    @patch("modules.utils.read_file_any_encoding", side_effect=PermissionError)
    def test_api_key_file_permission_error(self, mock_read_file):
        """Verify an error is logged if reading api.txt fails with PermissionError."""
        args = argparse.Namespace(api=None)
        mock_log = MagicMock()
        api_key = InitArgsAPI(args, mock_log)
        assert api_key is None
        mock_log.logger.assert_called_with("error", "Permission denied while trying to read api.txt!")


@pytest.mark.unit
class TestInitArgsMode:
    """Tests for the InitArgsMode function."""

    def test_init_args_mode_normal(self):
        """Verify Normal mode is selected by default."""
        args = argparse.Namespace(mode="normal")
        mode = InitArgsMode(args, MagicMock())
        assert mode == ScanMode.Normal

    def test_init_args_mode_noise(self):
        """Verify Noise mode is selected correctly."""
        args = argparse.Namespace(mode="noise")
        mode = InitArgsMode(args, MagicMock())
        assert mode == ScanMode.Noise

    @patch("modules.utils.is_root", return_value=True)
    def test_init_args_mode_evade_as_root(self, mock_is_root):
        """Verify Evade mode is selected when root."""
        args = argparse.Namespace(mode="evade")
        mode = InitArgsMode(args, MagicMock())
        assert mode == ScanMode.Evade

    @patch("modules.utils.is_root", return_value=False)
    def test_init_args_mode_evade_as_non_root(self, mock_is_root):
        """Verify Evade mode falls back to Normal when not root."""
        args = argparse.Namespace(mode="evade")
        mock_log = MagicMock()
        mode = InitArgsMode(args, mock_log)
        assert mode == ScanMode.Normal
        mock_log.logger.assert_called_with("error", "You must be root to use evasion mode! Switching back to normal mode ...")


@pytest.mark.unit
class TestReadFileAnyEncoding:
    """Tests for the read_file_any_encoding function."""

    def test_read_utf8_file(self, temp_file):
        """Verify it correctly reads a standard UTF-8 file."""
        content = "hello world"
        file_path = temp_file("test.txt", content)
        result = read_file_any_encoding(str(file_path))
        assert result == content

    def test_read_utf16_file(self, temp_dir):
        """Verify it falls back to and correctly reads a UTF-16 file."""
        content = "hello world"
        file_path = temp_dir / "test_utf16.txt"
        file_path.write_text(content, encoding="utf-16")
        result = read_file_any_encoding(str(file_path))
        assert result == content

    def test_read_latin1_file(self, temp_dir):
        """Verify it falls back to and correctly reads a Latin-1 file."""
        content = "hællø wørld"  # Characters valid in Latin-1
        file_path = temp_dir / "test_latin1.txt"
        # Write with an encoding that will fail UTF-8 and UTF-16
        file_path.write_text(content, encoding="latin-1")
        result = read_file_any_encoding(str(file_path))
        assert result == content

    def test_read_with_replacement(self, temp_dir):
        """Verify it falls back to replacing errors if all encodings fail."""
        # Create a file with a byte sequence invalid in UTF-8, UTF-16, and Latin-1
        invalid_bytes = b"\x81\x82"
        file_path = temp_dir / "test_invalid.txt"
        file_path.write_bytes(invalid_bytes)
        result = read_file_any_encoding(str(file_path))
        assert "" in result  # Check for the replacement character


@pytest.mark.unit
class TestCheckConnection:
    """Tests for the CheckConnection function."""

    @patch("modules.utils.get")
    def test_check_connection_success(self, mock_get):
        """Verify it returns True on a successful connection."""
        mock_log = MagicMock()
        result = CheckConnection(mock_log)
        assert result is True
        mock_log.logger.assert_not_called()

    @patch("modules.utils.get", side_effect=Exception("Test network error"))
    def test_check_connection_failure(self, mock_get):
        """Verify it returns False and logs errors on a failed connection."""
        mock_log = MagicMock()
        result = CheckConnection(mock_log)
        assert result is False
        mock_log.logger.assert_any_call("error", "Connection failed.")

        # Check that the exception itself was logged by inspecting the call arguments
        last_call_args, _ = mock_log.logger.call_args
        assert last_call_args[0] == "error"
        assert isinstance(last_call_args[1], Exception)
        assert str(last_call_args[1]) == "Test network error"


@pytest.mark.unit
class TestInitReportInteractive:
    """Tests for the interactive parts of the InitReport function."""

    @patch("builtins.input", side_effect=["user@example.com", "password", "to@example.com", "smtp.example.com", "465"])
    def test_init_report_email_interactive(self, mock_input, monkeypatch):
        """Verify email report object is created from user input."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        args = argparse.Namespace(report="email", report_email=None, report_email_password=None, report_email_to=None, report_email_from=None, report_email_server=None, report_email_server_port=None)
        
        method, report_obj = InitReport(args, MagicMock())

        assert method == ReportType.EMAIL
        assert report_obj.email == "user@example.com"
        assert report_obj.password == "password"
        assert report_obj.email_to == "to@example.com"

    @patch("builtins.input", return_value="https://example.com/webhook")
    def test_init_report_webhook_interactive(self, mock_input, monkeypatch):
        """Verify webhook URL is taken from user input."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        args = argparse.Namespace(report="webhook", report_webhook=None)

        method, webhook_url = InitReport(args, MagicMock())

        assert method == ReportType.WEBHOOK
        assert webhook_url == "https://example.com/webhook"


@pytest.mark.unit
class TestConfirmation:
    """Tests for the Confirmation function."""

    def test_confirmation_automatic_mode(self, monkeypatch):
        """Verify it returns True in automatic mode without asking for input."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", True)
        with patch("builtins.input") as mock_input:
            result = Confirmation("Test message")
            assert result is True
            mock_input.assert_not_called()

    @pytest.mark.parametrize("user_input, expected_result", [
        ("y", True), ("Y", True), ("", True), ("yes", True),
        ("n", False), ("N", False),
    ])
    @patch("builtins.input")
    def test_confirmation_interactive_mode(self, mock_input, monkeypatch, user_input, expected_result):
        """Verify it returns the correct boolean based on user input."""
        monkeypatch.setattr("modules.utils.DontAskForConfirmation", False)
        mock_input.return_value = user_input
        result = Confirmation("Test message")
        assert result is expected_result
        mock_input.assert_called_once_with("Test message")