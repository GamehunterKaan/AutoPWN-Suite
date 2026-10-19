# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path
from platform import system

from autopwn_suite.banners import print_banner
from autopwn_suite.subprocess_env import child_environment
from autopwn_suite.utils import is_root

INSTALL_DIR = "/opt/autopwn-suite"
SERVICE_FILE = "/etc/systemd/system/autopwn-daemon.service"


def _get_menu_choice(console, prompt: str, options: dict, default: str = None) -> str:
    """
    Displays a menu of options, gets user input, and validates it.

    Args:
        console: The Rich console object.
        prompt: The question to ask the user.
        options: A dictionary where keys are choices (e.g., '1') and
                 values are descriptions (e.g., 'Email').
        default: The default choice key to return if the user enters nothing.

    Returns:
        The key of the chosen option.
    """
    while True:
        console.print(prompt)
        for key, value in options.items():
            console.print(f"  [cyan]{key}[/cyan]. {value}")
        choice = console.input(f"Enter your choice ({'-'.join(options.keys())}): ").strip()
        if default and choice == "":
            return default
        if choice.lower() in options:  # the keys are digits or lowercase words, and InitArgsConf lowercases the type too
            return choice.lower()
        console.print(f"[red]Invalid choice. Please enter one of {list(options.keys())}.[/red]")

def _get_validated_int(console, prompt: str, default: int = None, minimum: int = None, maximum: int = None) -> int:
    """Gets and validates an integer input from the user. The bounds are the ones InitArgsConf enforces
    when the daemon reads the file back: a value it rejects would make the service exit and restart forever."""
    while True:
        user_input = console.input(prompt)
        if user_input == "" and default is not None:
            return default
        try:
            value = int(user_input)
        except ValueError:
            console.print("[red]Invalid input. Please enter a whole number.[/red]")
            continue
        if (minimum is None or value >= minimum) and (maximum is None or value <= maximum):
            return value
        limits = ([f"at least {minimum}"] if minimum is not None else []) + ([f"at most {maximum}"] if maximum is not None else [])
        console.print(f"[red]Out of range. Please enter a whole number that is {' and '.join(limits)}.[/red]")

def _get_validated_email(console, prompt: str, allow_empty: bool = False) -> str:
    """Gets and validates an email address from the user."""
    # A simple regex for email validation
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    while True:
        email = console.input(prompt)
        if allow_empty and email == "":
            return ""
        if email and re.match(email_regex, email):
            return email
        console.print("[red]Invalid email format. Please enter a valid email address.[/red]")

def _get_non_empty_input(console, prompt: str) -> str:
    """Gets a non-empty string input from the user."""
    while True:
        user_input = console.input(prompt).strip()
        if user_input:
            return user_input
        console.print("[red]This field cannot be empty.[/red]")

def _write_config(config, config_file):
    """Write the configuration for its owner only: it can hold an SMTP password, an NVD key and a webhook URL.
    The mode applies when the file is created, so it is never readable by others, not even briefly; Windows
    has no POSIX modes and ignores the group and other bits."""
    descriptor = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as configfile:
        config.write(configfile)

def CreateConfig(console, config_filename=""):
    console.print("Welcome to AutoPWN Suite Config Creator!")

    scan_interval = _get_validated_int(console, "Enter the scan interval in [cyan]seconds[/cyan] (Set to 0 for no interval - if not using as daemon): ", minimum=0)

    report_choice = _get_menu_choice(
        console,
        "Would you like to enable email or webhook notifications?",
        {"1": "Email", "2": "Webhook", "3": "None"}
    )

    if report_choice == "1":
        report_method = 'email'
        report_email = _get_validated_email(console, "Enter your [cyan]email address[/cyan]: ")
        report_email_password = _get_non_empty_input(console, "Enter your [cyan]email password[/cyan]: ")
        report_email_to = _get_validated_email(console, "Enter the email address to [cyan]send the report to[/cyan]: ")
        report_email_from = _get_validated_email(console, "Enter the email address to [cyan]send from[/cyan] (leave empty to use login email): ", allow_empty=True)
        report_email_server = _get_non_empty_input(console, "Enter the [cyan]email server[/cyan] to send the report from: ")
        report_email_server_port = _get_validated_int(console, "Enter the [cyan]email port[/cyan] to send the report from: ", minimum=1, maximum=65535)
        console.print("[green]Email notifications enabled.[/green]")
    elif report_choice == "2":
        report_method = 'webhook'
        report_webhook = _get_non_empty_input(console, "Enter your [cyan]webhook URL[/cyan]: ")
        console.print("[green]Webhook notifications enabled.[/green]")
    else: # choice == "3"
        report_method = 'none'
        console.print("[yellow]No notifications enabled.[/yellow]")

    target = console.input("Enter your [cyan]target[/cyan] (Leave empty for auto detection): ")
    host_file = console.input("Enter [cyan]host file[/cyan] (Leave empty for none - will override target): ")

    if target == "" and host_file == "":
        skip_discovery = False
    else:
        skip_discovery_input = console.input("Would you like to [cyan]skip discovery[/cyan]? (y/n) ")
        skip_discovery = skip_discovery_input.lower() == "y"

    api_key = console.input("Enter [cyan]API key[/cyan] (Leave empty for none): ")
    nmap_flags = console.input("Enter [cyan]nmap flags[/cyan] (Leave empty for none): ")
    speed = _get_validated_int(console, "Enter [cyan]speed[/cyan] (0-5, Leave empty for default): ", default=3, minimum=0, maximum=5)


    scan_type_choice = _get_menu_choice(
        console,
        "Pick [cyan]scan type[/cyan] for host discovery (Leave empty for ARP): ",
        {"1": "ARP", "2": "Ping"},
        default="1"
    )
    scan_type = "arp" if scan_type_choice == "1" else "ping"

    host_timeout = _get_validated_int(console, "Enter [cyan]host timeout[/cyan] (Leave empty for default): ", default=240, minimum=0)

    scan_method_choice = _get_menu_choice(
        console,
        "Enter [cyan]Scan Method[/cyan] (Leave empty for Normal): ",
        {"1": "Normal", "2": "Evade"},
        default="1"
    )
    scan_method = "normal" if scan_method_choice == "1" else "evade"

    output_folder = console.input("Enter [cyan]output folder[/cyan] (Leave empty for default): ")
    if output_folder == "":
        output_folder = "outputs"
    output_type = _get_menu_choice(
        console,
        "Enter [cyan]output type[/cyan] (Leave empty for html): ",
        {"html": "HTML report", "txt": "Plain text", "svg": "SVG image"},
        default="html"
    )

    console.print("Creating config file...")
    # InitArgsConf reads with interpolation disabled, so a '%' in a secret or URL must be written the same way.
    config = ConfigParser(interpolation=None)
    config['AUTOPWN'] = {
        'scan_interval': str(scan_interval),
        'target': target,
        'hostfile': host_file,
        'apikey': api_key,
        'scan_type': scan_type,
        'nmapflags': nmap_flags,
        'speed': str(speed),
        'auto': True,
        'skip_exploit_download': True,
        'mode': scan_method,
        'skip_discovery': str(skip_discovery),
        'output_folder': output_folder,
        'output_type': output_type,
        'host_timeout': str(host_timeout),
    }
    if report_method == 'email':
        config['REPORT'] = {
            'method': report_method,
            'email': report_email,
            'email_password': report_email_password,
            'email_to': report_email_to,
            'email_from': report_email_from or report_email,
            'email_server': report_email_server,
            'email_port': str(report_email_server_port)
        }
    elif report_method == 'webhook':
        config['REPORT'] = {
            'method': report_method,
            'webhook': report_webhook
        }


    if not config_filename:
        config_file = console.input("Enter [cyan]config file name[/cyan] (Leave empty for autopwn.conf): ")
        if config_file == "":
            config_file = "autopwn.conf"
    else:
        config_file = config_filename

    try:
        open(config_file, 'r', encoding='utf-8').close()
        overwrite_config = console.input(f"[yellow]Config file '{config_file}' already exists. Would you like to overwrite it?[/yellow] (y/n): ")
        if overwrite_config.lower() != 'y':
            console.print(f"[red]Config file '{config_file}' not overwritten.[/red]")
            return False
        else:
            os.remove(config_file)
            _write_config(config, config_file)

    except FileNotFoundError:
        _write_config(config, config_file)


    console.print(f"[green]Config file '{config_file}' created successfully![/green]")
    return True

def _root_controlled(path, lstat=os.lstat):
    """True when `path` and every parent directory, also after resolving symlinks, belong to root and
    cannot be changed by group or others. The daemon runs as root, so anything it executes or reads
    as configuration must not be replaceable by an unprivileged user."""
    for candidate in {Path(path), Path(os.path.realpath(path))}:
        for part in (candidate, *candidate.parents):
            info = lstat(part)
            if info.st_uid != 0:
                return False
            # A symlink's own mode bits are meaningless (always rwxrwxrwx); its owner is what counts.
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
    return True


def _service_files_are_root_controlled(install_path):
    """Everything the root service would start or read: the interpreter or binary, the package, the config directory."""
    locations = [sys.executable, install_path]
    if not getattr(sys, "frozen", False):
        locations.append(Path(__file__).resolve().parents[1])
    return all(_root_controlled(location) for location in locations)


def _exec_start(install_path):
    """Command line systemd runs: the interpreter that installed the service, or the frozen binary itself."""
    command = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "autopwn_suite"]
    command += ["-c", str(install_path / "autopwn-daemon.conf")]
    return " ".join(shlex.quote(part) for part in command)


def _service_can_import_package(install_path):
    """The unit runs `python -m autopwn_suite` with the install directory as its working directory. A source
    checkout started with `python autopwn.py` finds the package next to the script, which the service does not,
    and the service would then restart every 5 seconds without ever scanning. The probe starts the interpreter
    the way the unit does: from the install directory and without the caller's PYTHON* variables."""
    if getattr(sys, "frozen", False):
        return True  # the unit runs the binary itself
    probe = "import importlib.util, sys; sys.exit(importlib.util.find_spec('autopwn_suite') is None)"
    try:
        result = subprocess.run([sys.executable, "-E", "-c", probe], cwd=install_path, timeout=60,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _check_installable(console, install_path):
    """Create the install directory and refuse, with the reason, an installation the root service must not
    use. InstallDaemon runs it before asking any question, so a refusal does not follow a whole wizard that
    leaves its secret-bearing configuration behind."""
    try:
        if not install_path.exists():
            console.print(f"Creating install directory: {install_path}")
        install_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Failed to create install directory {install_path}: {e}[/red]")
        return False

    if not _service_files_are_root_controlled(install_path):
        console.print(
            "[red]Refusing to install the daemon: it runs as root, but the interpreter, the package or "
            f"{install_path} can be modified by another user.[/red]"
        )
        console.print("[yellow]Install AutoPWN Suite as root (for example with 'sudo bash install.sh' or a "
                      "standalone binary kept in a root-owned directory) and run --daemon-install from that "
                      "installation.[/yellow]")
        return False

    if not _service_can_import_package(install_path):
        console.print(
            "[red]Refusing to install the daemon: the service would run "
            f"'{_exec_start(install_path)}' from {install_path}, but this interpreter cannot import "
            "autopwn_suite from there.[/red]"
        )
        console.print("[yellow]A source checkout started with 'python autopwn.py' is not enough. Install "
                      "AutoPWN Suite as root (for example with 'sudo bash install.sh' or a standalone binary "
                      "kept in a root-owned directory) and run --daemon-install from that installation.[/yellow]")
        return False
    return True


def CopyFiles(console):
    DAEMON_INSTALL_PATH = Path(INSTALL_DIR)
    SERVICE_PATH = Path(SERVICE_FILE)
    LOG_PATH = Path("/var/log/autopwn-daemon.log")

    if not _check_installable(console, DAEMON_INSTALL_PATH):
        return

    # The service runs the installed program; only the configuration written by CreateConfig is placed here.
    src = Path.cwd() / "autopwn-daemon.conf"
    dst = DAEMON_INSTALL_PATH / "autopwn-daemon.conf"
    try:
        if not src.exists():
            console.print(f"[red]Configuration file {src} does not exist.[/red]")
            return
        if src.resolve() != dst.resolve():
            shutil.copy2(src, dst)
        # The configuration can hold the SMTP password, NVD key and webhook URL; the unit runs as root, so only root reads it.
        dst.chmod(0o600)
        console.print(f"[green]Configuration available at {dst}[/green]")
    except Exception as e:
        console.print(f"[red]Error copying {src} -> {dst}: {e}[/red]")
        return

    # Create log file
    try:
        if not LOG_PATH.exists():
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            LOG_PATH.touch()
            LOG_PATH.chmod(0o664)
            console.print(f"[green]Created log file: {LOG_PATH}[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: could not create log file {LOG_PATH}: {e}[/yellow]")

    # Write systemd service file — runs the installed program, restarts automatically
    service_content = f"""
[Unit]
Description=AutoPWN Suite Daemon
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={DAEMON_INSTALL_PATH}
ExecStart={_exec_start(DAEMON_INSTALL_PATH)}
Restart=always
RestartSec=5
KillMode=control-group
LimitNOFILE=65536
StandardOutput=append:{LOG_PATH}
StandardError=append:{LOG_PATH}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""

    try:
        console.print(f"Writing systemd service file to {SERVICE_PATH} ...")
        with open(SERVICE_PATH, "w", newline="\n") as fh:
            fh.write(service_content)
        console.print(f"[green]Service file written to {SERVICE_PATH}[/green]")
    except PermissionError:
        console.print(f"[red]Permission denied writing {SERVICE_PATH}. Run this script as root or use sudo.[/red]")
        console.print("[yellow]Here’s the unit content to save manually:[/yellow]")
        console.print(service_content)
        return

    # Reload, enable and (re)start the service. `enable --now` leaves a running service alone, so installing
    # again would keep the old program and configuration running; restart starts a stopped one as well.
    try:
        console.print("Reloading systemd daemon ...")
        subprocess.check_call(["systemctl", "daemon-reload"], env=child_environment())
        console.print("Enabling and starting service ...")
        subprocess.check_call(["systemctl", "enable", "autopwn-daemon.service"], env=child_environment())
        subprocess.check_call(["systemctl", "restart", "autopwn-daemon.service"], env=child_environment())
        console.print("[green]Service enabled and started successfully.[/green]")
        console.print("[blue]Check status with: sudo systemctl status autopwn-daemon.service[/blue]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Systemctl command failed: {e}[/red]")
        console.print("[yellow]You may need to run manually: sudo systemctl daemon-reload && sudo systemctl enable autopwn-daemon.service && sudo systemctl restart autopwn-daemon.service[/yellow]")
        return

    console.print("[green]AutoPWN daemon installation complete.[/green]")




def InstallDaemon(console):
    if not is_root() or not system().lower() == "linux":
        console.print("Daemon can only be installed on [cyan]Linux[/cyan] and as [cyan]root[/cyan]!")
        return
    print_banner(console)
    # Refuse an unusable installation first: the wizard below writes a configuration that can hold secrets.
    if not _check_installable(console, Path(INSTALL_DIR)):
        return
    if CreateConfig(console, "autopwn-daemon.conf") is False:
        return
    CopyFiles(console)


def _systemctl(console, *arguments):
    """Run systemctl; False (after saying why) when it is missing or reports an error."""
    try:
        result = subprocess.run(["systemctl", *arguments], env=child_environment(), stdin=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        console.print("[yellow]systemctl could not be run.[/yellow]")
        return False
    return result.returncode == 0


def UninstallDaemon(console):
    """Remove what InstallDaemon created: the service and its configuration, which can hold secrets. The
    program (install.sh, pipx, a binary), the log file and the scan outputs in /opt/autopwn-suite stay."""
    if not is_root() or not system().lower() == "linux":
        console.print("Daemon can only be removed on [cyan]Linux[/cyan] and as [cyan]root[/cyan]!")
        raise SystemExit(1)
    print_banner(console)
    service_path = Path(SERVICE_FILE)
    config_path = Path(INSTALL_DIR) / "autopwn-daemon.conf"

    console.print("Stopping and disabling the service ...")
    if not _systemctl(console, "disable", "--now", "autopwn-daemon.service"):
        console.print("[yellow]The service could not be stopped and disabled; it may not be installed. Continuing.[/yellow]")

    try:
        removed_unit = service_path.exists()
        service_path.unlink(missing_ok=True)
    except OSError as e:
        # Keep the configuration: a unit that is still there would start without it and restart forever.
        console.print(f"[red]Could not remove {service_path}: {e}[/red]")
        raise SystemExit(1) from e
    if removed_unit:
        console.print(f"[green]Removed {service_path}[/green]")
        if not _systemctl(console, "daemon-reload"):
            console.print("[yellow]systemd was not told about the removal; run: sudo systemctl daemon-reload[/yellow]")
    else:
        console.print(f"No service file at {service_path}.")

    try:
        removed_config = config_path.exists()
        config_path.unlink(missing_ok=True)
    except OSError as e:
        console.print(f"[red]Could not remove {config_path}: {e}[/red]")
        raise SystemExit(1) from e
    if removed_config:
        console.print(f"[green]Removed {config_path}[/green]")

    console.print("[green]AutoPWN daemon removed.[/green]")
    console.print(f"[blue]Left in place: the program, the log file /var/log/autopwn-daemon.log and the files in {INSTALL_DIR}. "
                  "Remove the program with 'sudo bash uninstall.sh', 'pipx uninstall autopwn-suite' or by deleting the binary.[/blue]")
