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
from autopwn_suite.utils import is_root


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
        if choice in options:
            return choice
        console.print(f"[red]Invalid choice. Please enter one of {list(options.keys())}.[/red]")

def _get_validated_int(console, prompt: str, default: int = None) -> int:
    """Gets and validates an integer input from the user."""
    while True:
        user_input = console.input(prompt)
        if user_input == "" and default is not None:
            return default
        try:
            return int(user_input)
        except ValueError:
            console.print("[red]Invalid input. Please enter a whole number.[/red]")

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

def CreateConfig(console, config_filename=""):
    console.print("Welcome to AutoPWN Suite Config Creator!")

    scan_interval = _get_validated_int(console, "Enter the scan interval in [cyan]seconds[/cyan] (Set to 0 for no interval - if not using as daemon): ")

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
        report_email_server_port = _get_validated_int(console, "Enter the [cyan]email port[/cyan] to send the report from: ")
        console.print("[green]Email notifications enabled.[/green]")
    elif report_choice == "2":
        report_method = 'webhook'
        report_webhook = console.input("Enter your [cyan]webhook URL[/cyan]: ")
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
    speed = _get_validated_int(console, "Enter [cyan]speed[/cyan] (0-5, Leave empty for default): ", default=3)


    scan_type_choice = _get_menu_choice(
        console,
        "Pick [cyan]scan type[/cyan] for host discovery (Leave empty for ARP): ",
        {"1": "ARP", "2": "Ping"},
        default="1"
    )
    scan_type = "arp" if scan_type_choice == "1" else "ping"

    host_timeout = _get_validated_int(console, "Enter [cyan]host timeout[/cyan] (Leave empty for default): ", default=240)

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
    output_type = console.input("Enter [cyan]output type[/cyan] (Leave empty for html): ")
    if output_type == "":
        output_type = "html"

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
            with open(config_file, 'w', encoding='utf-8') as configfile:
                config.write(configfile)

    except FileNotFoundError:
        with open(config_file, 'w', encoding='utf-8') as configfile:
            config.write(configfile)


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


def CopyFiles(console):
    DAEMON_INSTALL_PATH = Path("/opt/autopwn-suite")
    SERVICE_PATH = Path("/etc/systemd/system/autopwn-daemon.service")
    LOG_PATH = Path("/var/log/autopwn-daemon.log")

    try:
        console.print(f"Creating install directory: {DAEMON_INSTALL_PATH}")
        DAEMON_INSTALL_PATH.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Failed to create install directory {DAEMON_INSTALL_PATH}: {e}[/red]")
        return

    if not _service_files_are_root_controlled(DAEMON_INSTALL_PATH):
        console.print(
            "[red]Refusing to install the daemon: it runs as root, but the interpreter, the package or "
            f"{DAEMON_INSTALL_PATH} can be modified by another user.[/red]"
        )
        console.print("[yellow]Install AutoPWN Suite as root (for example with 'sudo bash install.sh' or a "
                      "standalone binary kept in a root-owned directory) and run --daemon-install from that "
                      "installation.[/yellow]")
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

    # Reload, enable and start the service
    try:
        console.print("Reloading systemd daemon ...")
        subprocess.check_call(["systemctl", "daemon-reload"])
        console.print("Enabling and starting service ...")
        subprocess.check_call(["systemctl", "enable", "--now", "autopwn-daemon.service"])
        console.print("[green]Service enabled and started successfully.[/green]")
        console.print("[blue]Check status with: sudo systemctl status autopwn-daemon.service[/blue]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Systemctl command failed: {e}[/red]")
        console.print("[yellow]You may need to run manually: sudo systemctl daemon-reload && sudo systemctl enable --now autopwn-daemon.service[/yellow]")
        return

    console.print("[green]AutoPWN daemon installation complete.[/green]")




def InstallDaemon(console):
    if not is_root() or not system().lower() == "linux":
        console.print("Daemon can only be installed on [cyan]Linux[/cyan] and as [cyan]root[/cyan]!")
        return
    print_banner(console)
    if CreateConfig(console, "autopwn-daemon.conf") is False:
        return
    CopyFiles(console)


def UninstallDaemon(console):
    print_banner(console)
