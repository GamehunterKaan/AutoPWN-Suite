try:
    from os import getuid

    import distro
except ImportError:
    from ctypes import windll
import os
from argparse import ArgumentParser
from configparser import ConfigParser, Error as ConfigError
from datetime import datetime
from enum import Enum
from os import get_terminal_size
from platform import platform, system
from re import search
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import DEVNULL, PIPE, CalledProcessError, Popen, check_call
from sys import platform as sys_platform

from requests import get
from rich.text import Text

from modules.report import ReportMail, ReportType


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


DontAskForConfirmation = False

class ScanType(Enum):
    Ping = 0
    ARP = 1


def cli():
    argparser = ArgumentParser(
        description="AutoPWN Suite | A project for scanning "
        + "vulnerabilities and exploiting systems automatically."
    )
    argparser.add_argument(
        "-v", "--version", help="Print version and exit.", action="store_true"
    )
    argparser.add_argument(
        "-y",
        "--yes-please",
        help="Don't ask for anything. (Full automatic mode)",
        action="store_true",
        required=False,
        default=False,
    )
    argparser.add_argument(
        "-c",
        "--config",
        help="Specify a config file to use. (Default : None)",
        default=None,
        required=False,
        metavar="CONFIG",
        type=str,
    )
    argparser.add_argument(
        "-nc",
        "--no-color",
        help="Disable colors.",
        default=False,
        required=False,
        action="store_true",
    )
    argparser.add_argument(
        "--daemon-install",
        help="Install the AutoPWN Suite daemon.",
        default=False,
        required=False,
        action="store_true",
    )
    argparser.add_argument(
        "--daemon-uninstall",
        help="Uninstall the AutoPWN Suite daemon.",
        default=False,
        required=False,
        action="store_true",
    )
    argparser.add_argument(
        "--create-config",
        help="Create a config file.",
        default=False,
        required=False,
        action="store_true",
    )
    scanargs = argparser.add_argument_group("Scanning", "Options for scanning")
    scanargs.add_argument(
        "-t",
        "--target",
        help=(
            "Target range to scan. This argument overwrites the"
            + " hostfile argument. (192.168.0.1 or 192.168.0.0/24)"
        ),
        type=str,
        required=False,
        default=None,
    )
    scanargs.add_argument(
        "-hf",
        "--host-file",
        help="File containing a list of hosts to scan.",
        type=str,
        required=False,
        default=None,
    )
    scanargs.add_argument(
        "-sd",
        "--skip-discovery",
        help="Skips the host discovery phase.",
        required=False,
        default=False,
        action="store_true",
    )
    scanargs.add_argument(
        "-st",
        "--scan-type",
        help="Scan type.",
        type=str,
        required=False,
        default=None,
        choices=["arp", "ping"],
    )
    scanargs.add_argument(
        "-nf",
        "--nmap-flags",
        help=(
            "Custom nmap flags to use for portscan."
            + ' (Has to be specified like : -nf="-O")'
        ),
        default="",
        type=str,
        required=False,
    )
    scanargs.add_argument(
        "-s",
        "--speed",
        help="Scan speed. (Default : 3)",
        default=3,
        type=int,
        required=False,
        choices=range(0, 6),
    )
    scanargs.add_argument(
        "-ht",
        "--host-timeout",
        help="Timeout for every host. (Default :240)",
        default=240,
        type=int,
        required=False,
    )
    scanargs.add_argument(
        "-a",
        "--api",
        help=(
            "Specify API key for vulnerability detection "
            + "for faster scanning. (Default : None)"
        ),
        default=None,
        type=str,
        required=False,
    )
    scanargs.add_argument(
        "-m",
        "--mode",
        help="Scan mode.",
        default="normal",
        type=str,
        required=False,
        choices=["evade", "noise", "normal"],
    )
    scanargs.add_argument(
        "-nt",
        "--noise-timeout",
        help="Noise mode timeout.",
        default=None,
        type=int,
        required=False,
        metavar="TIMEOUT",
    )
    scanargs.add_argument(
        "-sed",
        "--skip-exploit-download",
        help="Skip downloading exploits.",
        default=False,
        required=False,
        action="store_true",
    )

    reportargs = argparser.add_argument_group("Reporting", "Options for reporting")
    reportargs.add_argument(
        "-o",
        "--output",
        help="Output file name. Overrides output-folder.",
        default=None,
        type=str,
        required=False,
    )
    reportargs.add_argument(
        "-ot",
        "--output-type",
        help="Output file type. (Default : html)",
        default="html",
        type=str,
        required=False,
        choices=["html", "txt", "svg"],
    )
    reportargs.add_argument(
        "-of",
        "--output-folder",
        help="Output file folder. (Default : outputs/)",
        default="outputs",
        type=str,
        required=False,
    )
    reportargs.add_argument(
        "-rp",
        "--report",
        help="Report sending method.",
        type=str,
        required=False,
        default=None,
        choices=["email", "webhook"],
    )
    reportargs.add_argument(
        "-rpe",
        "--report-email",
        help="Email address to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpep",
        "--report-email-password",
        help="Password of the email report is going to be sent from.",
        type=str,
        required=False,
        default=None,
        metavar="PASSWORD",
    )
    reportargs.add_argument(
        "-rpet",
        "--report-email-to",
        help="Email address to send report to.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpef",
        "--report-email-from",
        help="Email to send from.",
        type=str,
        required=False,
        default=None,
        metavar="EMAIL",
    )
    reportargs.add_argument(
        "-rpes",
        "--report-email-server",
        help="Email server to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="SERVER",
    )
    reportargs.add_argument(
        "-rpesp",
        "--report-email-server-port",
        help="Port of the email server.",
        type=int,
        required=False,
        default=None,
        metavar="PORT",
    )
    reportargs.add_argument(
        "-rpw",
        "--report-webhook",
        help="Webhook to use for sending report.",
        type=str,
        required=False,
        default=None,
        metavar="WEBHOOK",
    )

    webuiargs = argparser.add_argument_group("Web UI", "Browser-based dashboard for controlling scans")
    webuiargs.add_argument(
        "--web",
        help="Start the web UI dashboard (scans are launched from the browser).",
        default=False,
        required=False,
        action="store_true",
    )
    webuiargs.add_argument(
        "--web-host",
        help="Web UI bind address. (Default: 0.0.0.0, env: AUTOPWN_WEB_HOST)",
        default=os.environ.get("AUTOPWN_WEB_HOST", "0.0.0.0"),
        type=str,
        required=False,
        metavar="HOST",
    )
    webuiargs.add_argument(
        "--web-port",
        help="Web UI port. (Default: 8080, env: AUTOPWN_WEB_PORT)",
        default=int(os.environ.get("AUTOPWN_WEB_PORT", "8080")),
        type=int,
        required=False,
        metavar="PORT",
    )

    return argparser.parse_args()


class fake_logger:
    def logger(self, exception_: str, message: str):
        pass


def is_root() -> bool:
    try:
        return getuid() == 0
    except Exception as e:
        return windll.shell32.IsUserAnAdmin() == 1


def GetIpAdress() -> str:
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = s.getsockname()[0]
    return PrivateIPAdress


def DetectIPRange() -> str:
    net_dict = {
        "255.255.255.255": 32,
        "255.255.255.254": 31,
        "255.255.255.252": 30,
        "255.255.255.248": 29,
        "255.255.255.240": 28,
        "255.255.255.224": 27,
        "255.255.255.192": 26,
        "255.255.255.128": 25,
        "255.255.255.0": 24,
        "255.255.254.0": 23,
        "255.255.252.0": 22,
        "255.255.248.0": 21,
        "255.255.240.0": 20,
        "255.255.224.0": 19,
        "255.255.192.0": 18,
        "255.255.128.0": 17,
        "255.255.0.0": 16,
    }
    ip = GetIpAdress()
    if system().lower() == "windows":
        proc = Popen("ipconfig", stdout=PIPE)
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        mask = (
            proc.stdout.readline().rstrip().split(b":")[-1].replace(b" ", b"").decode()
        )
        net_range = f"{ip}/{net_dict[mask]}"
    else:
        proc = Popen(["ip", "-o", "-f", "inet", "addr", "show"], stdout=PIPE)
        regex = rf"\b{ip}/\b([0-9]|[12][0-9]|3[0-2])\b"
        cmd_output = proc.stdout.read().decode()
        net_range = search(regex, cmd_output).group()
    return net_range


def InitAutomation(args) -> None:
    global DontAskForConfirmation
    if args.yes_please:
        DontAskForConfirmation = True
    else:
        DontAskForConfirmation = False


def read_file_any_encoding(filepath: str) -> str:
    # Try UTF-8 first
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.readline().strip("\n")
    except UnicodeError:
        pass
    # Try UTF-16 variations
    try:
        with open(filepath, "r", encoding="utf-16") as f:
            return f.readline().strip("\n")
    except UnicodeError:
        try:
            with open(filepath, "r", encoding="utf-16-le") as f:
                return f.readline().strip("\n")
        except UnicodeError:
            pass
    # Try latin-1 (very permissive)
    try:
        with open(filepath, "r", encoding="latin-1") as f:
            return f.readline().strip("\n")
    except Exception:
        pass
    # As a last resort, replace undecodable characters
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return f.readline().strip("\n")


def InitArgsAPI(args, log) -> str:
    if args.api:
        apiKey = args.api
    else:
        apiKey = None
        try:
            apiKey = read_file_any_encoding("api.txt")
        except FileNotFoundError:
            log.logger(
                "warning",
                "No API key specified and no api.txt file found. "
                + "Vulnerability detection is going to be slower! "
                + "You can get your own NIST API key from "
                + "https://nvd.nist.gov/developers/request-an-api-key",
            )
        except PermissionError:
            log.logger("error", "Permission denied while trying to read api.txt!")
        except Exception as e:
            log.logger("error", f"Error reading api.txt: {e}")

    return apiKey


def InitArgsScanType(args, log) -> ScanType:
    scantype = ScanType.Ping
    if args.scan_type == "arp":
        if is_root():
            scantype = ScanType.ARP
        else:
            log.logger(
                "warning",
                "You need to be root in order to run arp scan.\n"
                + "Changed scan mode to Ping Scan.",
            )
    elif args.scan_type is None or args.scan_type == "":
        if is_root():
            scantype = ScanType.ARP

    return scantype


def InitArgsTarget(args, log):
    if args.target:
        target = args.target
    else:
        if args.host_file:
            # read targets from host file and insert all of them into an array
            try:
                with open(args.host_file, "r", encoding="utf-8-sig") as target_file:
                    target = [line.strip() for line in target_file.read().splitlines()
                              if line.strip() and not line.lstrip().startswith("#")]
            except FileNotFoundError:
                log.logger("error", "Host file not found!")
            except PermissionError:
                log.logger("error", "Permission denied while trying to read host file!")
            except Exception:
                log.logger("error", "Unknown error while trying to read host file!")
            else:
                if not target:
                    log.logger("error", "Host file contains no targets!")
                    raise SystemExit(1)
                return target

            # An explicitly requested host list must not silently turn into a
            # scan of an automatically detected network after a read failure.
            raise SystemExit(1)
        else:
            if DontAskForConfirmation:
                try:
                    target = DetectIPRange()
                except Exception as e:
                    log.logger("error", e)
                    target = input("Enter target range to scan : ")
            else:
                try:
                    target = input("Enter target range to scan : ")
                except KeyboardInterrupt:
                    raise SystemExit("Ctrl+C pressed. Exiting.")

    return target


def InitArgsMode(args, log) -> ScanMode:
    scanmode = ScanMode.Normal

    if args.mode == "evade":
        if is_root():
            scanmode = ScanMode.Evade
            log.logger("info", "Evasion mode enabled!")
        else:
            log.logger(
                "error",
                "You must be root to use evasion mode!"
                + " Switching back to normal mode ...",
            )
    elif args.mode == "noise":
        scanmode = ScanMode.Noise
        log.logger("info", "Noise mode enabled!")

    return scanmode


def InitReport(args, log) -> tuple:
    if not args.report:
        return ReportType.NONE, None

    if args.report == "email":
        Method = ReportType.EMAIL
        if args.report_email:
            ReportEmail = args.report_email
        else:
            ReportEmail = input("Enter your email address : ")

        if args.report_email_password:
            ReportMailPassword = args.report_email_password
        else:
            ReportMailPassword = input("Enter your email password : ")

        if args.report_email_to:
            ReportMailTo = args.report_email_to
        else:
            ReportMailTo = input("Enter the email address to send the report to : ")

        if args.report_email_from:
            ReportMailFrom = args.report_email_from
        else:
            ReportMailFrom = ReportEmail

        if args.report_email_server:
            ReportMailServer = args.report_email_server
        else:
            ReportMailServer = input(
                "Enter the email server to send the report from : "
            )
            if ReportMailServer == "smtp.gmail.com":
                log.logger(
                    "warning", "Google no longer supports sending mails via SMTP."
                )
                return ReportType.NONE, None

        if args.report_email_server_port:
            ReportMailPort = args.report_email_server_port
        else:
            while True:
                ReportMailPort = input(
                    "Enter the email port to send the report from : "
                )
                try:
                    int(ReportMailPort)
                    break
                except ValueError:
                    log.logger("error", "Invalid port number!")

        EmailObj = ReportMail(
            ReportEmail,
            ReportMailPassword,
            ReportMailTo,
            ReportMailFrom,
            ReportMailServer,
            int(ReportMailPort),
        )

        return Method, EmailObj

    elif args.report == "webhook":
        Method = ReportType.WEBHOOK
        if args.report_webhook:
            Webhook = args.report_webhook
        else:
            Webhook = input("Enter your webhook URL : ")

        return Method, Webhook


def Confirmation(message) -> bool:
    if DontAskForConfirmation:
        return True

    confirmation = input(message)
    return confirmation.lower() != "n"


def UserConfirmation(args) -> tuple[bool, bool, bool]:
    portscan = Confirmation("Do you want to scan ports? [Y/n] : ")
    if not portscan:
        return False, False, False

    vulnscan = Confirmation("Do you want to scan for vulnerabilities? [Y/n] : ")
    if not vulnscan:
        return True, False, False

    if args.skip_exploit_download:
        return True, True, False
    else:
        downloadexploits = Confirmation("Do you want to download exploits? [Y/n] : ")
    
    return portscan, vulnscan, downloadexploits


def WebScan() -> bool:
    return Confirmation("Do you want to scan for web vulnerabilities? [Y/n] : ")


def GetHostsToScan(hosts, console) -> list[str]:
    if len(hosts) == 0:
        raise SystemExit(
            "No hosts found! {time} - Scan completed.".format(
                time=datetime.now().strftime("%b %d %Y %H:%M:%S")
            )
        )

    index = 0
    for host in hosts:
        if not len(host) % 2 == 0:
            host += " "

        msg = Text.assemble(("[", "red"), (str(index), "cyan"), ("] ", "red"), host)

        console.print(msg, justify="center")

        index += 1

    if DontAskForConfirmation:
        return hosts

    console.print(
        "\n[yellow]Enter the index number of the "
        + "host you would like to enumurate further.\n"
        + "Enter 'all' to enumurate all hosts.\n"
        + "Enter 'exit' to exit [/yellow]"
    )

    while True:
        host = input(f"────> ")
        Targets = hosts

        if host in hosts:
            Targets = [host]
            break
        else:
            if host == "all" or host == "":
                break
            elif host == "exit":
                raise SystemExit(
                    "{time} - Scan completed.".format(
                        time=datetime.now().strftime("%b %d %Y %H:%M:%S")
                    )
                )
            else:
                try:
                    index = int(host)
                except ValueError:
                    console.print(
                        "Please enter a valid host number or 'all' " + "or 'exit'",
                        style="red",
                    )
                    continue
                if 0 <= index < len(hosts):
                    Targets = [hosts[index]]
                    break
                else:
                    console.print(
                        "Please enter a valid host number or 'all' " + "or 'exit'",
                        style="red",
                    )

    return Targets


def InitArgsConf(args, log) -> None:
    if not args.config:
        return

    try:
        # Secrets, paths, Nmap flags and webhook URLs are case sensitive and may
        # contain literal percent signs. Only enum values should be normalized.
        config = ConfigParser(interpolation=None)
        if not config.read(args.config, encoding="utf-8-sig"):
            raise FileNotFoundError(args.config)

        options = {
            "AUTOPWN": [
                ("scan_interval", "scan_interval", "int"),
                ("target", "target", "text"),
                ("hostfile", "host_file", "text"),
                ("scantype", "scan_type", "lower"),
                ("scan_type", "scan_type", "lower"),
                ("nmapflags", "nmap_flags", "text"),
                ("speed", "speed", "int"),
                ("apikey", "api", "text"),
                ("auto", "yes_please", "bool"),
                ("skip_exploit_download", "skip_exploit_download", "bool"),
                ("skip_discovery", "skip_discovery", "bool"),
                ("mode", "mode", "lower"),
                ("noisetimeout", "noise_timeout", "int"),
                ("host_timeout", "host_timeout", "int"),
                ("output_folder", "output_folder", "text"),
                ("output_type", "output_type", "lower"),
            ],
            "REPORT": [
                ("output", "output", "text"),
                ("outputtype", "output_type", "lower"),
                ("outputfolder", "output_folder", "text"),
                ("method", "report", "lower"),
                ("email", "report_email", "text"),
                ("email_password", "report_email_password", "text"),
                ("email_to", "report_email_to", "text"),
                ("email_from", "report_email_from", "text"),
                ("email_server", "report_email_server", "text"),
                ("email_port", "report_email_server_port", "int"),
                ("webhook", "report_webhook", "text"),
            ],
            "WEBUI": [
                ("enabled", "web", "bool"),
                ("host", "web_host", "text"),
                ("port", "web_port", "int"),
            ],
        }
        for section, entries in options.items():
            for option, attribute, kind in entries:
                if not config.has_option(section, option):
                    continue
                if kind == "bool":
                    value = config.getboolean(section, option)
                elif kind == "int":
                    value = config.getint(section, option)
                else:
                    value = config.get(section, option)
                    if kind == "lower":
                        value = value.strip().lower()
                if attribute == "speed" and value not in range(6):
                    raise ValueError("speed must be between 0 and 5")
                if attribute in ("scan_interval", "host_timeout", "noise_timeout") and value < 0:
                    raise ValueError(f"{option} must not be negative")
                if attribute in ("report_email_server_port", "web_port") and not 1 <= value <= 65535:
                    raise ValueError(f"{option} must be between 1 and 65535")
                choices = {
                    "scan_type": ("", "arp", "ping"),
                    "mode": ("normal", "noise", "evade"),
                    "output_type": ("html", "txt", "svg"),
                    "report": ("", "none", "email", "webhook"),
                }
                if attribute in choices and value not in choices[attribute]:
                    raise ValueError(f"Invalid value for {section}.{option}")
                if attribute == "report" and value in ("", "none"):
                    value = None
                setattr(args, attribute, value)

    except FileNotFoundError:
        log.logger("error", "Config file not found!")
        raise SystemExit
    except PermissionError:
        log.logger("error", "Permission denied while trying to read config file!")
        raise SystemExit
    except (ConfigError, ValueError) as error:
        log.logger("error", f"Invalid config file: {error}")
        raise SystemExit(1)


def install_nmap_linux(log) -> None:
    distro_ = distro.id().lower()
    try:
        if distro_ in [
            "ubuntu",
            "debian",
            "linuxmint",
            "raspbian",
            "kali",
            "parrot",
        ]:
            check_call(
                ["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"],
                stderr=DEVNULL,
            )
        elif distro_ in ["arch", "manjaro"]:
            check_call(
                ["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"],
                stderr=DEVNULL,
            )
        elif distro_ in ["fedora", "oracle"]:
            check_call(
                ["/usr/bin/sudo", "dnf", "install", "nmap", "-y"], stderr=DEVNULL
            )
        elif distro_ in ["rhel", "centos"]:
            check_call(
                ["/usr/bin/sudo", "yum", "install", "nmap", "-y"], stderr=DEVNULL
            )
        elif distro_ in ["sles", "opensuse"]:
            check_call(
                ["/usr/bin/sudo", "zypper", "install", "nmap", "--non-interactive"],
                stderr=DEVNULL,
            )
        else:
            raise CalledProcessError(1, "cmd")

    except CalledProcessError:
        _distro_choice_ = input(
            "Cannot recognize the needed package manager for your "
            + f"system that seems to be running in: {distro_} and "
            + f"{sys_platform}, {platform()}, kindly select the "
            + "correct package manager below to proceed to the "
            + "installation, else, select, n.\n\t0 Abort installation\n"
            + "\t1 apt-get\n\t2 dnf\n\t3 yum\n\t4 pacman\n\t5 zypper."
            + "\nSelect option [0-5] >"
        )
        pkg_cmds = {
            "1": ["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"],
            "2": ["/usr/bin/sudo", "dnf", "install", "nmap", "-y"],
            "3": ["/usr/bin/sudo", "yum", "install", "nmap", "-y"],
            "4": ["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"],
            "5": ["/usr/bin/sudo", "zypper", "install", "nmap", "--non-interactive"],
        }
        if _distro_choice_ in pkg_cmds:
            try:
                check_call(pkg_cmds[_distro_choice_], stderr=DEVNULL)
            except CalledProcessError:
                log.logger("error", "Couldn't install nmap (Linux)")
        else:
            log.logger("error", "Couldn't install nmap (Linux)")


def install_nmap_windows(log) -> None:
    try:
        check_call(
            [
                "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "winget",
                "install",
                "nmap",
                "--silent",
            ],
            stderr=DEVNULL,
        )
        log.logger("warning", "Nmap is installed but shell restart is required.")
        raise SystemExit
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Windows)")
        raise SystemExit


def install_nmap_mac(log) -> None:
    try:
        check_call(["/usr/bin/sudo", "brew", "install", "nmap"], stderr=DEVNULL)
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Mac)")


def check_nmap(log) -> None:
    try:
        check_call(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)
    except (CalledProcessError, FileNotFoundError):
        log.logger("warning", "Nmap is not installed.")
        if DontAskForConfirmation:
            auto_install = True
        else:
            auto_install = (
                input(f"Install Nmap on your system ({system()})? ").lower() != "n"
            )
        if auto_install:
            platform_ = system().lower()
            if platform_ == "linux":
                install_nmap_linux(log)
            elif platform_ == "windows":
                install_nmap_windows(log)
            elif platform_ == "darwin":
                install_nmap_mac(log)
            else:
                raise SystemExit("Unknown OS! Auto installation not supported!")
        else:
            log.logger("error", "Denied permission to install Nmap.")
            raise SystemExit


def ParamPrint(
    args,
    targetarg: str,
    scantype_name: ScanType,
    scanmode_name: ScanMode,
    apiKey: str,
    console,
    log,
) -> None:

    if not is_root():
        log.logger(
            "warning",
            "It is recommended to run this script as root"
            + " since it is more silent and accurate.",
        )

    term_width = get_terminal_width()
    
    msg = (
        "\n┌─[ Scanning with the following parameters ]\n"
        + f"├"
        + "─" * (term_width - 1)
        + "\n"
        + f"│\tTarget : {targetarg}\n"
        + f"│\t{'Output file' if args.output else 'Output folder'} : [yellow]{args.output if args.output else args.output_folder}[/yellow]\n"
        + f"│\tAPI Key : {type(apiKey) == str}\n"
        + f"│\tAutomatic : {DontAskForConfirmation}\n"
    )

    if args.skip_discovery:
        msg += f"│\tSkip discovery: True\n"

    if args.host_file:
        msg += f"│\tHostfile: {args.host_file}\n"

    if not args.host_timeout == 240:
        msg += f"│\tHost timeout: {args.host_timeout}\n"

    if scanmode_name == ScanMode.Normal:
        msg += (
            f"│\tScan type : [red]{scantype_name.name}[/red]\n"
            + f"│\tScan speed : {args.speed}\n"
        )
    elif scanmode_name == ScanMode.Evade:
        msg += (
            f"│\tScan mode : {scanmode_name.name}\n"
            + f"│\tScan type : [red]{scantype_name.name}[/red]\n"
            + f"│\tScan speed : {args.speed}\n"
        )
    elif scanmode_name == ScanMode.Noise:
        msg += f"│\tScan mode : {scanmode_name.name}\n"

    if not args.nmap_flags == None and not args.nmap_flags == "":
        msg += f"│\tNmap flags : [blue]{args.nmap_flags}[/blue]\n"

    if args.report:
        msg += f"│\tReporting method : {args.report}\n"

    msg += "└" + "─" * (term_width - 1)

    console.print(msg)


def CheckConnection(log) -> bool:
    try:
        get("https://google.com", timeout=10)
    except Exception as e:
        log.logger("error", "Connection failed.")
        log.logger("error", e)
        return False
    else:
        return True




def SaveOutput(console, out_type, output_file, output_folder, target) -> None:
    if output_file:
        # User provided a path, use it directly
        full_path = output_file
        # Ensure the directory exists
        os.makedirs(os.path.dirname(full_path) or '.', exist_ok=True)
    elif output_folder:
        os.makedirs(output_folder, exist_ok=True)
        base_name = 'multihost' if isinstance(target, list) else str(target).replace('/', '_')
        sanitized_name = base_name.replace('\\', '_')
        full_path = os.path.join(output_folder, f"{datetime.now().strftime('%Y-%m-%d')}_{sanitized_name}")
    else:
        # No path provided, create a default one in the 'outputs' directory
        output_dir = "outputs"
        os.makedirs(output_dir, exist_ok=True)
        base_name = 'multihost' if isinstance(target, list) else str(target).replace('/', '_')
        sanitized_name = base_name.replace('\\', '_')
        full_path = os.path.join(output_dir, f"{datetime.now().strftime('%Y-%m-%d')}_{sanitized_name}")

    # Ensure the file has the correct extension
    if not full_path.endswith(f".{out_type}"):
        full_path += f".{out_type}"

    if out_type == "html":
        console.save_html(full_path)
    elif out_type == "svg":
        console.save_svg(full_path)
    elif out_type == "txt":
        console.save_text(full_path)

    console.print(f"Report saved to [cyan]{full_path}[/cyan]")



def get_terminal_width() -> int:
    try:
        width, _ = get_terminal_size()
    except OSError:
        width = 80

    if system().lower() == "windows":
        width -= 1

    return width
