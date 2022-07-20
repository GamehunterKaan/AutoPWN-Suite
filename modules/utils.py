try:
    from os import getuid

    import distro
except ImportError:
    from ctypes import windll

from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime
from enum import Enum
from os import get_terminal_size
from platform import platform, system
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import DEVNULL, CalledProcessError, check_call
from sys import platform as sys_platform

from requests import get
from rich.text import Text

from modules.report import ReportMail, ReportType


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


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

    reportargs = argparser.add_argument_group("Reporting", "Options for reporting")
    reportargs.add_argument(
        "-o",
        "--output",
        help="Output file name. (Default : autopwn.log)",
        default="autopwn",
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

    return argparser.parse_args()


class fake_logger:
    def logger(self, exception_: str, message: str):
        pass


def is_root():
    try:
        return getuid() == 0
    except Exception as e:
        return windll.shell32.IsUserAnAdmin() == 1


def GetIpAdress() -> str:
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = str(s.getsockname()[0])
    return PrivateIPAdress


def DetectIPRange() -> str:
    PrivateIPAdress = GetIpAdress().split(".")
    target = (
        f"{PrivateIPAdress[0]}."
        + f"{PrivateIPAdress[1]}."
        + f"{PrivateIPAdress[2]}.0/24"
    )
    return target


def InitAutomation(args) -> None:
    global DontAskForConfirmation
    if args.yes_please:
        DontAskForConfirmation = True
    else:
        DontAskForConfirmation = False


def InitArgsAPI(args, log) -> str:
    if args.api:
        apiKey = args.api

    else:
        apiKey = None
        try:
            with open("api.txt", "r", encoding="utf-8") as f:
                apiKey = f.readline().strip("\n")
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

    return apiKey


def InitArgsScanType(args, log):
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
                with open(args.host_file, "r", encoding="utf-8") as target_file:
                    target = target_file.read().splitlines()
            except FileNotFoundError:
                log.logger("error", "Host file not found!")
            except PermissionError:
                log.logger("error", "Permission denied while trying to read host file!")
            except Exception:
                log.logger("error", "Unknown error while trying to read host file!")
            else:
                return target

            target = DetectIPRange()
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


def InitArgsMode(args, log):
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


def InitReport(args, log):
    if not args.report:
        return ReportType.NONE, None

    if args.report == "email":
        Method = ReportType.EMAIL
        if args.reportemail:
            ReportEmail = args.reportemail
        else:
            ReportEmail = input("Enter your email address : ")

        if args.reportemailpassword:
            ReportMailPassword = args.reportemailpassword
        else:
            ReportMailPassword = input("Enter your email password : ")

        if args.reportemailto:
            ReportMailTo = args.reportemailto
        else:
            ReportMailTo = input("Enter the email address to send the report to : ")

        if args.reportemailfrom:
            ReportMailFrom = args.reportemailfrom
        else:
            ReportMailFrom = ReportEmail

        if args.reportemailserver:
            ReportMailServer = args.reportemailserver
        else:
            ReportMailServer = input(
                "Enter the email server to send the report from : "
            )
            if ReportMailServer == "smtp.gmail.com":
                log.logger(
                    "warning", "Google no longer supports sending mails via SMTP."
                )
                return ReportType.NONE, None

        if args.reportemailserverport:
            ReportMailPort = args.reportemailserverport
        else:
            while True:
                ReportMailPort = input(
                    "Enter the email port to send the report from : "
                )
                if not isinstance(ReportMailPort, int):
                    break
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
        if args.reportwebhook:
            Webhook = args.reportwebhook
        else:
            Webhook = input("Enter your webhook URL : ")

        return Method, Webhook


def Confirmation(message) -> bool:
    if DontAskForConfirmation:
        return True

    confirmation = input(message)
    return confirmation.lower() != "n"


def UserConfirmation():
    if DontAskForConfirmation:
        return True, True, True

    portscan = Confirmation("Do you want to scan ports? [Y/n] : ")
    if not portscan:
        return False, False, False

    vulnscan = Confirmation("Do you want to scan for vulnerabilities? [Y/n] : ")
    if not vulnscan:
        return True, False, False

    downloadexploits = Confirmation("Do you want to download exploits? [Y/n] : ")

    return portscan, vulnscan, downloadexploits


def WebScan() -> bool:
    return Confirmation("Do you want to scan for web vulnerabilities? [Y/n] : ")


def GetHostsToScan(hosts, console):
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
                if int(host) < len(hosts) and int(host) >= 0:
                    Targets = [hosts[int(host)]]
                    break
                else:
                    console.print(
                        "Please enter a valid host number or 'all' " + "or 'exit'",
                        style="red",
                    )

    return Targets


def InitArgsConf(args, log):
    if not args.config:
        return None

    try:
        config = ConfigParser()
        config.read(args.config)

        if config.has_option("AUTOPWN", "target"):
            args.target = config.get("AUTOPWN", "target").lower()

        if config.has_option("AUTOPWN", "hostfile"):
            args.host_file = config.get("AUTOPWN", "hostfile").lower()

        if config.has_option("AUTOPWN", "scantype"):
            args.scan_type = config.get("AUTOPWN", "scantype").lower()

        if config.has_option("AUTOPWN", "nmapflags"):
            args.nmap_flags = config.get("AUTOPWN", "nmapflags").lower()

        if config.has_option("AUTOPWN", "speed"):
            try:
                args.speed = int(config.get("AUTOPWN", "speed"))
            except ValueError:
                log.logger("error", "Invalid speed value in config file. (Default : 3)")

        if config.has_option("AUTOPWN", "apikey"):
            args.api = config.get("AUTOPWN", "apikey").lower()

        if config.has_option("AUTOPWN", "auto"):
            args.yes_please = True

        if config.has_option("AUTOPWN", "mode"):
            args.mode = config.get("AUTOPWN", "mode").lower()

        if config.has_option("AUTOPWN", "noisetimeout"):
            args.noise_timeout = config.get("AUTOPWN", "noisetimeout").lower()

        if config.has_option("REPORT", "output"):
            args.output = config.get("REPORT", "output").lower()

        if config.has_option("REPORT", "outputtype"):
            args.output_type = config.get("REPORT", "outputtype").lower()

        if config.has_option("REPORT", "method"):
            args.report = config.get("REPORT", "method").lower()

        if config.has_option("REPORT", "email"):
            args.report_email = config.get("REPORT", "email").lower()

        if config.has_option("REPORT", "email_password"):
            args.report_email_password = config.get("REPORT", "email_password").lower()

        if config.has_option("REPORT", "email_to"):
            args.report_email_to = config.get("REPORT", "email_to").lower()

        if config.has_option("REPORT", "email_from"):
            args.report_email_from = config.get("REPORT", "email_from").lower()

        if config.has_option("REPORT", "email_server"):
            args.report_email_server = config.get("REPORT", "email_server").lower()

        if config.has_option("REPORT", "email_port"):
            args.report_email_server_port = config.get("REPORT", "email_port").lower()

        if config.has_option("REPORT", "webhook"):
            args.report_webhook = config.get("REPORT", "webhook")

    except FileNotFoundError:
        log.logger("error", "Config file not found!")
        raise SystemExit
    except PermissionError:
        log.logger("error", "Permission denied while trying to read config file!")
        raise SystemExit


def install_nmap_linux(log):
    distro_ = distro.id().lower()
    while True:
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
                break
            elif distro_ in ["arch", "manjaro"]:
                check_call(
                    ["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"],
                    stderr=DEVNULL,
                )
                break
            elif distro_ in ["fedora", "oracle"]:
                check_call(
                    ["/usr/bin/sudo", "dnf", "install", "nmap", "-y"], stderr=DEVNULL
                )
                break
            elif distro in ["rhel", "centos"]:
                check_call(
                    ["/usr/bin/sudo", "yum", "install", "nmap", "-y"], stderr=DEVNULL
                )
                break
            elif distro in ["sles", "opensuse"]:
                check_call(
                    ["/usr/bin/sudo", "zypper", "install", "nmap", "--non-interactive"],
                    stderr=DEVNULL,
                )
                break
            else:
                raise CalledProcessError

        except CalledProcessError:
            _distro_ = input(
                "Cannot recognize the needed package manager for your "
                + f"system that seems to be running in: {distro_} and "
                + f"{sys_platform}, {platform()}, kindly select the "
                + "correct package manager below to proceed to the "
                + "installation, else, select, n.\n\t0 Abort installation\n"
                + "\t1 apt-get\n\t2 dnf\n\t3 yum\n\t4 pacman\n\t5 zypper."
                + "\nSelect option [0-5] >"
            )
            if _distro_ == 1:
                distro_ = "ubuntu"
            elif _distro_ == 2:
                distro_ = "fedora"
            elif _distro_ == 3:
                distro_ = "centos"
            elif _distro_ == 4:
                distro_ = "arch"
            elif _distro_ == 5:
                distro_ = "opensuse"
            else:
                log.logger("error", "Couldn't install nmap (Linux)")
                break
            continue


def install_nmap_windows(log):
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


def install_nmap_mac(log):
    try:
        check_call(["/usr/bin/sudo", "brew", "install", "nmap"], stderr=DEVNULL)
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Mac)")


def check_nmap(log):
    try:
        check_call(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)
    except (CalledProcessError, FileNotFoundError):
        log.logger("warning", "Nmap is not installed.")
        if DontAskForConfirmation:
            auto_install = True
        else:
            auto_install = (
                input(f"Install Nmap on your system ({distro.id()})? ").lower() != "n"
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


def ParamPrint(args, targetarg, scantype_name, scanmode_name, apiKey, console, log):

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
        + f"│\tOutput file : [yellow]{args.output}[/yellow]\n"
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
        get("https://google.com")
    except Exception as e:
        log.logger("error", "Connection failed.")
        log.logger("error", e)
        return False
    else:
        return True


def SaveOutput(console, out_type, report, output_file):
    if out_type == "html":
        if not output_file.endswith(".html"):
            output_file += ".html"
        console.save_html(output_file)
    elif out_type == "svg":
        if not output_file.endswith(".svg"):
            output_file += ".svg"
        console.save_svg(output_file)
    elif out_type == "txt":
        console.save_text(output_file)


def get_terminal_width() -> int:
    try:
        width, _ = get_terminal_size()
    except OSError:
        width = 80

    if system().lower() == "windows":
        width -= 1

    return width


def check_version(cur_version: str, log) -> None:
    try:
        data = get("https://pypi.org/pypi/autopwn-suite/json").json()
    except Exception as e:
        log.logger("error", "An error occured while checking AutoPWN Suite version.")
        log.logger("error", e)
    else:
        version = list(data["releases"].keys())[-1]
        version_major = int(version.split(".")[0])
        version_minor = int(version.split(".")[1])
        version_patch = int(version.split(".")[2])

        cur_version_major = int(cur_version.split(".")[0])
        cur_version_minor = int(cur_version.split(".")[1])
        cur_version_patch = int(cur_version.split(".")[2])

        if version_major > cur_version_major:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised.",
            )
        elif version_minor > cur_version_minor:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised.",
            )
        elif version_patch > cur_version_patch:
            log.logger(
                "warning",
                "Your version of AutoPWN Suite is outdated. Update is advised.",
            )
