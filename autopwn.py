import distro
from sys import platform as sys_platform
from platform import platform, system
from getpass import getpass
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM
from os import get_terminal_size
from platform import system
from subprocess import check_call, CalledProcessError, DEVNULL
from datetime import datetime

from colorama import init
from rich.console import Console
from rich.text import Text
from configparser import ConfigParser

from modules.logger import Logger
from modules.colors import bcolors
from modules.scanner import is_root
from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.web.webvuln import webvuln
from modules.searchvuln import SearchSploits
from modules.report import (
    InitializeReport,
    ReportType,
    ReportMail,
    ReportWebhook
)
from modules.scanner import (
    AnalyseScanResults,
    PortScan,
    DiscoverHosts,
    ScanMode,
    ScanType,
    NoiseScan
)

__author__ = "GamehunterKaan"
__version__ = "1.5.1"

argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument(
    "-v", "--version",
    help="Print version and exit.",
    action="store_true"
)
argparser.add_argument(
    "-y", "--yesplease",
    help="Don't ask for anything. (Full automatic mode)",
    action="store_true",
    required=False,
    default=False
)
argparser.add_argument(
    "-c", "--config",
    help="Specify a config file to use. (Default : None)",
    default=None,
    required=False,
    metavar="CONFIG",
    type=str
)

scanargs = argparser.add_argument_group("Scanning", "Options for scanning")
scanargs.add_argument(
    "-t", "--target",
    help=(
            "Target range to scan. This argument overwrites the",
            "hostfile argument. (192.168.0.1 or 192.168.0.0/24)"
        ),
    type=str,
    required=False,
    default=None
)
scanargs.add_argument(
    "-hf", "--hostfile",
    help="File containing a list of hosts to scan.",
    type=str,
    required=False,
    default=None
)
scanargs.add_argument(
    "-st", "--scantype",
    help="Scan type.",
    type=str,
    required=False,
    default=None,
    choices=["arp", "ping"]
)
scanargs.add_argument(
    "-nf", "--nmapflags",
    help=(
            "Custom nmap flags to use for portscan.",
            " (Has to be specified like : -nf=\"-O\")"
        ),
    default="",
    type=str,
    required=False
)
scanargs.add_argument(
    "-s", "--speed",
    help="Scan speed. (Default : 3)",
    default=3,
    type=int,
    required=False,
    choices=range(0,6)
)
scanargs.add_argument(
    "-a", "--api",
    help=(
            "Specify API key for vulnerability detection ",
            "for faster scanning. (Default : None)"
        ),
    default=None,
    type=str,
    required=False
)
scanargs.add_argument(
    "-m", "--mode",
    help="Scan mode.",
    default="normal",
    type=str,
    required=False,
    choices=["evade", "noise", "normal"]
)
scanargs.add_argument(
    "-nt", "--noisetimeout",
    help="Noise mode timeout. (Default : None)",
    default=None,
    type=int,
    required=False,
    metavar="TIMEOUT"
)

reportargs = argparser.add_argument_group("Reporting", "Options for reporting")
reportargs.add_argument(
    "-o", "--output",
    help="Output file name. (Default : autopwn.log)",
    default="autopwn.log",
    type=str,
    required=False
)
reportargs.add_argument(
    "-rp", "--report",
    help="Report sending method.",
    type=str,
    required=False,
    default=None,
    choices=["email", "webhook"]
)
reportargs.add_argument(
    "-rpe",
    "--reportemail",
    help="Email address to use for sending report.",
    type=str,
    required=False,
    default=None,
    metavar="EMAIL"
)
reportargs.add_argument(
    "-rpep",
    "--reportemailpassword",
    help="Password of the email report is going to be sent from.",
    type=str,
    required=False,
    default=None,
    metavar="PASSWORD"
)
reportargs.add_argument(
    "-rpet", "--reportemailto",
    help="Email address to send report to.",
    type=str,
    required=False,
    default=None,
    metavar="EMAIL"
)
reportargs.add_argument(
    "-rpef", "--reportemailfrom",
    help="Email to send from.",
    type=str,
    required=False,
    default=None,
    metavar="EMAIL"
)
reportargs.add_argument(
    "-rpes", "--reportemailserver",
    help="Email server to use for sending report.",
    type=str,
    required=False,
    default=None,
    metavar="SERVER"
)
reportargs.add_argument(
    "-rpesp", "--reportemailserverport",
    help="Port of the email server.",
    type=int,
    required=False,
    default=None,
    metavar="PORT"
)
reportargs.add_argument(
    "-rpw", "--reportwebhook",
    help="Webhook to use for sending report.",
    type=str,
    required=False,
    default=None,
    metavar="WEBHOOK"
)

args = argparser.parse_args()
console = Console()
log = Logger()


def InitArgsConf():
    if not args.config:
        return None

    try:
        config = ConfigParser()
        config.read(args.config)

        if config.has_option("AUTOPWN", "target"):
            args.target = config.get("AUTOPWN", "target").lower()

        if config.has_option("AUTOPWN", "hostfile"):
            args.hostfile = config.get("AUTOPWN", "hostfile").lower()

        if config.has_option("AUTOPWN", "scantype"):
            args.scantype = config.get("AUTOPWN", "scantype").lower()

        if config.has_option("AUTOPWN", "nmapflags"):
            args.nmapflags = config.get("AUTOPWN", "nmapflags").lower()

        if config.has_option("AUTOPWN", "speed"):
            try:
                args.speed = int(config.get("AUTOPWN", "speed"))
            except ValueError:
                log.logger(
                    "error",
                    "Invalid speed value in config file. (Default : 3)"
                )

        if config.has_option("AUTOPWN", "apikey"):
            args.api = config.get("AUTOPWN", "apikey").lower()

        if config.has_option("AUTOPWN", "auto"):
            args.yesplease = True

        if config.has_option("AUTOPWN", "mode"):
            args.mode = config.get("AUTOPWN", "mode").lower()

        if config.has_option("AUTOPWN", "noisetimeout"):
            args.noisetimeout = config.get("AUTOPWN", "noisetimeout").lower()

        if config.has_option("REPORT", "output"):
            args.output = config.get("AUTOPWN", "output").lower()

        if config.has_option("REPORT", "method"):
            args.report = config.get("REPORT", "method").lower()

        if config.has_option("REPORT", "email"):
            args.reportemail = config.get("REPORT", "email").lower()

        if config.has_option("REPORT", "email_password"):
            args.reportemailpassword = config.get(
                    "REPORT", "email_password"
                ).lower()

        if config.has_option("REPORT", "email_to"):
            args.reportemailto = config.get("REPORT", "email_to").lower()

        if config.has_option("REPORT", "email_from"):
            args.reportemailfrom = config.get("REPORT", "email_from").lower()

        if config.has_option("REPORT", "email_server"):
            args.reportemailserver = config.get(
                    "REPORT", "email_server"
                ).lower()

        if config.has_option("REPORT", "email_port"):
            args.reportemailserverport = config.get(
                    "REPORT", "email_port"
                ).lower()

        if config.has_option("REPORT", "webhook"):
            args.reportwebhook = config.get("REPORT", "webhook").lower()

    except FileNotFoundError:
        log.logger("error", "Config file not found!")
        raise SystemExit
    except PermissionError:
        log.logger(
            "error", "Permission denied while trying to read config file!"
        )
        raise SystemExit


def InitArgsScanType():
    scantype = ScanType.Ping

    if args.scantype == "arp" or args.scantype == None:
        if is_root():
            scantype = ScanType.Arp

    return scantype


def InitArgsAPI():
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
                + "Vulnerability detection is going to be slower!"
                + "You can get your own NIST API key from "
                + "https://nvd.nist.gov/developers/request-an-api-key"
            )
        except PermissionError:
            log.logger(
                "error", "Permission denied while trying to read api.txt!"
            )

    return apiKey


def install_nmap_linux():
    distro_ = distro.id().lower()
    while True:
        try:
            if distro_ in ["ubuntu", "debian", "linuxmint", "raspbian"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "apt-get",
                        "install",
                        "nmap",
                        "-y"
                        ],
                    stderr=DEVNULL
                )
            elif distro_ in ["arch", "manjaro"]:
                check_call(
                        [
                            "/usr/bin/sudo",
                            "pacman",
                            "-S",
                            "nmap",
                            "--noconfirm"
                            ],
                        stderr=DEVNULL
                )
            elif distro_ in ["fedora", "oracle"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "dnf",
                        "install",
                        "nmap"
                        ],
                    stderr=DEVNULL
                )
            elif distro in ["rhel", "centos"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "yum",
                        "install",
                        "nmap"
                        ],
                    stderr=DEVNULL
                )
            elif distro in ["sles", "opensuse"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "zypper",
                        "install",
                        "nmap"
                        ],
                    stderr=DEVNULL
                )
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


def install_nmap_windows():
    # TODO: implement this
    """shut up, pylint"""
    try:
        check_call(
            [
                "powershell",
                "winget",
                "install",
                "nmap",
                "--silent"
                ],
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Windows)")


def install_nmap_mac():
    try:
        check_call(
            [
                "/usr/bin/sudo",
                "brew",
                "install",
                "nmap"
                ],
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Mac)")


def check_nmap():
    # Check if nmap is installed if not, install it
    try:
        check_call(
            ["nmap", "-h"],
            stdout=DEVNULL,
            stderr=DEVNULL
        )
    except FileNotFoundError:
        log.logger("warning", "Nmap is not installed.")
        auto_install = input(
                f"Install Nmap on your system ({distro.id()}: {platform()})? "
            )
        if auto_install in ["y", "Y"]:
            platform_ = system().lower()
            if  platform_ == "linux":
                install_nmap_linux()
            if platform_ == "windows":
                install_nmap_windows()
            elif platform_ == "darwin":
                install_nmap_mac()
            else:
                raise SystemExit(
                    "Unknown OS! Auto installation not supported!"
                )
        else:
            log.logger("error", "Denied permission to install Nmap.")
            raise SystemExit


def DetectIPRange():
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        PrivateIPAdress = str(s.getsockname()[0]).split(".")
        target = (
                f"{PrivateIPAdress[0]}.",
                f"{PrivateIPAdress[1]}.",
                f"{PrivateIPAdress[2]}.0/24"
            )
    except ConnectionError:
        raise SystemExit
    else:
        return target


def InitArgsTarget():
    if args.target:
        target = args.target
    else:
        if args.hostfile:
            # read targets from host file and insert all of them into an array
            try:
                with open(args.hostfile, "r", encoding="utf-8") as target_file:
                    target = target_file.readlines()
            except FileNotFoundError:
                log.logger("error", "Host file not found!")
            except PermissionError:
                log.logger(
                    "error",
                    "Permission denied while trying to read host file!"
                )
            except Exception:
                log.logger(
                    "error", "Unknown error while trying to read host file!"
                )
            else:
                return target

            target = DetectIPRange()
        else:
            if DontAskForConfirmation:
                target = DetectIPRange()
            else:
                try:
                    target = input("Enter target range to scan : ")
                except KeyboardInterrupt:
                    raise SystemExit("Ctrl+C pressed. Exiting.")

    return target


def InitArgsMode():
    scanmode = ScanMode.Normal

    if args.mode == "evade":
        if is_root():
            scanmode = ScanMode.Evade
            log.logger("info", "Evasion mode enabled!")
        else:
            log.logger(
                "error",
                "You must be root to use evasion mode!"
                + " Switching back to normal mode ..."
            )
    elif args.mode == "noise":
        scanmode = ScanMode.Noise
        log.logger("error", "Noise mode enabled!")

    return scanmode


def InitReport():
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
            ReportMailPassword = getpass("Enter your email password : ")

        if args.reportemailto:
            ReportMailTo = args.reportemailto
        else:
            ReportMailTo = input(
                    "Enter the email address to send the report to : "
                )

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
                    "error",
                    "Google no longer supports sending mails via SMTP."
                )
                return ReportType.NONE, None

        if args.reportemailserverport:
            ReportMailPort = args.reportemailserverport
        else:
            while True:
                ReportMailPort = input(
                        "Enter the email port to send the report from : "
                    )
                if isinstance(ReportMailPort, int):
                    break
                log.logger("error", "Invalid port number!")

        EmailObj = ReportMail(
                ReportEmail,
                ReportMailPassword,
                ReportMailTo,
                ReportMailFrom,
                ReportMailServer,
                int(ReportMailPort),
                args.output
            )

        return Method, EmailObj

    elif args.report == "webhook":
        Method = ReportType.WEBHOOK
        if args.reportwebhook:
            Webhook = args.reportwebhook
        else:
            Webhook = input("Enter your webhook URL : ")

        WebhookObj = ReportWebhook(Webhook, args.output)

        return Method, WebhookObj


def ParamPrint(term_width):
    # print everything inside args class to screen
    if args.config:
        console.print(f"\n┌─[ Config file {args.config} was used. ]")
        console.print("├─[ Scanning with the following parameters. ]")
    else:
        console.print("\n┌─[ Scanning with the following parameters. ]")

    console.print(
        "├" + "─" * (term_width-1)
        + f"\n│\tTarget : {targetarg}\n"
        + f"│\tScan type : {scantype.name}\n"
        + f"│\tScan mode : {scanmode.name}\n"
        + f"│\tScan speed : {scanspeed}\n"
        + f"│\tNmap flags : {nmapflags}\n"
        + f"│\tAPI key : {apiKey}\n"
        + f"│\tOutput file : {outputfile}\n"
        + f"│\tDont ask for confirmation : {DontAskForConfirmation}\n"
        + f"│\tHost file : {args.hostfile}\n"
        + f"│\tReporting method : {args.report}\n"
        + "└" + "─" * (term_width-1)
    )


def Confirmation(message):
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

    vulnscan = Confirmation(
            "Do you want to scan for vulnerabilities? [Y/n] : "
        )
    if not vulnscan:
        return True, False, False

    downloadexploits = Confirmation(
            "Do you want to download exploits? [Y/n] : "
        )

    return portscan, vulnscan, downloadexploits


def WebScan():
    return Confirmation(
        "Do you want to scan for web vulnerabilities? [Y/n] : "
    )


def GetHostsToScan(hosts):
    if len(hosts) == 0:
        raise SystemExit(
            "No hosts found! {time} - Scan completed.".format(
                time = datetime.now().strftime("%b %d %Y %H:%M:%S")
            )
        )

    index = 0
    for host in hosts:
        console.print(
            Text(f"[red][[/red]{index}[red]][/red] {host}", justify="center")
        )
        index += 1

    if DontAskForConfirmation:
        return hosts

    console.print(
        "\n[yellow]Enter the index number of the "
        + "host you would like to enumurate further."
        + "Enter 'all' to enumurate all hosts."
        + "Enter 'exit' to exit [/yellow]"
    )

    while True:
        host = input(f"{bcolors.blue}────>{bcolors.endc}")
        Targets = hosts

        if host in hosts:
            Targets = [host]
        else:
            if host == "all" or host == "":
                break
            elif host == "exit":
                raise SystemExit(
                    "{time} - Scan completed.".format(
                        time = datetime.now().strftime("%b %d %Y %H:%M:%S")
                    )
                )
            else:
                try:
                    if int(host) < len(hosts) and int(host) >= 0:
                        Targets = [hosts[int(host)]]
                        break
                except:
                    console.print(
                        "Please enter a valid host number or 'all' "
                        + "or 'exit'", style="red"
                    )

    return Targets


#post scan stuff
def FurtherEnumuration(hosts):
    Targets = GetHostsToScan(hosts)
    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()

    for host in Targets:
        if not ScanPorts:
            break

        PortScanResults = PortScan(host, scanspeed, scanmode, nmapflags)
        PortArray = AnalyseScanResults(PortScanResults,host)
        if ScanVulns and len(PortArray) > 0:
            VulnsArray = SearchSploits(PortArray, apiKey)
            if DownloadExploits and len(VulnsArray) > 0:
                GetExploitsFromArray(VulnsArray, host)

        if ScanWeb:
            webvuln(host)


#main function
def main():
    init()

    if args.version:
        console.print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    if args.config:
        InitArgsConf()

    global targetarg, scantype, scanmode, scanspeed, nmapflags, apiKey
    global outputfile, DontAskForConfirmation, hostfile, noisetimeout

    outputfile = args.output
    print_banner()

    width_, _ = get_terminal_size()
    DontAskForConfirmation = args.yesplease
    targetarg = InitArgsTarget()
    scantype = InitArgsScanType()
    scanmode = InitArgsMode()
    scanspeed = args.speed
    nmapflags = args.nmapflags
    apiKey = InitArgsAPI()
    hostfile = args.hostfile
    noisetimeout = args.noisetimeout
    ReportMethod, ReportObject = InitReport()

    if not is_root():
        log.logger(
            "error",
            "It is recommended to run this script as root"
            + "since it is more silent and accurate."
        )

    ParamPrint(width_)
    check_nmap()

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, scantype, noisetimeout)

    OnlineHosts = DiscoverHosts(
            targetarg, scantype, scanspeed, scanmode
        )
    FurtherEnumuration(OnlineHosts)
    InitializeReport(ReportMethod, ReportObject)
    console.print(
        "{time} - Scan completed.".format(
            time = datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )


#only run the script if its not imported as a module (directly interpreted with python3)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
