from getpass import getpass
from argparse import ArgumentParser
from os import get_terminal_size
from datetime import datetime

from colorama import init
from rich.console import Console
from rich.text import Text

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


def cli():
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

    return argparser.parse_args()




def InitArgsTarget(args, log):
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
                + " Switching back to normal mode ..."
            )
    elif args.mode == "noise":
        scanmode = ScanMode.Noise
        log.logger("error", "Noise mode enabled!")

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


def GetHostsToScan(hosts, console):
    if len(hosts) == 0:
        raise SystemExit(
            "No hosts found! {time} - Scan completed.".format(
                time = datetime.now().strftime("%b %d %Y %H:%M:%S")
            )
        )

    index = 0
    for host in hosts:
        msg = Text.assemble(("[", "red"), index, ("]", "red"), host, justify="center")
        console.print(msg)
        index += 1

    if DontAskForConfirmation:
        return hosts

    console.print(
        "\n[yellow]Enter the index number of the "
        + "host you would like to enumurate further. "
        + "Enter 'all' to enumurate all hosts. "
        + "Enter 'exit' to exit [/yellow] ", end=" "
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
def FurtherEnumuration(hosts, console, log):
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
                GetExploitsFromArray(VulnsArray, console,  host)

        if ScanWeb:
            webvuln(host, log)


#main function
def main():
    init()

    __author__ = "GamehunterKaan"
    __version__ = "1.5.1"

    args = cli()
    console = Console()
    log = Logger()

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
