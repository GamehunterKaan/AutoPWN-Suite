from datetime import datetime
from os import get_terminal_size

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import (AnalyseScanResults, DiscoverHosts, NoiseScan,
                             PortScan)
from modules.searchvuln import SearchSploits
from modules.utils import (GetHostsToScan, InitArgsAPI, InitArgsConf,
                           InitArgsMode, InitArgsScanType, InitArgsTarget,
                           InitAutomation, InitReport, ParamPrint, SaveOutput,
                           ScanMode, ScanType, UserConfirmation, WebScan,
                           check_nmap, cli, is_root)
from modules.web.webvuln import webvuln


def FurtherEnumuration(
        hosts,
        console,
        log,
        scanspeed,
        scanmode,
        nmapflags,
        apiKey
    ) -> None:
    Targets = GetHostsToScan(hosts, console)
    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(host, console, log, scanspeed, scanmode, nmapflags)
            PortArray = AnalyseScanResults(PortScanResults, log, console, host)
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, log, console, apiKey)
                if DownloadExploits and len(VulnsArray) > 0:
                    GetExploitsFromArray(VulnsArray, log, console, host)

        if ScanWeb:
            webvuln(host, log, console)


#main function
def main() -> None:

    __author__ = "GamehunterKaan"
    __version__ = "2.0.0"

    args = cli()
    console = Console(record=True)
    log = Logger()

    if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    if args.config:
        InitArgsConf(args, log)

    print_banner(console)

    term_width, _ = get_terminal_size()
    outputfile = args.output
    DontAskForConfirmation = InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    scanspeed = args.speed
    nmapflags = args.nmapflags
    apiKey = InitArgsAPI(args, log)
    hostfile = args.hostfile
    noisetimeout = args.noisetimeout
    ReportMethod, ReportObject = InitReport(args, log)

    if not is_root():
        log.logger(
            "warning",
            "It is recommended to run this script as root"
            + " since it is more silent and accurate."
        )

    ParamPrint(
        args,
        targetarg,
        scantype,
        scanmode,
        scanspeed,
        nmapflags,
        apiKey,
        outputfile,
        DontAskForConfirmation,
        console,
        term_width
    )

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(
            targetarg, log, console, scantype, noisetimeout
        )

    OnlineHosts = DiscoverHosts(
        targetarg, console, scantype, scanmode
    )

    FurtherEnumuration(
        OnlineHosts,
        console,
        log,
        scanspeed,
        scanmode,
        nmapflags,
        apiKey,
    )

    print(" " * term_width, end="\r")
    console.print(
        "{time} - Scan completed.".format(
            time = datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.outputtype, args.report, outputfile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
