from datetime import datetime

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
                           check_nmap, cli, is_root, get_terminal_width)
from modules.web.webvuln import webvuln


def FurtherEnumuration(
        args,
        hosts,
        console,
        log,
        scanmode,
        apiKey
    ) -> None:
    Targets = GetHostsToScan(hosts, console)
    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(host, console, log, args.speed,
                                       args.host_timeout, scanmode,
                                       args.nmap_flags)
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

    term_width = get_terminal_width()
    DontAskForConfirmation = InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = InitArgsAPI(args, log)
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
        apiKey,
        console
    )

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(
            targetarg, log, console, scantype, args.noise_timeout
        )

    OnlineHosts = DiscoverHosts(
        targetarg, console, scantype, scanmode
    )

    FurtherEnumuration(
        args,
        OnlineHosts,
        console,
        log,
        scanmode,
        apiKey,
    )

    print(" " * term_width, end="\r")
    console.print(
        "{time} - Scan completed.".format(
            time = datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
