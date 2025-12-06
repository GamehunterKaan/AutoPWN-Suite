from datetime import datetime
from time import sleep

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import AnalyseScanResults, DiscoverHosts, NoiseScan, PortScan
from modules.searchvuln import SearchSploits
from modules.utils import (
    GetHostsToScan,
    InitArgsAPI,
    InitArgsConf,
    InitArgsMode,
    InitArgsScanType,
    InitArgsTarget,
    InitAutomation,
    InitReport,
    ParamPrint,
    SaveOutput,
    ScanMode,
    UserConfirmation,
    WebScan,
    CheckConnection,
    check_nmap,
    cli,
)
from modules.web.webvuln import webvuln
from modules.daemon.daemon_installer import InstallDaemon, UninstallDaemon, CreateConfig

def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, console, console2, log
) -> None:

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = DiscoverHosts(targetarg, console, scantype, scanmode)
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = [targetarg]

    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation(args)
    ScanWeb = WebScan()

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, host)
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, log, console, console2, apiKey)
                if DownloadExploits and len(VulnsArray) > 0:
                    GetExploitsFromArray(VulnsArray, log, console, console2, host)

        if ScanWeb:
            webvuln(host, log, console)

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )


def main() -> None:
    __author__ = "GamehunterKaan"
    __version__ = "2.3.2"

    args = cli()
    if args.no_color:
        console = Console(record=True, color_system=None)
        console2 = Console(record=False, color_system=None)
    else:
        console = Console(record=True, color_system="truecolor")
        console2 = Console(record=False, color_system="truecolor")
    log = Logger(console)

    if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit
    elif args.daemon_install:
        InstallDaemon(console)
        raise SystemExit
    elif args.daemon_uninstall:
        UninstallDaemon(console)
        raise SystemExit
    elif args.create_config:
        CreateConfig(console)
        raise SystemExit

    print_banner(console)

    CheckConnection(log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = InitArgsAPI(args, log)
    ReportMethod, ReportObject = InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, apiKey, console, log)

    StartScanning(args, targetarg, scantype, scanmode, apiKey, console, console2, log)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.output, args.output_folder, targetarg)

    if not hasattr(args, "scan_interval"):
        args.scan_interval = None
    if args.scan_interval and args.scan_interval > 0:
        console.print(f"Sleeping for {args.scan_interval} seconds...")
        sleep(args.scan_interval)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
