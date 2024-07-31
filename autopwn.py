from datetime import datetime

import requests
from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.exploit import exploit_vulnerabilities
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import (AnalyseScanResults, DiscoverHosts, NoiseScan,
                             PortScan)
from modules.searchvuln import SearchSploits
from modules.utils import (GetHostsToScan, GetShodanVulns, GetZoomEyeVulns,
                           InitArgsAPI, InitArgsConf, InitArgsMode,
                           InitArgsScanType, InitArgsTarget, InitAutomation,
                           InitReport, ParamPrint, SaveOutput, ScanMode,
                           UserConfirmation, WebScan, check_nmap,
                           check_version, cli, resolve_hostnames_to_ips)
from modules.scanner import ShodanScan, display_shodan_results
from modules.web.webvuln import webvuln


def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, shodan_api_key, zoomeye_api_key, console, log
) -> None:

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = DiscoverHosts(targetarg, console, scantype, scanmode)
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = [targetarg]

    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()


    all_vulnerabilities = []

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags, shodan_api_key
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, host)
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, log, console, apiKey)
                if shodan_api_key:
                    ShodanVulns = GetShodanVulns(host, shodan_api_key, log)
                    VulnsArray.extend(ShodanVulns)
                if zoomeye_api_key:
                    ZoomEyeVulns = GetZoomEyeVulns(host, zoomeye_api_key, log)
                    VulnsArray.extend(ZoomEyeVulns)
                if DownloadExploits and len(VulnsArray) > 0:
                    all_vulnerabilities.extend(VulnsArray)

    if all_vulnerabilities:
        exploit_vulnerabilities(all_vulnerabilities, targetarg, log, console)

    if ScanWeb:
            webvuln(host, log, console)


    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )


def main() -> None:
    __author__ = "GamehunterKaan"
    __version__ = "2.1.5"

    args = cli()
    console = Console(record=True, color_system=None if args.no_color else "truecolor")
    log = Logger(console)

    if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    vuln_api_key, shodan_api_key, zoomeye_api_key = InitArgsAPI(args, log)
    api_keys_used = sum([1 for key in [vuln_api_key, shodan_api_key, zoomeye_api_key] if key])
    print_banner(console, api_keys_used)
    check_version(__version__, log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    vuln_api_key, shodan_api_key, zoomeye_api_key = InitArgsAPI(args, log)
    ReportMethod, ReportObject = InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, api_keys_used, console, log)

    StartScanning(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, zoomeye_api_key, console, log)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
