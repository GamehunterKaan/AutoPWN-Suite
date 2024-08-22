from datetime import datetime

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.exploit import exploit_vulnerabilities
from modules.keyword_generator import generate_keywords
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import (AnalyseScanResults, DiscoverHosts, NoiseScan,
                             PortScan)
from modules.searchvuln import SearchSploits, VulnerableSoftware, GetShodanVulns, GetZoomEyeVulns
from modules.utils import (GetHostsToScan, 
                           InitArgsAPI, InitArgsConf, InitArgsMode,
                           InitArgsScanType, InitArgsTarget, InitAutomation,
                           InitReport, ParamPrint, SaveOutput, ScanMode,
                           UserConfirmation, check_nmap, cli,
                           check_version, cli, remove_duplicate_vulnerabilities)
from modules.web.webvuln import webvuln


def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, shodan_api_key, zoomeye_api_key, openai_api_key, console, log
) -> None:

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = DiscoverHosts(targetarg, console, scantype, scanmode)
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = [targetarg]

    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation() if not args.exploit else (True, True, True)
    PortArray = []

    all_vulnerabilities = []

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags, shodan_api_key
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, host, shodan_results=None)
        if ScanVulns and PortArray and len(PortArray) > 0:
            VulnsArray = []
            keywords = generate_keywords(PortArray)
            sploits = SearchSploits(keywords, log, console, args, apiKey)
            for sploit in sploits:
                all_vulnerabilities.append(sploit)
            if shodan_api_key:
                ShodanVulns, ShodanPorts = GetShodanVulns(host, shodan_api_key, log)
                for port in ShodanPorts:
                    PortArray.append((host, port, "tcp", "shodan", ""))
                for vuln in ShodanVulns:
                    log.logger("info", f"Shodan Vuln: {vuln['title']} - CVEs: {', '.join(vuln['CVEs'])}")
                    vuln_obj = VulnerableSoftware(
                        title=vuln['title'],
                        CVEs=vuln['CVEs'],
                        severity_score=vuln['severity_score'],
                        exploitability=vuln['exploitability']
                    )
                    all_vulnerabilities.append(vuln_obj)
            if zoomeye_api_key:
                ZoomEyeVulns = GetZoomEyeVulns(host, zoomeye_api_key, log)
                for vuln in ZoomEyeVulns:
                    vuln_obj = VulnerableSoftware(
                        title=vuln['title'],
                        CVEs=vuln['CVEs'],
                        severity_score=vuln['severity_score'],
                        exploitability=vuln['exploitability']
                    )
                    all_vulnerabilities.append(vuln_obj)
                    
            all_vulnerabilities = remove_duplicate_vulnerabilities(all_vulnerabilities)
            if all_vulnerabilities:
                print("All vulnerabilities: ", all_vulnerabilities)
            if DownloadExploits and len(all_vulnerabilities) > 0:
                GetExploitsFromArray(all_vulnerabilities, log, console, console)
    
    for host in Targets:
        webvuln(host, log, console)

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )

def StartExploiting(
    args, targetarg, scantype, scanmode, apiKey, shodan_api_key, zoomeye_api_key, openai_api_key, console, log
) -> None:
    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = DiscoverHosts(targetarg, console, scantype, scanmode)
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = [targetarg]

    all_vulnerabilities = []

    for host in Targets:
        PortScanResults = PortScan(
            host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags, shodan_api_key
        )
        PortArray = AnalyseScanResults(PortScanResults, log, console, host, shodan_results=None)
        if PortArray and len(PortArray) > 0:
            keywords = generate_keywords(PortArray)
            sploits = SearchSploits(keywords, log, console, args, apiKey)
            for sploit in sploits:
                all_vulnerabilities.append(sploit)
            if shodan_api_key:
                ShodanVulns, ShodanPorts = GetShodanVulns(host, shodan_api_key, log)
                for port in ShodanPorts:
                    PortArray.append((host, port, "tcp", "shodan", ""))
                for vuln in ShodanVulns:
                    log.logger("info", f"Shodan Vuln: {vuln['title']} - CVEs: {', '.join(vuln['CVEs'])}")
                    vuln_obj = VulnerableSoftware(
                        title=vuln['title'],
                        CVEs=vuln['CVEs'],
                        severity_score=vuln['severity_score'],
                        exploitability=vuln['exploitability']
                    )
                    all_vulnerabilities.append(vuln_obj)
            if zoomeye_api_key:
                ZoomEyeVulns = GetZoomEyeVulns(host, zoomeye_api_key, log)
                for vuln in ZoomEyeVulns:
                    vuln_obj = VulnerableSoftware(
                        title=vuln['title'],
                        CVEs=vuln['CVEs'],
                        severity_score=vuln['severity_score'],
                        exploitability=vuln['exploitability']
                    )
                    all_vulnerabilities.append(vuln_obj)
                    
            all_vulnerabilities = remove_duplicate_vulnerabilities(all_vulnerabilities)
            if all_vulnerabilities:
                print("All vulnerabilities: ", all_vulnerabilities)
                exploit_vulnerabilities(all_vulnerabilities, host, log, console)

    console.print(
        "{time} - Exploitation completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )
    __author__ = "GamehunterKaan"
    __version__ = "2.1.5"

    args = cli()
    console = Console(record=True, color_system=None if args.no_color else "truecolor")
    log = Logger(console)

    if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    print_banner(console)
    vuln_api_key, shodan_api_key, zoomeye_api_key, openai_api_key = InitArgsAPI(args, log)
    api_keys_used = sum([1 for key in [vuln_api_key, shodan_api_key, zoomeye_api_key, openai_api_key] if key])
    check_version(__version__, log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    ReportMethod, ReportObject = InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, api_keys_used, openai_api_key, console, log)

    if args.exploit:
        StartExploiting(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, zoomeye_api_key, openai_api_key, console, log)
    else:
        StartScanning(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, zoomeye_api_key, openai_api_key, console, log)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
