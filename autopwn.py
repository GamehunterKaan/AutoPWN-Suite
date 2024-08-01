from datetime import datetime

from rich.console import Console

from modules.banners import print_banner
from modules.exploit import (exploit_vulnerabilities, metasploitSearch,
                             search_exploits)
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import (AnalyseScanResults, DiscoverHosts, NoiseScan,
                             PortScan, ShodanScan, display_shodan_results)
from modules.searchvuln import SearchSploits, VulnerableSoftware
from modules.utils import (GetHostsToScan, GetShodanVulns, GetZoomEyeVulns,
                           InitArgsAPI, InitArgsConf, InitArgsMode,
                           InitArgsScanType, InitArgsTarget, InitAutomation,
                           InitReport, ParamPrint, SaveOutput, ScanMode,
                           UserConfirmation, WebScan, check_nmap,
                           check_version, cli, resolve_hostnames_to_ips)
from modules.web.webvuln import webvuln


def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, shodan_api_key, zoomeye_api_key, console, log, exploit, max_exploits=10
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
    if args.metasploit_scan:
        log.logger("info", "Metasploit scan enabled.")
    ScanWeb = args.web or WebScan()

    all_vulnerabilities = []

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags, shodan_api_key
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, host, shodan_results=None)
        if ScanVulns and PortArray and len(PortArray) > 0:
            VulnsArray = []
            if args.metasploit_scan:
                metasploit_vulns = []
                for port in PortArray:
                    metasploit_vulns.extend(metasploitSearch(port[3]))
                for vuln in metasploit_vulns:
                    if isinstance(vuln, dict) and all(key in vuln for key in ['name', 'fullname']):
                        vuln_obj = VulnerableSoftware(
                            title=vuln['name'],
                            CVEs=[vuln['fullname']],
                            severity_score=0.0,
                            exploitability=0.0
                        )
                        all_vulnerabilities.append(vuln_obj)
                    else:
                        log.logger("warning", f"Vulnerability data missing required keys: {vuln}")
            else:
                sploits = SearchSploits(PortArray, log, console, apiKey)
                for sploit in sploits:
                    vuln_obj = VulnerableSoftware(
                        title=sploit['title'],
                        CVEs=sploit['CVEs'],
                        severity_score=sploit['severity_score'],
                        exploitability=sploit['exploitability']
                    )
                    all_vulnerabilities.append(vuln_obj)
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
            if DownloadExploits and len(all_vulnerabilities) > 0:
                GetExploitsFromArray(all_vulnerabilities, log, console, console, max_exploits=max_exploits)
    
    if len(all_vulnerabilities) > 0:
        GetExploitsFromArray(all_vulnerabilities, log, console, console, max_exploits=max_exploits)
        if exploit:
            exploit_vulnerabilities(all_vulnerabilities, targetarg, log, console, max_exploits=max_exploits)
            
    if ScanWeb:
        for host in Targets:
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

    StartScanning(args, targetarg, scantype, scanmode, vuln_api_key, shodan_api_key, zoomeye_api_key, console, log, args.exploit)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
