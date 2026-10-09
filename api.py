from json import dumps
from typing import Any, Dict, List, Type, Union

from nmap import PortScanner

from modules.nist_search import searchCVE, VulnerabilityLookup
from modules.searchvuln import GenerateKeyword
from modules.scanner import InitHostInfo, ResolveScanHosts
from modules.utils import fake_logger, is_root

JSON = Union[Dict[str, Any], List[Any], int, str, float, bool, Type[None]]


class AutoScanner:
    def __init__(self) -> None:
        self.scan_results = {}

    def __str__(self) -> str:
        return str(self.scan_results)

    def InitHostInfo(self, target_key: JSON) -> JSON:
        info = InitHostInfo(target_key)
        return {"mac": info.mac, "vendor": info.vendor, "os_name": info.os,
                "os_accuracy": info.os_accuracy, "os_type": info.os_type}

    def ParseVulnInfo(self, vuln):
        vuln_info = {}
        vuln_info["description"] = vuln.description
        vuln_info["severity"] = vuln.severity
        vuln_info["severity_score"] = vuln.severity_score
        vuln_info["details_url"] = vuln.details_url
        vuln_info["exploitability"] = vuln.exploitability
        vuln_info["data_source"] = vuln.data_source
        vuln_info["database_updated_at"] = vuln.database_updated_at

        return vuln_info

    def CreateScanArgs(
        self,
        host_timeout,
        scan_speed,
        os_scan: bool,
        nmap_args,
    ) -> str:

        scan_args = ["-sV"]

        if host_timeout:
            scan_args.append("--host-timeout")
            scan_args.append(str(host_timeout))

        if scan_speed is not None and scan_speed in range(0, 6):
            scan_args.append("-T")
            scan_args.append(str(scan_speed))
        elif scan_speed is not None:
            raise Exception("Scanspeed must be in range of 0, 5.")

        if is_root() and os_scan:
            scan_args.append("-O")
        elif os_scan:
            raise Exception("Root privileges are required for os scan.")

        if isinstance(nmap_args, list):
            for arg in nmap_args:
                scan_args.append(arg)
        elif isinstance(nmap_args, str):
            scan_args.append(nmap_args)

        scan_arguments = " ".join(scan_args)

        return scan_arguments

    def SearchVuln(
        self, port_key: JSON, apiKey: str = None, debug: bool = False, *, lookup=None
    ) -> JSON:
        product = port_key.get("product", "")
        version = port_key.get("version", "")
        log = fake_logger()

        keyword = GenerateKeyword(product, version)
        if keyword == "":
            return

        if debug:
            print(f"Searching for keyword {keyword} ...")

        Vulnerablities = (lookup.search(keyword, log, apiKey) if lookup is not None
                          else searchCVE(keyword, log, apiKey, strict=True))
        if len(Vulnerablities) == 0:
            return

        vulns = {}
        for vuln in Vulnerablities:
            vulns[vuln.CVEID] = self.ParseVulnInfo(vuln)

        return vulns

    def scan(
        self, target, host_timeout=None, scan_speed=None, apiKey=None,
        os_scan=False, scan_vulns=True, nmap_args=None, debug=False, *,
        offline=False, vulnerability_source="auto", vuln_db=None,
    ) -> JSON:
        lookup = VulnerabilityLookup("offline" if offline else vulnerability_source, vuln_db) if scan_vulns else None
        try:
            if offline or vulnerability_source == "offline":
                if isinstance(nmap_args, list):
                    nmap_args = [*nmap_args, "-n"]
                else:
                    nmap_args = ((nmap_args or "") + " -n").strip()
            return self._scan(target, host_timeout, scan_speed, apiKey, os_scan,
                              scan_vulns, nmap_args, debug, lookup=lookup)
        finally:
            if lookup is not None:
                lookup.close()

    def _scan(
        self,
        target,
        host_timeout: int = None,
        scan_speed: int = None,
        apiKey: str = None,
        os_scan: bool = False,
        scan_vulns: bool = True,
        nmap_args=None,
        debug: bool = False,
        *, lookup=None,
    ) -> JSON:
        if type(target) == str:
            target = [target]

        self.scan_results = {}
        nm = PortScanner()
        scan_arguments = self.CreateScanArgs(
            host_timeout, scan_speed, os_scan, nmap_args
        )
        for host in target:
            if debug:
                print(f"Scanning {host} ...")

            nm.scan(hosts=host, arguments=scan_arguments)
            for resolved_host in ResolveScanHosts(nm, host):
                host_data = nm[resolved_host]
                port_scan = host_data.get("tcp", {})
                udp_scan = host_data.get("udp", {})
                result = {"ports": port_scan}
                # Keep the existing TCP ports mapping; UDP uses a separate key so
                # equal TCP/UDP port numbers cannot overwrite one another.
                if "udp" in host_data:
                    result["udp_ports"] = udp_scan
                self.scan_results[resolved_host] = result

                if os_scan:
                    result["os"] = self.InitHostInfo(host_data)
                if not scan_vulns:
                    continue

                vulns = {}
                for ports in (port_scan, udp_scan):
                    for port_data in ports.values():
                        if port_data.get("state") != "open":
                            continue
                        product = port_data.get("product", "")
                        vulnerabilities = self.SearchVuln(port_data, apiKey, debug, lookup=lookup)
                        if vulnerabilities:
                            vulns.setdefault(product, {}).update(vulnerabilities)
                result["vulns"] = vulns

        return self.scan_results

    def save_to_file(self, filename: str = "autopwn.json") -> None:
        with open(filename, "w") as output:
            json_object = dumps(self.scan_results)
            output.write(json_object)
