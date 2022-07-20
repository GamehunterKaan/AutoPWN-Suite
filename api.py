from json import dumps
from typing import Any, Dict, List, Type, Union

from nmap import PortScanner

from modules.nist_search import searchCVE
from modules.searchvuln import GenerateKeyword
from modules.utils import fake_logger, is_root

JSON = Union[Dict[str, Any], List[Any], int, str, float, bool, Type[None]]


class AutoScanner:
    def __init__(self) -> None:
        self.scan_results = {}

    def __str__(self) -> str:
        return str(self.scan_results)

    def InitHostInfo(self, target_key: JSON) -> JSON:
        os_info = {}
        try:
            mac = target_key["addresses"]["mac"]
        except (KeyError, IndexError):
            mac = "Unknown"

        try:
            vendor = target_key["vendor"][0]
        except (KeyError, IndexError):
            vendor = "Unknown"

        try:
            os_name = target_key["osmatch"][0]["name"]
        except (KeyError, IndexError):
            os_name = "Unknown"

        try:
            os_accuracy = target_key["osmatch"][0]["accuracy"]
        except (KeyError, IndexError):
            os_accuracy = "Unknown"

        try:
            os_type = target_key["osmatch"][0]["osclass"][0]["type"]
        except (KeyError, IndexError):
            os_type = "Unknown"

        os_info["mac"] = mac
        os_info["vendor"] = vendor
        os_info["os_name"] = os_name
        os_info["os_accuracy"] = os_accuracy
        os_info["os_type"] = os_type

        return os_info

    def ParseVulnInfo(self, vuln):
        vuln_info = {}
        vuln_info["description"] = vuln.description
        vuln_info["severity"] = vuln.severity
        vuln_info["severity_score"] = vuln.severity_score
        vuln_info["details_url"] = vuln.details_url
        vuln_info["exploitability"] = vuln.exploitability

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

        if scan_speed and scan_speed in range(0, 6):
            scan_args.append("-T")
            scan_args.append(str(scan_speed))
        elif scan_speed and not scan_speed in range(0, 6):
            raise Exception("Scanspeed must be in range of 0, 5.")

        if is_root() and os_scan:
            scan_args.append("-O")
        elif os_scan:
            raise Exception("Root privileges are required for os scan.")

        if type(nmap_args) == list:
            for arg in nmap_args:
                scan_args.append(arg)
        elif type(nmap_args) == str:
            scan_args.append(nmap_args)

        scan_arguments = " ".join(scan_args)

        return scan_arguments

    def SearchVuln(
        self, port_key: JSON, apiKey: str = None, debug: bool = False
    ) -> JSON:
        product = port_key["product"]
        version = port_key["version"]
        log = fake_logger()

        keyword = GenerateKeyword(product, version)
        if keyword == "":
            return

        if debug:
            print(f"Searching for keyword {keyword} ...")

        Vulnerablities = searchCVE(keyword, log, apiKey)
        if len(Vulnerablities) == 0:
            return

        vulns = {}
        for vuln in Vulnerablities:
            vulns[vuln.CVEID] = self.ParseVulnInfo(vuln)

        return vulns

    def scan(
        self,
        target,
        host_timeout: int = None,
        scan_speed: int = None,
        apiKey: str = None,
        os_scan: bool = False,
        scan_vulns: bool = True,
        nmap_args=None,
        debug: bool = False,
    ) -> JSON:
        if type(target) == str:
            target = [target]

        log = fake_logger()
        nm = PortScanner()
        scan_arguments = self.CreateScanArgs(
            host_timeout, scan_speed, os_scan, nmap_args
        )
        for host in target:
            if debug:
                print(f"Scanning {host} ...")

            nm.scan(hosts=host, arguments=scan_arguments)
            try:
                port_scan = nm[host]["tcp"]
            except KeyError:
                pass
            else:
                self.scan_results[host] = {}
                self.scan_results[host]["ports"] = port_scan

            if os_scan and is_root():
                os_info = self.InitHostInfo(nm[host])
                self.scan_results[host]["os"] = os_info

            if not scan_vulns:
                continue

            vulns = {}
            for port in nm[host]["tcp"]:
                product = nm[host]["tcp"][port]["product"]
                Vulnerablities = self.SearchVuln(nm[host]["tcp"][port], apiKey, debug)
                if Vulnerablities:
                    vulns[product] = Vulnerablities

            self.scan_results[host]["vulns"] = vulns

        return self.scan_results

    def save_to_file(self, filename: str = "autopwn.json") -> None:
        with open(filename, "w") as output:
            json_object = dumps(self.scan_results)
            output.write(json_object)
