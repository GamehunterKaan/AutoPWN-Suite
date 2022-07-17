from json import dumps
from typing import Any, Dict, List, Type, Union

from nmap import PortScanner

from modules.nist_search import searchCVE
from modules.utils import is_root

JSON = Union[Dict[str, Any], List[Any], int, str, float, bool, Type[None]]


def InitHostInfo(target_key):
    try:
        mac = target_key["addresses"]["mac"]
    except (KeyError, IndexError):
        mac = "Unknown"

    try:
        vendor = target_key["vendor"][0]
    except (KeyError, IndexError):
        vendor = "Unknown"

    try:
        os = target_key["osmatch"][0]["name"]
    except (KeyError, IndexError):
        os = "Unknown"

    try:
        os_accuracy = target_key["osmatch"][0]["accuracy"]
    except (KeyError, IndexError):
        os_accuracy = "Unknown"

    try:
        os_type = target_key["osmatch"][0]["osclass"][0]["type"]
    except (KeyError, IndexError):
        os_type = "Unknown"

    return mac, vendor, os, os_accuracy, os_type


class AutoScanner:
    class fake_logger:
        def logger(self, exception_ : str, message : str):
            pass

    def __init__(self) -> None:
        self.scan_results = {}

    def __str__(self) -> str:
        return str(self.scan_results)

    def scan(
            self,
            target,
            host_timeout=None,
            scan_speed=None,
            apiKey=None,
            debug=False,
            output_file=None,
        ) -> JSON:
        if type(target) == str:
            target = [target]
        elif not type(target) in [str, list]:
            raise TypeError("Host argument must be str or list.")

        log = self.fake_logger()
        nm = PortScanner()

        scan_args = ["-sV"]

        if host_timeout:
            scan_args.append("--host-timeout")
            scan_args.append(str(host_timeout))

        if scan_speed and scan_speed in range(0, 6):
            scan_args.append("-T")
            scan_args.append(str(scan_speed))
        elif scan_speed and not scan_speed in range(0, 6):
            raise Exception("Scanspeed must be in range of 0, 6.")

        if is_root():
            scan_args.append("-O")

        scan_arguments = " ".join(scan_args)
        
        self.scan_results = {}
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

            if "-O" in scan_args:
                os_info = {}
                os_info["mac"] = nm[host]["addresses"]["mac"]
                os_info["vendor"] = nm[host]["vendor"][0]
                os_info["os"] = nm[host]["osmatch"][0]["name"]
                os_info["accuracy"] = nm[host]["osmatch"][0]["accuracy"]
                os_info["type"] = nm[host]["osmatch"][0]["osclass"][0]["type"]
                self.scan_results[host]["os"] = os_info

            vulns = {}
            for port in nm[host]["tcp"]:
                self.scan_results[host]["vulns"] = {}
                product = nm[host]["tcp"][port]["product"]
                version = nm[host]["tcp"][port]["version"]

                keyword = f"{product} {version}"

                if debug:
                    print(f"Searching for keyword {keyword}")

                Vulnerablities = searchCVE(keyword, log, apiKey)
                
                if len(Vulnerablities) == 0:
                    continue

                vulns["product"] = {}
                for vuln in Vulnerablities:
                    vulns["product"][vuln.CVEID] = {}
                    vulns["product"][vuln.CVEID]["description"] = vuln.description
                    vulns["product"][vuln.CVEID]["severity"] = vuln.severity
                    vulns["product"][vuln.CVEID]["severity_score"] = vuln.severity_score
                    vulns["product"][vuln.CVEID]["details_url"] = vuln.details_url
                    vulns["product"][vuln.CVEID]["exploitability"] = vuln.exploitability

                self.scan_results[host]["vulns"] = vulns

        if output_file:
            with open(output_file, "w") as output:
                json_object = dumps(self.scan_results)
                output.write(json_object)

        return self.scan_results

scanner = AutoScanner()
results = scanner.scan("192.168.0.29")
print(results)
print(results["192.168.0.29"].keys())
print(results["192.168.0.29"]["vulns"].keys())
