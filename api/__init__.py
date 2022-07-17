from typing import Any, Dict, List, Type, Union

# from modules.nist_search import searchCVE
from nmap import PortScanner

JSON = Union[Dict[str, Any], List[Any], int, str, float, bool, Type[None]]

class AutoScanner:
    def __init__(self) -> None:
        self.scan_results = {}
        pass

    def __str__(self) -> str:
        return str(self.scan_results)

    def scan(
            self,
            target,
            host_timeout=None,
            scan_speed=None,
            apiKey=None,
            debug=False
        ) -> JSON:
        if type(target) == str:
            target = [target]
        elif not type(target) in [str, list]:
            raise TypeError("Host argument must be str or list.")

        nm = PortScanner()

        scan_args = ["-sV", "-O"]

        if host_timeout:
            scan_args.append("--host-timeout")
            scan_args.append(str(host_timeout))

        if scan_speed and scan_speed in range(0, 6):
            scan_args.append("-T")
            scan_args.append(str(scan_speed))
        elif scan_speed and not scan_speed in range(0, 6):
            raise Exception("Scanspeed must be in range of 0, 6.")

        scan_args = " ".join(scan_args)
        
        self.scan_results = {}
        for host in target:
            if debug:
                print(f"Scanning {host} ...")
            result = nm.scan(hosts=host, arguments=scan_args)
            self.scan_results[host]["nmap"] = result[target]

        print(self.scan_results)

scanner = AutoScanner
AutoScanner.scan("192.168.0.28")