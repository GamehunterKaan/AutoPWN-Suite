from multiprocessing import Process
from dataclasses import dataclass
from time import sleep
from enum import Enum

try:
    from os import getuid
except ImportError:
    from ctypes import windll

from rich.console import Console

from modules.nmap import PortScanner
from modules.logger import (
    info,
    error,
    println,
    banner,
    colors,
    bcolors
)


@dataclass
class PortInfo:
    port : int
    protocol : str
    state : str
    service : str
    product : str
    version : str


@dataclass()
class TargetInfo:
    ip : str
    mac : str = "Unknown"
    vendor : str = "Unknown"
    os : str = "Unknown"
    os_accuracy : int = 0
    os_type : str = "Unknown"

    def colored(self):
        return (
            f"{bcolors.yellow}MAC Address : {bcolors.endc} {self.mac}\n"
            + f"{bcolors.yellow}Vendor : {bcolors.endc} {self.vendor}\n"
            + f"{bcolors.yellow}OS : {bcolors.endc} {self.os}\n"
            + f"{bcolors.yellow}Accuracy : {bcolors.endc} {self.os_accuracy}"
            + f"{bcolors.yellow}Type : {bcolors.endc} {self.os_type[:20]}\n"
        )

    def __str__(self):
        return (
            f"MAC Address : {self.mac}"
            + f" Vendor : {self.vendor}\n"
            + f"OS : {self.os}"
            + f" Accuracy : {self.os_accuracy}"
            + f" Type : {self.os_type}" + "\n"
        )


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


class ScanType(Enum):
    Ping = 0
    ARP = 1


def is_root(): # this function is used everywhere, so it"s better to put it here
    try:
        return getuid() == 0
    except Exception as e:
        return windll.shell32.IsUserAnAdmin() == 1


# this function is for turning a list of hosts into a single string
def listToString(s):
    str1 = " "
    return (str1.join(s))

#do a ping scan using nmap
def TestPing(target, mode=ScanMode.Normal):
    nm = PortScanner()
    if isinstance(target, list):
        target = listToString(target)
    if mode == ScanMode.Evade and is_root():
        resp = nm.scan(
            hosts=target,
            arguments="-sn -T 2 -f -g 53 --data-length 10"
        )
    else:
        resp = nm.scan(hosts=target, arguments="-sn")

    return nm.all_hosts()


#do a arp scan using nmap
def TestArp(target, mode=ScanMode.Normal):
    nm = PortScanner()
    if isinstance(target, list):
        target = listToString(target)
    if mode == ScanMode.Evade:
        resp = nm.scan(
            hosts=target,
            arguments="-sn -PR -T 2 -f -g 53 --data-length 10"
        )
    else:
        resp = nm.scan(hosts=target, arguments="-sn -PR")

    return nm.all_hosts()


#run a port scan on target using nmap
def PortScan(target, scanspeed=5, mode=ScanMode.Normal, customflags=""):
    banner("Running a portscan on host " + str(target) + "...", colors.green)

    nm = PortScanner()

    try:
        if is_root():
            if mode == ScanMode.Evade:
                resp = nm.scan(
                    hosts=target,
                    arguments=" ".join(
                        [
                            "-sS",
                            "-sV",
                            "-O",
                            "-Pn",
                            "-T",
                            "2",
                            "-f",
                            "-g",
                            "53",
                            "--data-length",
                            "10",
                            customflags,
                        ]
                    )
                )
            else:
                resp = nm.scan(
                    hosts=target,
                    arguments=" ".join(
                        [
                            "-sS",
                            "-sV",
                            "--host-timeout",
                            "60",
                            "-Pn",
                            "-O",
                            "-T",
                            str(scanspeed),
                            customflags,
                        ]
                    )
                )
        else:
            resp = nm.scan(
                hosts=target,
                arguments=" ".join(
                    [
                        "-sV",
                        "--host-timeout",
                        "60",
                        "-Pn",
                        "-T",
                        str(scanspeed),
                        customflags,
                    ]
                )
            )
    except Exception as e:
        raise SystemExit(f"Error: {e}")
    else:
        return nm


def CreateNoise(target):
    nm = PortScanner()
    try:
        if is_root():
            while True:
                resp = nm.scan(hosts=target, arguments="-A -T 5 -D RND:10")
        else:
            while True:
                resp = nm.scan(hosts=target, arguments="-A -T 5")
    except KeyboardInterrupt:
        raise SystemExit("Ctr+C, aborting.")


def NoiseScan(target, scantype=ScanType.ARP, timeout=None):
    banner("Creating noise...", colors.green)

    if scantype == ScanType.ARP:
        if is_root():
            Uphosts = TestArp(target)
    else:
        Uphosts = TestPing(target)

    NoisyProcesses = []
    for host in Uphosts:
        info(
            f"Started creating noise on {host}..."
        )
        P = Process(target=CreateNoise, args=(host,))
        NoisyProcesses.append(P)
        P.start()

    try:
        if timeout:
            while True:
                print("|   " + str(timeout) + " seconds left!", end="     \r")
                sleep(0.25)
                print("/   " + str(timeout) + " seconds left!", end="     \r")
                sleep(0.25)
                print("-   " + str(timeout) + " seconds left!", end="     \r")
                sleep(0.25)
                print("\\   " + str(timeout) + " seconds left!", end="     \r")
                sleep(0.25)
                timeout -= 1
                if timeout == 0:
                    println("\nNoise scan complete!")
                    for P in NoisyProcesses:
                        P.terminate()
                    raise SystemExit
    except KeyboardInterrupt:
        error("\nNoise scan interrupted!")
        for P in NoisyProcesses:
            P.terminate()
        raise SystemExit


def DiscoverHosts(
        target,
        scantype=ScanType.ARP,
        scanspeed=3,
        mode=ScanMode.Normal
    ):
    if isinstance(target, list):
        banner(
            f"Scanning {len(target)} target(s) using {scantype.name} scan...",
            colors.green
        )
    else:
        banner(
            f"Scanning {target} using {scantype.name} scan...", colors.green
        )

    if scantype == ScanType.Ping:
        OnlineHosts = TestPing(target, mode)
        return OnlineHosts
    elif scantype == ScanType.ARP:
        OnlineHosts = TestArp(target, mode)
        return OnlineHosts


def InitHostInfo(nm, target):
    try:
        mac = nm[target]["addresses"]["mac"]
    except (KeyError, IndexError):
        mac = "Unknown"

    try:
        vendor = nm[target]["vendor"][0]
    except (KeyError, IndexError):
        vendor = "Unknown"

    try:
        os = nm[target]["osmatch"][0]["name"]
    except (KeyError, IndexError):
        os = "Unknown"

    try:
        os_accuracy = nm[target]["osmatch"][0]["accuracy"]
    except (KeyError, IndexError):
        os_accuracy = "Unknown"

    try:
        os_type = nm[target]["osmatch"][0]["osclass"][0]["type"]
    except (KeyError, IndexError):
        os_type = "Unknown"

    return mac, vendor, os, os_accuracy, os_type


def AnalyseScanResults(nm, target=None):
    """
    Analyse and print scan results.
    """

    console = Console()
    HostArray = []
    if target is None:
        target = nm.all_hosts()[0]

    try:
        nm[target]
    except KeyError:
        error(f"Target {target} seems to be offline.")
        return []

    mac, vendor, os, os_accuracy, os_type = InitHostInfo(nm, target)
    CurrentTargetInfo = TargetInfo(
            target, mac, vendor, os, os_accuracy, os_type
        )

    println(CurrentTargetInfo.colored().center(60))

    reason = nm[target]["status"]["reason"]

    if is_root():
        if reason in ["localhost-response", "user-set"]:
            info(f"Target {target} seems to be us.")

    # we cant detect if the host is us or not, if we are not root
    # we could get our ip address and compare them but i think it"s not quite necessary

    if len(nm[target].all_protocols()) == 0:
        error(f"Target {target} seems to have no open ports.")
        return HostArray

    for port in nm[target]["tcp"].keys():
        if not len(nm[str(target)]["tcp"][int(port)]["state"]) == 0:
            state = nm[str(target)]["tcp"][int(port)]["state"]
        else:
            state = "Unknown"

        if not len(nm[str(target)]["tcp"][int(port)]["name"]) == 0:
            service = nm[str(target)]["tcp"][int(port)]["name"]
        else:
            service = "Unknown"

        if not len(nm[str(target)]["tcp"][int(port)]["product"]) == 0:
            product = nm[str(target)]["tcp"][int(port)]["product"]
        else:
            product = "Unknown"

        if not len(nm[str(target)]["tcp"][int(port)]["version"]) == 0:
            version = nm[str(target)]["tcp"][int(port)]["version"]
        else:
            version = "Unknown"

        console.print(
            f"[cyan]Port: [/cyan] {port}\n"
            + f"[cyan]State: [/cyan] {state}\n"
            + f"[cyan]Service: [/cyan] {service[:15]}\n"
            + f"[cyan]Product: [/cyan] {product[:20]}\n"
            + f"[cyan]Version: [/cyan] {version[:15]}"
        )

        if state == "open":
            HostArray.insert(
                len(HostArray), [target, port, service, product, version]
            )

    return HostArray
