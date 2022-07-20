from dataclasses import dataclass
from enum import Enum
from multiprocessing import Process
from time import sleep

from nmap import PortScanner
from rich import box
from rich.table import Table

from modules.logger import banner
from modules.utils import GetIpAdress, ScanMode, ScanType, is_root


@dataclass()
class TargetInfo:
    mac: str = "Unknown"
    vendor: str = "Unknown"
    os: str = "Unknown"
    os_accuracy: int = 0
    os_type: str = "Unknown"

    def colored(self) -> str:

        return (
            f"[yellow]MAC Address :[/yellow] {self.mac}\n"
            + f"[yellow]Vendor :[/yellow] {self.vendor}\n"
            + f"[yellow]OS :[/yellow] {self.os}\n"
            + f"[yellow]Accuracy :[/yellow] {self.os_accuracy}\n"
            + f"[yellow]Type :[/yellow] {self.os_type[:20]}\n"
        )

    def __str__(self) -> str:
        return (
            f"MAC Address : {self.mac}"
            + f" Vendor : {self.vendor}\n"
            + f"OS : {self.os}"
            + f" Accuracy : {self.os_accuracy}"
            + f" Type : {self.os_type}"
            + "\n"
        )


# do a ping scan using nmap
def TestPing(target, mode=ScanMode.Normal) -> list:
    nm = PortScanner()
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade and is_root():
        nm.scan(hosts=target, arguments="-sn -T 2 -f -g 53 --data-length 10")
    else:
        nm.scan(hosts=target, arguments="-sn")

    return nm.all_hosts()


# do a arp scan using nmap
def TestArp(target, mode=ScanMode.Normal) -> list:
    nm = PortScanner()
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade:
        nm.scan(hosts=target, arguments="-sn -PR -T 2 -f -g 53 --data-length 10")
    else:
        nm.scan(hosts=target, arguments="-sn -PR")

    return nm.all_hosts()


# run a port scan on target using nmap
def PortScan(
    target,
    log,
    scanspeed=5,
    host_timeout=240,
    mode=ScanMode.Normal,
    customflags="",
) -> PortScanner:

    log.logger("info", f"Scanning {target} for open ports ...")

    nm = PortScanner()
    try:
        if is_root():
            if mode == ScanMode.Evade:
                nm.scan(
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
                    ),
                )
            else:
                nm.scan(
                    hosts=target,
                    arguments=" ".join(
                        [
                            "-sS",
                            "-sV",
                            "--host-timeout",
                            str(host_timeout),
                            "-Pn",
                            "-O",
                            "-T",
                            str(scanspeed),
                            customflags,
                        ]
                    ),
                )
        else:
            nm.scan(
                hosts=target,
                arguments=" ".join(
                    [
                        "-sV",
                        "--host-timeout",
                        str(host_timeout),
                        "-Pn",
                        "-T",
                        str(scanspeed),
                        customflags,
                    ]
                ),
            )
    except Exception as e:
        raise SystemExit(f"Error: {e}")
    else:
        return nm


def CreateNoise(target):
    nm = PortScanner()
    while True:
        try:
            if is_root():
                nm.scan(hosts=target, arguments="-A -T 5 -D RND:10")
            else:
                nm.scan(hosts=target, arguments="-A -T 5")
        except KeyboardInterrupt:
            raise SystemExit("Ctr+C, aborting.")
        else:
            break


def NoiseScan(target, log, console, scantype=ScanType.ARP, noisetimeout=None) -> None:
    banner("Creating noise...", "green", console)

    Uphosts = TestPing(target)
    if scantype == ScanType.ARP:
        if is_root():
            Uphosts = TestArp(target)

    try:
        with console.status("Creating noise ...", spinner="line"):
            NoisyProcesses = []
            for host in Uphosts:
                log.logger("info", f"Started creating noise on {host}...")
                P = Process(target=CreateNoise, args=(host,))
                NoisyProcesses.append(P)
                P.start()
                if noisetimeout:
                    sleep(noisetimeout)
                else:
                    while True:
                        sleep(1)

        log.logger("info", "Noise scan complete!")
        for P in NoisyProcesses:
            P.terminate()
        raise SystemExit
    except KeyboardInterrupt:
        log.logger("error", "Noise scan interrupted!")
        raise SystemExit


def DiscoverHosts(target, console, scantype=ScanType.ARP, mode=ScanMode.Normal) -> list:
    if isinstance(target, list):
        banner(
            f"Scanning {len(target)} target(s) using {scantype.name} scan ...",
            "green",
            console,
        )
    else:
        banner(f"Scanning {target} using {scantype.name} scan ...", "green", console)

    OnlineHosts = TestPing(target, mode)
    if scantype == ScanType.ARP:
        OnlineHosts = TestArp(target, mode)

    return OnlineHosts


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

    return TargetInfo(
        mac=mac,
        vendor=vendor,
        os=os,
        os_accuracy=os_accuracy,
        os_type=os_type,
    )


def InitPortInfo(port):
    state = "Unknown"
    service = "Unknown"
    product = "Unknown"
    version = "Unknown"

    if not len(port["state"]) == 0:
        state = port["state"]

    if not len(port["name"]) == 0:
        service = port["name"]

    if not len(port["product"]) == 0:
        product = port["product"]

    if not len(port["version"]) == 0:
        version = port["version"]

    return state, service, product, version


def AnalyseScanResults(nm, log, console, target=None) -> list:
    """
    Analyse and print scan results.
    """
    HostArray = []
    if target is None:
        target = nm.all_hosts()[0]

    try:
        nm[target]
    except KeyError:
        log.logger("warning", f"Target {target} seems to be offline.")
        return []

    CurrentTargetInfo = InitHostInfo(nm[target])

    if is_root():
        if nm[target]["status"]["reason"] in ["localhost-response", "user-set"]:
            log.logger("info", f"Target {target} seems to be us.")
    elif GetIpAdress() == target:
        log.logger("info", f"Target {target} seems to be us.")

    if len(nm[target].all_tcp()) == 0:
        log.logger("warning", f"Target {target} seems to have no open ports.")
        return HostArray

    banner(f"Portscan results for {target}", "green", console)

    if not CurrentTargetInfo.mac == "Unknown" and not CurrentTargetInfo.os == "Unknown":
        console.print(CurrentTargetInfo.colored(), justify="center")

    table = Table(box=box.MINIMAL)

    table.add_column("Port", style="cyan")
    table.add_column("State", style="white")
    table.add_column("Service", style="blue")
    table.add_column("Product", style="red")
    table.add_column("Version", style="purple")

    for port in nm[target]["tcp"].keys():
        state, service, product, version = InitPortInfo(nm[target]["tcp"][port])
        table.add_row(str(port), state, service, product, version)

        if state == "open":
            HostArray.insert(len(HostArray), [target, port, service, product, version])

    console.print(table, justify="center")

    return HostArray
