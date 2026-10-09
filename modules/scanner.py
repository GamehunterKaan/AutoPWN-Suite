from dataclasses import dataclass
from enum import Enum
from multiprocessing import Process
from time import sleep

from nmap import PortScanner
from rich import box
from rich.table import Table

from modules.logger import banner
from modules.utils import GetIpAdress, ScanMode, ScanType, is_root
from modules.nmap_progress import scan_with_progress, ScanCancelled


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
def TestPing(target, mode=ScanMode.Normal, *, offline=False, progress=None, should_stop=None) -> list:
    nm = PortScanner()
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade and is_root():
        arguments = "-sn -T 2 -f -g 53 --data-length 10"
    else:
        arguments = "-sn"
    arguments += " -n" if offline else ""
    if progress is not None:
        scan_with_progress(nm, target, arguments, progress, should_stop)
    else:
        nm.scan(hosts=target, arguments=arguments)

    return nm.all_hosts()


# do a arp scan using nmap
def TestArp(target, mode=ScanMode.Normal, *, offline=False, progress=None, should_stop=None) -> list:
    nm = PortScanner()
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade:
        arguments = "-sn -PR -T 2 -f -g 53 --data-length 10"
    else:
        arguments = "-sn -PR"
    arguments += " -n" if offline else ""
    if progress is not None:
        scan_with_progress(nm, target, arguments, progress, should_stop)
    else:
        nm.scan(hosts=target, arguments=arguments)

    return nm.all_hosts()


# run a port scan on target using nmap
def PortScan(
    target,
    log,
    scanspeed=5,
    host_timeout=240,
    mode=ScanMode.Normal,
    customflags="",
    *, progress=None, should_stop=None,
) -> PortScanner:

    log.logger("info", f"Scanning {target} for open ports ...")

    nm = PortScanner()
    # If customflags already specifies a scan technique (-sS, -sU, -sT, etc.),
    # don't add the default -sS so the techniques don't conflict.
    import re as _re
    _has_scan_type = bool(_re.search(r'-s[STAUWMNFX]', customflags))
    default_scan = [] if _has_scan_type else ["-sS"]
    try:
        if is_root():
            base_flags = default_scan + [
                "-sV",
                "--host-timeout",
                str(host_timeout),
                "-Pn",
                "-O",
                "-T",
                str(scanspeed),
            ]
            if mode == ScanMode.Evade:
                base_flags += ["-f", "-g", "53", "--data-length", "10"]
            arguments = " ".join(base_flags + [customflags])
        else:
            arguments = " ".join(
                [
                    "-sV",
                    "--host-timeout",
                    str(host_timeout),
                    "-Pn",
                    "-T",
                    str(scanspeed),
                    customflags,
                ]
            )
        if progress is not None:
            scan_with_progress(nm, target, arguments, progress, should_stop)
        else:
            nm.scan(hosts=target, arguments=arguments)
    except ScanCancelled:
        raise
    except Exception as e:
        raise SystemExit(f"Error: {e}")
    else:
        return nm


def CreateNoise(target, offline=False) -> None:
    nm = PortScanner()
    while True:
        try:
            if is_root():
                nm.scan(hosts=target, arguments="-A -T 5 -D RND:10" + (" -n" if offline else ""))
            else:
                nm.scan(hosts=target, arguments="-A -T 5" + (" -n" if offline else ""))
        except KeyboardInterrupt:
            raise SystemExit("Ctr+C, aborting.")
        else:
            break


def NoiseScan(target, log, console, scantype=ScanType.ARP, noisetimeout=None, *, offline=False) -> None:
    banner("Creating noise...", "green", console)

    Uphosts = TestPing(target, offline=True) if offline else TestPing(target)
    if scantype == ScanType.ARP:
        if is_root():
            Uphosts = TestArp(target, offline=True) if offline else TestArp(target)

    if not Uphosts:
        log.logger("warning", "No hosts found for noise scan.")
        raise SystemExit(1)

    NoisyProcesses = []
    try:
        with console.status("Creating noise ...", spinner="line"):
            for host in Uphosts:
                log.logger("info", f"Started creating noise on {host}...")
                P = Process(target=CreateNoise, args=(host, True) if offline else (host,))
                P.start()
                NoisyProcesses.append(P)

            if noisetimeout:
                sleep(noisetimeout)
            else:
                while True:
                    sleep(1)

        log.logger("info", "Noise scan complete!")
        raise SystemExit
    except KeyboardInterrupt:
        log.logger("error", "Noise scan interrupted!")
        raise SystemExit
    finally:
        for P in NoisyProcesses:
            if P.is_alive():
                P.terminate()
        for P in NoisyProcesses:
            P.join(timeout=2)


def DiscoverHosts(target, console, scantype=ScanType.ARP, mode=ScanMode.Normal, *, offline=False, progress=None, should_stop=None) -> list:
    if isinstance(target, list):
        banner(
            f"Scanning {len(target)} target(s) using {scantype.name} scan ...",
            "green",
            console,
        )
    else:
        banner(f"Scanning {target} using {scantype.name} scan ...", "green", console)

    if progress is not None:
        scan = TestArp if scantype == ScanType.ARP else TestPing
        return scan(target, mode, offline=offline, progress=progress, should_stop=should_stop)
    if scantype == ScanType.ARP:
        OnlineHosts = TestArp(target, mode, offline=True) if offline else TestArp(target, mode)
    else:
        OnlineHosts = TestPing(target, mode, offline=True) if offline else TestPing(target, mode)

    return OnlineHosts


def InitHostInfo(target_key) -> TargetInfo:
    try:
        mac = target_key["addresses"]["mac"]
    except (KeyError, IndexError):
        mac = "Unknown"

    try:
        vendors = target_key["vendor"]
        if isinstance(vendors, dict):
            vendor = vendors.get(mac) or next(iter(vendors.values()), "Unknown")
        else:
            vendor = vendors[0]
    except (KeyError, IndexError, TypeError):
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


def InitPortInfo(port) -> tuple[str, str, str, str]:
    return tuple(port.get(key) or "Unknown" for key in ("state", "name", "product", "version"))


def ResolveScanHosts(nm, target=None) -> list[str]:
    """Resolve a requested hostname/range to the host keys Nmap returned."""
    if target is not None:
        try:
            nm[target]
        except KeyError:
            pass
        else:
            return [target]
    return list(nm.all_hosts())


def AnalyseScanResults(nm, log, console, target=None) -> list:
    """
    Analyse and print scan results.
    """
    HostArray = []
    hosts = ResolveScanHosts(nm, target)
    if not hosts:
        log.logger("warning", f"Target {target or 'scan'} seems to be offline.")
        return []
    if target is None or hosts != [target]:
        for host in hosts:
            HostArray.extend(AnalyseScanResults(nm, log, console, host))
        return HostArray

    CurrentTargetInfo = InitHostInfo(nm[target])

    if is_root():
        try:
            reason = nm[target]["status"]["reason"]
        except (KeyError, TypeError):
            reason = ""
        if reason in ["localhost-response", "user-set"]:
            log.logger("info", f"Target {target} seems to be us.")
    else:
        try:
            if GetIpAdress() == target:
                log.logger("info", f"Target {target} seems to be us.")
        except OSError:
            pass

    try:
        tcp_ports = nm[target]["tcp"]
    except KeyError:
        tcp_ports = {}
    try:
        udp_ports = nm[target]["udp"]
    except KeyError:
        udp_ports = {}

    if len(tcp_ports) == 0 and len(udp_ports) == 0:
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

    for port, data in tcp_ports.items():
        state, service, product, version = InitPortInfo(data)
        table.add_row(str(port), state, service, product, version)

        if state == "open":
            HostArray.insert(len(HostArray), [target, port, service, product, version])

    for port, data in udp_ports.items():
        state, service, product, version = InitPortInfo(data)
        table.add_row(f"{port}/udp", state, service, product, version)
        if state == "open":
            HostArray.append([target, port, service, product, version, "udp"])

    console.print(table, justify="center")

    return HostArray
