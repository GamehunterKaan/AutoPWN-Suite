from modules.nmap import PortScanner
from modules.color import print_colored, colors, bcolors
from modules.outfile import WriteToFile
from os import getuid
from multiprocessing import Process
from dataclasses import dataclass
from time import sleep
from enum import Enum

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
            (
                bcolors.yellow + "MAC Address : " + bcolors.endc + "{0:20}" +
                bcolors.yellow + " Vendor : " + bcolors.endc + "{1:30}" + "\n" +
                bcolors.yellow + "OS : " + bcolors.endc + "{2:20}" +
                bcolors.yellow + " Accuracy : " + bcolors.endc + "{3:5}" +
                bcolors.yellow + " Type : " + bcolors.endc + "{4:20}" + "\n"
            ).format(
                    str(self.mac),
                    str(self.vendor),
                    str(self.os[:20]),
                    str(self.os_accuracy),
                    str(self.os_type[:20])
                )
        )

    def __str__(self):
        return (
            (
                "MAC Address : {0:20}" +
                " Vendor : {1:30}" + "\n" +
                "OS : {2:20}" +
                " Accuracy : {3:5}" +
                " Type : {4:20}" + "\n"
            ).format(
                    str(self.mac),
                    str(self.vendor),
                    str(self.os[:20]),
                    str(self.os_accuracy),
                    str(self.os_type[:20])
                )
        )


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2

class ScanType(Enum):
    Ping = 0
    ARP = 1

def is_root():
    return getuid() == 0

# this function is for turning a list of hosts into a single string
def listToString(s): 
    str1 = " "
    return (str1.join(s))

#do a ping scan using nmap
def TestPing(target, mode=ScanMode.Normal):
    nm = PortScanner()
    if type(target) is list:
        target = listToString(target)
    if mode == ScanMode.Evade and is_root():
        resp = nm.scan(hosts=target, arguments="-sn -T 2 -f -g 53 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

#do a arp scan using nmap
def TestArp(target, mode=ScanMode.Normal):
    nm = PortScanner()
    if type(target) is list:
        target = listToString(target)
    if mode == ScanMode.Evade:
        resp = nm.scan(hosts=target, arguments="-sn -PR -T 2 -f -g 53 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

#run a port scan on target using nmap
def PortScan(target, scanspeed=5, mode=ScanMode.Normal, customflags=""):
    print_colored("\n" + "─" * 60, colors.green)
    print_colored(("Running a portscan on host " + str(target) + "...").center(60), colors.green)
    print_colored("─" * 60 + "\n", colors.green)

    WriteToFile("\n" + "─" * 60)
    WriteToFile(("Portscan results for host " + str(target) + ".").center(60))
    WriteToFile("─" * 60 + "\n")

    nm = PortScanner()

    try:
        if is_root():
            if mode == ScanMode.Evade:
                resp = nm.scan(hosts=target, arguments="-sS -sV -O -Pn -T 2 -f -g 53 --data-length 10 %s" % (customflags))
            else:
                resp = nm.scan(hosts=target, arguments="-sS -sV --host-timeout 60 -Pn -O -T %d %s" % (scanspeed, customflags))
        else:
            resp = nm.scan(hosts=target, arguments="-sV --host-timeout 60 -Pn -T %d %s" % (scanspeed, customflags))
    except Exception as e:
        print_colored("Error: %s" % (e), colors.red)
        WriteToFile("Error: %s" % (e))
        exit(0)

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
        pass

def NoiseScan(target, scantype=ScanType.ARP, timeout=None):
    print_colored("\n" + "─" * 60, colors.green)
    print_colored("Creating noise...".center(60), colors.green)
    print_colored("─" * 60 + "\n", colors.green)
    WriteToFile("\nCreating noise...")

    if scantype == ScanType.Ping:
        Uphosts = TestPing(target)
    elif scantype == ScanType.ARP:
        if is_root():
            Uphosts = TestArp(target)
        else:
            Uphosts = TestPing(target)
    
    NoisyProcesses = []

    for host in Uphosts:
        print_colored("Started creating noise on %s..." % (host), colors.green)
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
                    print("\nNoise scan complete!")
                    for P in NoisyProcesses:
                        P.terminate()
                    exit(0)
                    break
        else:
            while True:
                sleep(1)
    except KeyboardInterrupt:
        print_colored("\nStopping noise...", colors.red)
        WriteToFile("\nStopped noise...")
        for P in NoisyProcesses:
            P.terminate()
        exit(0)

def DiscoverHosts(target, scantype=ScanType.ARP, scanspeed=3, mode=ScanMode.Normal):
    print_colored("\n" + "─" * 60, colors.green)
    WriteToFile("\n" + "─" * 60)
    if type(target) is list:
        print_colored(("Scanning " + str(len(target)) + " target(s) using " + str(scantype.name) + " scan...").center(60), colors.green)
        WriteToFile("\nScanning %d hosts using %s scan..." % (len(target), str(scantype.name)))
    else:
        print_colored(("Scanning " + target + " using " + str(scantype.name) + " scan...").center(60), colors.green)
        WriteToFile(("Scanning " + target + " using " + str(scantype.name) + " scan...").center(60))
    
    print_colored("─" * 60 + "\n", colors.green)
    WriteToFile("─" * 60 + "\n")

    if scantype == ScanType.Ping:
        OnlineHosts = TestPing(target, mode)
        return OnlineHosts

    elif scantype == ScanType.ARP:
        OnlineHosts = TestArp(target, mode)
        return OnlineHosts

def InitHostInfo(nm, target):
    try:
        mac = nm[target]['addresses']['mac']
    except KeyError:
        mac = 'Unknown'
    except IndexError:
        mac = 'Unknown'

    try:
        vendor = nm[target]['vendor'][0]
    except KeyError:
        vendor = 'Unknown'
    except IndexError:
        vendor = 'Unknown'

    try:
        os = nm[target]['osmatch'][0]['name']
    except KeyError:
        os = 'Unknown'
    except IndexError:
        os = 'Unknown'

    try:
        os_accuracy = nm[target]['osmatch'][0]['accuracy']
    except KeyError:
        os_accuracy = 'Unknown'
    except IndexError:
        os_accuracy = 'Unknown'

    try:
        os_type = nm[target]['osmatch'][0]['osclass'][0]['type']
    except KeyError:
        os_type = 'Unknown'
    except IndexError:
        os_type = 'Unknown'


    return mac, vendor, os, os_accuracy, os_type

#analyse and print scan results
def AnalyseScanResults(nm, target=None):
    HostArray = []

    if target is None:
        target = nm.all_hosts()[0]

    try:
        nm[target]
    except KeyError:
        print_colored("Target " + str(target) + " seems to be offline.", colors.red)
        WriteToFile("Target " + str(target) + " seems to be offline.")
        return []


    mac, vendor, os, os_accuracy, os_type = InitHostInfo(nm, target)
    CurrentTargetInfo = TargetInfo(target, mac, vendor, os, os_accuracy, os_type)

    print(CurrentTargetInfo.colored().center(60))
    WriteToFile(str(CurrentTargetInfo).center(60) + "\n")

    reason = nm[target]['status']['reason']

    if is_root():
        if reason == 'localhost-response' or reason == 'user-set':
            print_colored('Target ' + str(target) + ' seems to be us.', colors.underline)
            WriteToFile('Target ' + str(target) + ' seems to be us.\n')
    # we cant detect if the host is us or not, if we are not root
    # we could get our ip address and compare them but i think it's not quite necessary

    if len(nm[target].all_protocols()) == 0:
        print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
        WriteToFile("Target " + str(target) + " seems to have no open ports.")
        return HostArray
    for port in nm[target]['tcp'].keys():
                        
        if not len(nm[str(target)]['tcp'][int(port)]['state']) == 0:
            state = nm[str(target)]['tcp'][int(port)]['state']
        else:
            state = 'Unknown'
    
        if not len(nm[str(target)]['tcp'][int(port)]['name']) == 0:
            service = nm[str(target)]['tcp'][int(port)]['name']
        else:
            service = 'Unknown'

        if not len(nm[str(target)]['tcp'][int(port)]['product']) == 0:
            product = nm[str(target)]['tcp'][int(port)]['product']
        else:
            product = 'Unknown'

        if not len(nm[str(target)]['tcp'][int(port)]['version']) == 0:
            version = nm[str(target)]['tcp'][int(port)]['version']
        else:
            version = 'Unknown'

        print(
            (
                bcolors.cyan + "Port : " + bcolors.endc + "{0:10}" + 
                bcolors.cyan + " State : " + bcolors.endc + "{1:10}" +
                bcolors.cyan + " Service : " + bcolors.endc + "{2:15}" +
                bcolors.cyan + " Product : " + bcolors.endc + "{3:20}" +
                bcolors.cyan + " Version : " + bcolors.endc + "{4:15}"
            ).format(str(port), state, service[:15], product[:20], version[:15])
        )

        WriteToFile(
            (
                "Port : {0:10}" + 
                " State : {1:10}" +
                " Service : {2:20}" +
                " Product : {3:20}" +
                " Version : {4:20}"
            ).format(str(port), state, service[:15], product[:20], version[:15])
        )

        if state == 'open':
            HostArray.insert(len(HostArray), [target, port, service, product, version])

    return HostArray