from modules.nmap import PortScanner
from modules.color import print_colored, colors, bcolors
from modules.outfile import WriteToFile
from os import getuid
from multiprocessing import Process
from dataclasses import dataclass

@dataclass
class PortInfo:
    # gotta figure out how to use dataclasses
    port = 0
    protocol = ''
    state = ''
    service = ''
    product = ''
    version = ''

def is_root():
    if getuid() == 0:
        return True #return True if the user is root
    else:
        return False

# this function is for turning a list of hosts into a single string
def listToString(s): 
    str1 = " "
    return (str1.join(s))

#do a ping scan using nmap
def TestPing(target, mode):
    nm = PortScanner()
    if type(target) is list:
        target = listToString(target)
    if mode == "evade":
        resp = nm.scan(hosts=target, arguments="-sn -T 2 -f -g 53 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

#do a arp scan using nmap
def TestArp(target, mode):
    nm = PortScanner()
    if type(target) is list:
        target = listToString(target)
    if mode == "evade":
        resp = nm.scan(hosts=target, arguments="-sn -PR -T 2 -f -g 53 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

#run a port scan on target using nmap
def PortScan(target, scanspeed, mode):
    print_colored("\n" + "-" * 60, colors.green)
    print_colored(("Running a portscan on host " + str(target) + "...").center(60), colors.green)
    print_colored("-" * 60 + "\n", colors.green)
    WriteToFile("\nPortscan on " + str(target) + " : ")
    nm = PortScanner()
    if is_root():
        if mode == "evade":
            resp = nm.scan(hosts=target, arguments="-sS -sV -O -Pn -T 2 -f -g 53 --data-length 10")
        else:
            resp = nm.scan(hosts=target, arguments="-sS -sV --host-timeout 60 -Pn -O -T %d" % (scanspeed))
    else:
        resp = nm.scan(hosts=target, arguments="-sV --host-timeout 60 -Pn -T %d" % (scanspeed))
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

def DiscoverHosts(target, scantype, scanspeed, mode):
    if mode == "noise":
        print_colored("\n" + "-" * 60, colors.green)
        print_colored("Creating noise...".center(60), colors.green)
        print_colored("-" * 60 + "\n", colors.green)
        WriteToFile("\nCreating noise...")
        if scantype == "ping":
            Uphosts = TestPing(target, mode)
        elif scantype == "arp":
            if is_root():
                Uphosts = TestArp(target, mode)
            else:
                Uphosts = TestPing(target, mode)
        for host in Uphosts:
            print_colored("Started creating noise on %s..." % (host), colors.green)
            P = Process(target=CreateNoise, args=(host,))
            P.start()
        while True:
            try:
                sleep(10)
            except KeyboardInterrupt:
                print_colored("\nStopping noise...", colors.red)
                WriteToFile("\nStopped noise...")
                exit(0)
    else:
        print_colored("\n" + "-" * 60, colors.green)
        if type(target) is list:
            print_colored(("Scanning " + str(len(target)) + " target(s) using " + scantype + " scan...").center(60), colors.green)
            WriteToFile("\nScanning %d hosts using %s scan..." % (len(target), scantype))
        else:
            print_colored(("Scanning " + target + " using " + scantype + " scan...").center(60), colors.green)
            WriteToFile("\nScanning %s using %s scan..." % (target, scantype))
        
        print_colored("-" * 60 + "\n", colors.green)
        
        if scantype == "ping":
            OnlineHosts = TestPing(target, mode)
            return OnlineHosts

        elif scantype == "arp":
            OnlineHosts = TestArp(target, mode)
            return OnlineHosts

#analyse and print scan results
def AnalyseScanResults(nm,target):
    HostArray = []

    try:
        nm[target]

        try:
            mac = nm[target]['addresses']['mac']
        except:
            mac = 'Unknown'

        try:
            vendor = nm[target]['vendor'][mac]
        except:
            vendor = 'Unknown'

        try:
            os = nm[target]['osmatch'][0]['name']
        except:
            os = 'Unknown'

        try:
            accuracy = nm[target]['osmatch'][0]['accuracy']
        except:
            accuracy = 'Unknown'

        try:
            ostype = nm[target]['osmatch'][0]['osclass'][0]['type']
        except:
            ostype = 'Unknown'

        print(
            (
                bcolors.yellow + "MAC Address : " + bcolors.endc + "{0:20}" +
                bcolors.yellow + " Vendor : " + bcolors.endc + "{1:30}"
            ).format(mac , vendor)
        )

        WriteToFile(
            (
                "MAC Address : {0:20}" +
                " Vendor : {1:30}\n"
            ).format(mac, vendor)
        )

        print(
            (
                bcolors.yellow + "OS : " + bcolors.endc + "{0:20}" +
                bcolors.yellow + " Accuracy : " + bcolors.endc + "{1:5}" +
                bcolors.yellow + " Type : " + bcolors.endc + "{2:20}"
            ).format(os , accuracy , ostype)
        )

        WriteToFile(
            (
                "OS : {0:20}" +
                " Accuracy : {1:5}" +
                " Type : {2:20}"
            ).format(os , accuracy , ostype)
        )

        print("\n")
        WriteToFile("\n")

        if nm[target]['status']['reason'] == 'localhost-response' or nm[target]['status']['reason'] == 'user-set':
            print_colored('Target ' + str(target) + ' seems to be us.', colors.underline)
            WriteToFile('Target ' + str(target) + ' seems to be us.')
        if len(nm[target].all_protocols()) == 0:
            print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
            WriteToFile("Target " + str(target) + " seems to have no open ports.")
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                                
                try:
                    if not len(nm[str(target)][proto][int(port)]['state']) == 0:
                        state = nm[str(target)][proto][int(port)]['state']
                    else:
                        state = 'Unknown'
                except:
                    state = 'Unknown'
                
                try:
                    if not len(nm[str(target)][proto][int(port)]['name']) == 0:
                        service = nm[str(target)][proto][int(port)]['name']
                    else:
                        service = 'Unknown'
                except:
                    service = 'Unknown'

                try:
                    if not len(nm[str(target)][proto][int(port)]['product']) == 0:
                        product = nm[str(target)][proto][int(port)]['product']
                    else:
                        product = 'Unknown'
                    
                except:
                    product = 'Unknown'

                try:
                    if not len(nm[str(target)][proto][int(port)]['version']) == 0:
                        version = nm[str(target)][proto][int(port)]['version']
                    else:
                        version = 'Unknown'
                except:
                    version = 'Unknown'

                print(
                    (
                        bcolors.cyan + "Port : " + bcolors.endc + "{0:10}" + 
                        bcolors.cyan + " State : " + bcolors.endc + "{1:10}" +
                        bcolors.cyan + " Service : " + bcolors.endc + "{2:15}" +
                        bcolors.cyan + " Product : " + bcolors.endc + "{3:20}" +
                        bcolors.cyan + " Version : " + bcolors.endc + "{4:15}"
                    ).format(str(port), state, service, product, version)
                )

                WriteToFile(
                    (
                        "Port : {0:10}" + 
                        " State : {1:10}" +
                        " Service : {2:20}" +
                        " Product : {3:20}" +
                        " Version : {4:20}"
                    ).format(str(port), state, service, product, version)
                )

                if state == 'open':
                    HostArray.insert(len(HostArray), [target, port, service, product, version])

    except KeyError:
        print_colored("Target " + str(target) + " seems to be offline.", colors.red)
        WriteToFile("Target " + str(target) + " seems to be offline.")
    except Exception as e:
        print_colored("An error occured while scanning " + str(target) + ".", colors.red)
        WriteToFile("An error occured while scanning " + str(target) + ".")
        print_colored(str(e), colors.red)
        WriteToFile(str(e))
    return HostArray
