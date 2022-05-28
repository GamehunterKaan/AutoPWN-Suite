from modules.nmap import PortScanner
from modules.color import print_colored, colors, bcolors
from modules.outfile import output
from os import getuid

def is_root():
    if getuid() == 0:
        return True #return True if the user is root
    else:
        return False

#do a ping scan using nmap
def TestPing(target, scantype, evade):
    print_colored("\n" + "-" * 64, colors.green)
    print_colored("\tDoing host discovery on " + str(target) + "... (PING)", colors.green)
    print_colored("-" * 64 + "\n", colors.green)
    output.WriteToFile("\nHost discovery on " + str(target) + " : PING\n")
    nm = PortScanner()
    if evade:
        resp = nm.scan(hosts=target, arguments="-sn -T 1 -f -g 53 --spoof-mac 0 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

#do a arp scan using nmap
def TestArp(target, evade):
    print_colored("\n" + "-" * 64, colors.green)
    print_colored("\tDoing host discovery on " + str(target) + "... (ARP)", colors.green)
    print_colored("-" * 64 + "\n", colors.green)
    output.WriteToFile("\nHost discovery on " + str(target) + " : ARP\n")
    nm = PortScanner()
    if evade:
        resp = nm.scan(hosts=target, arguments="-sn -PR -T 1 -f -g 53 --spoof-mac 0 --data-length 10")
    else:
        resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

def DiscoverHosts(target, scantype, scanspeed, evade):
    if scantype == 'ping':
        OnlineHosts = TestPing(target)
        return OnlineHosts

    elif scantype == 'arp':
        if is_root():
            OnlineHosts = TestArp(target, evade)
        else:
            #switch over to ping scan if user is not root
            print_colored("Not running as root! Running ping scan instead...", colors.red) #Yell at the user for not running as root!
            output.WriteToFile("Switched over to ping scan because user is not root.")
            OnlineHosts = TestPing(target, evade)
        return OnlineHosts

    else:
        #if specified scan type is invalid, decide which scan type to use depending on user privilege
        if is_root():
            print_colored("Unknown scan type: %s! Using arp scan instead..." % (scantype), colors.red)
            OnlineHosts = TestArp(target)
            return OnlineHosts
        else:
            print_colored("Unknown scan type: %s! Using ping scan instead..." % (scantype), colors.red)
            OnlineHosts = TestPing(target)
            return OnlineHosts

#run a port scan on target using nmap
def PortScan(target, scanspeed, evade):
    print_colored("\n---------------------------------------------------------", colors.green)
    print_colored("\tRunning a portscan on host " + str(target) + "...", colors.green)
    print_colored("---------------------------------------------------------\n", colors.green)
    output.WriteToFile("\nPortscan on " + str(target) + " : ")
    nm = PortScanner()
    if is_root():
        if evade:
            resp = nm.scan(hosts=target, arguments="-sS -sV -O --host-timeout 60 -Pn -T 1 -f -g 53 --spoof-mac 0 --data-length 10")
        else:
            resp = nm.scan(hosts=target, arguments="-sS -sV --host-timeout 60 -Pn -O -T %d" % (scanspeed))
    else:
        resp = nm.scan(hosts=target, arguments="-sV --host-timeout 60 -Pn -T %d" % (scanspeed))
    return nm

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

        print_colored("MAC Address : %s\tVendor : %s" % (mac, vendor), colors.yellow)
        print_colored("OS : %s\tAccuracy : %s\tType : %s\n" % (os, accuracy,ostype), colors.yellow)

        output.WriteToFile("MAC Address : %s\tVendor : %s" % (mac, vendor))
        output.WriteToFile("OS : %s\tAccuracy : %s\tType : %s\n" % (os, accuracy,ostype))

        if nm[target]['status']['reason'] == 'localhost-response' or nm[target]['status']['reason'] == 'user-set':
            print_colored('Target ' + str(target) + ' seems to be us.', colors.underline)
            output.WriteToFile('Target ' + str(target) + ' seems to be us.')
        if len(nm[target].all_protocols()) == 0:
            print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
            output.WriteToFile("Target " + str(target) + " seems to have no open ports.")
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
                    bcolors.cyan + "Port : " + bcolors.endc + str(port) + 
                    bcolors.cyan + "\tState : " + bcolors.endc + str(state) +
                    bcolors.cyan + "\tService : " + bcolors.endc + str(service) +
                    bcolors.cyan + "\tProduct : " + bcolors.endc + str(product) +
                    bcolors.cyan + "\tVersion : " + bcolors.endc + str(version)
                )

                output.WriteToFile("Port : " + str(port) + "\tState : " + str(state) + "\tService : " + str(service) + "\tProduct : " + str(product) + "\tVersion : " + str(version))

                if state == 'open':
                    HostArray.insert(len(HostArray), [target, port, service, product, version])

    except:
        print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
        output.WriteToFile("Target " + str(target) + " seems to have no open ports.")
    return HostArray