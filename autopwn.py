#!/usr/bin/env python3
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM
from os import getuid
from logging import exception
from modules.nmap import PortScanner
from modules.color import print_colored, colors
from modules.banners import print_banner
from modules.searchvuln import SearchSploits

__author__ = 'GamehunterKaan'

#parse command line arguments
argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument("-o", "--output", help="Output file name. (Default : autopwn.log)", default="autopwn.log")
argparser.add_argument("-t", "--target", help="Target range to scan. (192.168.0.1 or 192.168.0.0/24)")
argparser.add_argument("-st", "--scantype", help="Scan type. (Ping or ARP)", default="arp")
argparser.add_argument("-s", "--speed", help="Scan speed. (0-5)", default=2)
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)",action="store_true")
args = argparser.parse_args()

#check if user wants to do automatic scan
if args.yesplease:
    DontAskForConfirmation = True
else:
    DontAskForConfirmation = False

def DetectPrivateIPAdress():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def DetectNetworkRange(ip):
    #split the IP address into 4 pieces and replace last part with 0/24
    return str(ip.split('.')[0]) + '.' + str(ip.split('.')[1]) + '.' + ip.split('.')[2] + '.0/24'

#use the 2 functions above if user doesn't specify an IP address and enabled automatic scan
if args.target:
    targetarg = args.target
else:
    if DontAskForConfirmation:
        PrivateIPAdress = DetectPrivateIPAdress()
        targetarg = DetectNetworkRange(PrivateIPAdress)
    else:
        print_colored("Please specify a target.", colors.cyan)
        targetarg = input()

#print a beautiful banner
print_banner()

def is_root():
    if getuid() == 0:
        return True #return True if the user is root
    else:
        return False

if is_root() == False:
    print_colored("It's recommended to run this script as root since it's more silent and accurate.", colors.red)

#do a ping scan using nmap
def TestPing(target):
    print_colored("\n---------------------------------------------------------", colors.green)
    print_colored("\tDoing host discovery on " + str(target) + "...", colors.green)
    print_colored("---------------------------------------------------------\n", colors.green)
    nm = PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

#do a arp scan using nmap
def TestArp(target):
    print_colored("\n---------------------------------------------------------", colors.green)
    print_colored("\tDoing host discovery on " + str(target) + "...", colors.green)
    print_colored("---------------------------------------------------------\n", colors.green)
    nm = PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

#run a port scan on target using nmap
def PortScan(target):
    print_colored("\n---------------------------------------------------------", colors.green)
    print_colored("\tRunning a portscan on host " + str(target) + "...", colors.green)
    print_colored("---------------------------------------------------------\n", colors.green)
    nm = PortScanner()
    if is_root():
        resp = nm.scan(hosts=target, arguments="-sS -sV --host-timeout 60 -Pn -O")
    else:
        resp = nm.scan(hosts=target, arguments="-sV --host-timeout 60 -Pn")
    return nm

#analyse and print scan results
def AnalyseScanResults(nm,target):
    HostArray = []
    CPEArray = []
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

        try:
            cpes = nm[target]['osmatch'][0]['osclass'][0]['cpe']
        except:
            cpes = []

        for cpe in cpes:
            CPEArray.insert(len(CPEArray), cpe)

        print_colored("MAC Address : %s\tVendor : %s" % (mac, vendor), colors.yellow)
        print_colored("OS : %s\tAccuracy : %s\tType : %s\n" % (os, accuracy,ostype), colors.yellow)
        if nm[target]['status']['reason'] == 'localhost-response' or nm[target]['status']['reason'] == 'user-set':
            print_colored('Target ' + str(target) + ' seems to be us.', colors.underline)
        if len(nm[target].all_protocols()) == 0:
            print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
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

                print('Port : %s\tState : %s\tService : %s\tProduct : %s\tVersion : %s'
                 %      (port, state, service, product, version))
                if state == 'open':
                    HostArray.insert(len(HostArray), [target, port, service, product, version])

    except:
        print_colored("Target " + str(target) + " seems to have no open ports.", colors.red)
    return HostArray,CPEArray

#ask the user if they want to scan ports
def UserWantsPortScan():
    if DontAskForConfirmation:
        return True
    else:
        print_colored("\nWould you like to run a port scan on these hosts? (Y/N)", colors.blue)
        while True:
            wannaportscan = input().lower()
            if wannaportscan == 'y' or wannaportscan == 'yes':
                return True
                break
            elif wannaportscan == 'n' or wannaportscan == 'no':
                return False
            else:
                print("Please say Y or N!")

#ask the user if they want to do a vulnerability check
def UserWantsVulnerabilityDetection():
    if DontAskForConfirmation:
        return True
    else:
        print_colored("\nWould you like to do a version based vulnerability detection? (Y/N)", colors.blue)
        while True:
            wannaportscan = input().lower()
            if wannaportscan == 'y' or wannaportscan == 'yes':
                return True
                break
            elif wannaportscan == 'n' or wannaportscan == 'no':
                return False
            else:
                print("Please say Y or N!")

#post scan stuff
def PostScanStuff(hosts):
    for host in hosts:
        print("\t\t" + host)
    if UserWantsPortScan():
        for host in hosts:
            PortScanResults = PortScan(host)
            PortArray, CPEArray = AnalyseScanResults(PortScanResults,host)
            if len(PortArray) > 0:
                if UserWantsVulnerabilityDetection():
                    SearchSploits(PortArray,CPEArray)
            else:
                print("Skipping vulnerability detection for " + str(host))

#main function
def main():
    if args.scantype == 'ping':
        results = TestPing(targetarg)
        PostScanStuff(results)

    elif args.scantype == 'arp':
        if is_root():
            results = TestArp(targetarg)
        else:
            #switch over to ping scan if user is not root
            print_colored("Not running as root! Running ping scan instead...", colors.red) #Yell at the user for not running as root!
            results = TestPing(targetarg)
        PostScanStuff(results)

    else:
        #if specified scan type is invalid, decide which scan type to use depending on user privilege
        if is_root():
            print_colored("Unknown scan type: %s! Using arp scan instead..." % (args.scantype), colors.red)
            results = TestArp(targetarg)
            PostScanStuff(results)
        else:
            print_colored("Unknown scan type: %s! Using ping scan instead..." % (args.scantype), colors.red)
            results = TestPing(targetarg)
            PostScanStuff(results)

#only run the script if its not imported as a module (directly interpreted with python3)
if __name__ == '__main__':
    main()