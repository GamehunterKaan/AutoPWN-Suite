#!/usr/bin/env python3
from argparse import ArgumentParser
from nmap import PortScanner
from socket import socket, AF_INET, SOCK_DGRAM
from os import getuid
from logging import exception
from color import print_colored
from banners import print_banner

argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument("-o", "--output", help="Output file name. (Default:autopwn.log)")
argparser.add_argument("-t", "--target", help="Target range to scan. (192.168.0.1 or 192.168.0.0/24)")
argparser.add_argument("-st", "--scantype", help="Scan type. (Ping or ARP)")
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)",action="store_true")
args = argparser.parse_args()

print_banner()

blue = 'blue'
cyan = 'cyan'
green = 'green'
yellow = 'yellow'
red = 'red'
bold = 'bold'
underline = 'underline'
no_new_line = 'no_new_line'

if not getuid() == 0:
    print_colored("This script requires root permissions.", red)
    exit()

if args.output:
    outfile = args.output
else:
    outfile = 'autopwn.log'

if args.scantype:
    scantype = args.scantype.lower()
else:
    scantype = 'arp'

if args.yesplease:
    DontAskForConfirmation = True
else:
    DontAskForConfirmation = False

def DetectPrivateIPAdress():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def DetectNetworkRange(ip):
    return str(ip.split('.')[0]) + '.' + str(ip.split('.')[1]) + '.' + ip.split('.')[2] + '.0/24'

if args.target:
    targetarg = args.target
else:
    if DontAskForConfirmation:
        PrivateIPAdress = DetectPrivateIPAdress()
        targetarg = DetectNetworkRange(PrivateIPAdress)
    else:
        print_colored("Please specify a target.", cyan)
        targetarg = input()


def TestPing(target):
    print_colored("\n---------------------------------------------------------", green)
    print_colored("\tDoing host discovery on " + str(target) + "...", green)
    print_colored("---------------------------------------------------------\n", green)
    nm = PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

def TestArp(target):
    print_colored("\n---------------------------------------------------------", green)
    print_colored("\tDoing host discovery on " + str(target) + "...", green)
    print_colored("---------------------------------------------------------\n", green)
    nm = PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

def PortScan(target):
    print_colored("\n---------------------------------------------------------", green)
    print_colored("\tRunning a portscan on host " + str(target) + "...", green)
    print_colored("---------------------------------------------------------\n", green)
    nm = PortScanner()
    resp = nm.scan(hosts=target, arguments="-sS --host-timeout 60 -Pn")
    return nm

def AnalyseScanResults(nm,target):
    try:
        nm[target]
        if nm[target]['status']['reason'] == 'localhost-response' or nm[target]['status']['reason'] == 'user-set':
            print_colored('Target ' + str(target) + ' seems to be us.', underline)
        if len(nm[target].all_protocols()) == 0:
            print_colored("Target " + str(host) + " seems to have no open ports.", red)
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                print('\tPort : %s\tState : %s' % (port, nm[str(target)][proto][port]['state']))
    except:
        print_colored("Target " + str(host) + " seems to have no open ports.", red)

def UserWantsPortScan():
    if DontAskForConfirmation:
        return True
    else:
        print_colored("\nWould you like to run a port scan on these hosts? (Y/N)", blue)
        while True:
            wannaportscan = input().lower()
            if wannaportscan == 'y' or wannaportscan == 'yes':
                return True
                break
            elif wannaportscan == 'n' or wannaportscan == 'no':
                return False
            else:
                print("Please say Y or N!")

if scantype == 'ping':
    results = TestPing(targetarg)
    for host in results:
        print(host)
    if UserWantsPortScan():
        for host in results:
            PortScanResults = PortScan(host)
            AnalyseScanResults(PortScanResults,host)

elif scantype == 'arp':
    results = TestArp(targetarg)
    for host in results:
        print("\t\t" + host)
    if UserWantsPortScan():
        for host in results:
            PortScanResults = PortScan(host)
            AnalyseScanResults(PortScanResults,host)

else:
    raise exception("Unknown scan type : " + scantype)