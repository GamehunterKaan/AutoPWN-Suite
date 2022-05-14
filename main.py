#!/usr/bin/env python3
import argparse
from logging import exception
import scapy.all as scapy
import nmap
from color import *

argparser = argparse.ArgumentParser()
argparser.add_argument("-o", "--output", help="Output file name. (Default:autopwn.log)")
argparser.add_argument("-t", "--target", help="Target range to scan. (192.168.0.1 or 192.168.0.0/24)")
argparser.add_argument("-st", "--scantype", help="Scan type. (Ping or ARP)")
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)")
args = argparser.parse_args()

if args.output:
    outfile = args.output
else:
    outfile = 'autopwn.log'

if args.scantype:
    scantype = args.scantype.lower()
else:
    scantype = 'arp'

if not args.target:
    raise exception("No targets specified!")

targetarg = args.target

def TestPing(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

def TestArp(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

def PortScan(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sS --host-timeout 30")

    try:
        len(nm[target].all_protocols())
    except:
        return 0
    
    if len(nm[target].all_protocols()) == 0:
        return 0
    
    else:
        for proto in nm[target].all_protocols():
            lport = nm[target][proto].keys()

        return lport

print_yellow("#########################################################\n")

if scantype == 'ping':
    results = TestPing(targetarg)
    for host in results:
        print(host)
    print_blue("\nWould you like to run a port scan on these hosts? (Y/N)")
    wannaportscan = input()
    if wannaportscan == 'Y':
        for host in results:
            print_green("\n---------------------------------------------------------")
            print_green("Running a portscan for host " + str(host) + "...")
            print_green("---------------------------------------------------------")
            ports = PortScan(host)
            if ports == 0:
                print_red("\nTarget " + str(host) + " seems to have no open ports.")
            else:
                for port in ports:
                    print("Port " + str(port) + " is open on " + str(host))
    print_yellow("\n#########################################################")

elif scantype == 'arp':
    results = TestArp(targetarg)
    for host in results:
        print(host)
    print_blue("\nWould you like to run a port scan on these hosts? (Y/N)")
    wannaportscan = input()
    if wannaportscan == 'Y':
        for host in results:
            print_green("\n---------------------------------------------------------")
            print_green("Running a portscan for host " + str(host) + "...")
            print_green("---------------------------------------------------------")
            ports = PortScan(host)
            if ports == 0:
                print_red("\nTarget " + str(host) + " seems to have no open ports.")
            else:
                for port in ports:
                    print("Port " + str(port) + " is open on " + str(host))
    print_yellow("\n#########################################################")

else:
    raise exception("Unknown scan type : " + scantype)