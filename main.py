#!/usr/bin/env python3
import argparse
from logging import exception
import scapy.all as scapy
import nmap

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

"""
target_octets = targetarg.split('.')
targets = []

if not target_octets[3].isdigit():
    for i in range(1,256):
        targets.append(str(target_octets[0]) + '.' + str(target_octets[1]) + '.' + str(target_octets[2]) + '.' + str(i))
else:
    targets.append(targetarg)


def TestPing(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()
"""
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

if scantype == 'ping':
    uphosts = TestPing(targetarg)
    for host in uphosts:
        print("Target " + host + " is up!")
    wannaportscan = input("Would you like to run a port scan on these hosts? (Y/N)\n")
    if wannaportscan == 'Y':
        for host in uphosts:
            print("Running a portscan for host " + host + "...")
            ports = PortScan(host)


elif scantype == 'arp':
    results = TestArp(targetarg)
    for host in results:
        print(host)
    wannaportscan = input("Would you like to run a port scan on these hosts? (Y/N)\n")
    if wannaportscan == 'Y':
        for host in results:
            print("\n---------------------------------------------------------")
            print("Running a portscan for host " + str(host) + "...")
            print("---------------------------------------------------------")
            ports = PortScan(host)
            if ports == 0:
                print("\nTarget " + str(host) + " seems to have no open ports.")
            else:
                print("\n")
                for port in ports:
                    print("Port " + str(port) + " is open on " + str(host))
                print("\n")
else:
    raise exception("Unknown scan type : " + scantype)