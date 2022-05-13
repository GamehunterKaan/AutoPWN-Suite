#!/usr/bin/env python3
import argparse
from logging import exception
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
"""

def TestPing(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    return nm.all_hosts()

def TestArp(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn -PR")
    return nm.all_hosts()

if scantype == 'ping':
    uphosts = TestPing(targetarg)
    for host in uphosts:
        print("Target " + host + " is up!")
elif scantype == 'arp':
    uphosts = TestArp(targetarg)
    for host in uphosts:
        print("Target " + host + " is up!")
else:
    raise exception("Unknown scan type : " + scantype)
