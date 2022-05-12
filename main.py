#!/usr/bin/env python3
import argparse
from logging import exception
import nmap
argparser = argparse.ArgumentParser()

argparser.add_argument("-o", "--output", help="Output file name. (Default:autopwn.log)")
argparser.add_argument("-t", "--target", help="Target range to scan.")
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

def TestPing(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn")
    if len(nm.all_hosts()) != 0:
        return True
    else:
        return False

def TestArp(target):
    nm = nmap.PortScanner()
    resp = nm.scan(hosts=target, arguments="-sn -PR")
    if len(nm.all_hosts()) != 0:
        return True
    else:
        return False

if scantype == 'ping':
    if TestPing(args.target):
        print("Target " + args.target + " is up!") 
elif scantype == 'arp':
    if TestArp(args.target):
        print("Target " + args.target + " is up!") 
else:
    raise exception("Unknown scan type : " + scantype)
