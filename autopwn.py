#!/usr/bin/env python3
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM
from os import getuid
from subprocess import check_call, CalledProcessError, DEVNULL
from modules.color import print_colored, colors, bcolors
from modules.banners import print_banner
from modules.searchvuln import SearchSploits
from modules.scanner import AnalyseScanResults, PortScan, DiscoverHosts
from modules.outfile import InitializeOutput, WriteToFile, OutputBanner

__author__ = 'GamehunterKaan'
__version__ = '1.0.3'

#parse command line arguments
argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument("-o", "--output", help="Output file name. (Default : autopwn.log)", default="autopwn.log")
argparser.add_argument("-t", "--target", help="Target range to scan. This argument overwrites the hostfile argument. (192.168.0.1 or 192.168.0.0/24)")
argparser.add_argument("-hf", "--hostfile", help="File containing a list of hosts to scan.")
argparser.add_argument("-st", "--scantype", help="Scan type. (Ping or ARP)")
argparser.add_argument("-s", "--speed", help="Scan speed. (0-5) (Default : 3)", default=3)
argparser.add_argument("-a", "--api", help="Specify API key for vulnerability detection for faster scanning. You can also specify your API key in api.txt file. (Default : None)", default=None)
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)",action="store_true")
argparser.add_argument("-m", "--mode", help="Scan mode. (Evade, Noise, Normal)", default="normal")
argparser.add_argument("-v", "--version", help="Print version and exit.", action="store_true")
args = argparser.parse_args()

if args.version:
    print("AutoPWN Suite v" + __version__)
    exit(0)

#print a beautiful banner
print_banner()

outputfile = args.output
InitializeOutput(context=args.output)
DontAskForConfirmation = args.yesplease

def is_root():
    if getuid() == 0:
        return True #return True if the user is root
    else:
        return False

if args.scantype == "arp":
    if not is_root():
        print_colored("You must be root to do an arp scan!", colors.red)
        scantype = "ping"
elif args.scantype == "ping":
    pass
elif args.scantype == "":
    if is_root():
        scantype = "arp"
    else:
        scantype = "ping"
else:
    if is_root():
        scantype = "arp"
        print_colored("Unknown scan type: %s! Using arp scan instead..." % (args.scantype), colors.red)
    else:
        scantype = "ping"
        print_colored("Unknown scan type: %s! Using ping scan instead..." % (args.scantype), colors.red)

scanspeed = int(args.speed)

if is_root() == False:
    print_colored("It's recommended to run this script as root since it's more silent and accurate.", colors.red)

try:
    args.speed = int(args.speed)
except ValueError:
    print_colored("Speed must be a number!", colors.red)
    args.speed = 3
    print_colored("Using default speed : %d" % args.speed, colors.cyan) #Use default speed if user specified invalid speed value type

if not args.speed <= 5 or not args.speed >= 0:
    print_colored("Invalid speed specified : %d" % args.speed, colors.red)
    args.speed = 3
    print_colored("Using default speed : %d" % args.speed, colors.cyan) #Use default speed if user specified invalid speed value

if args.api:
    print_colored("Using the specified API key for searching vulnerabilities.", colors.yellow)
    apiKey = args.api
else:
    try:
        with open("api.txt", "r") as f:
            apiKey = f.readline().strip("\n")
            print_colored("Using the API key from api.txt file.", colors.yellow)
    except FileNotFoundError:
        print_colored("No API key specified and no api.txt file found. Vulnerability detection is going to be slower!", colors.red)
        print_colored("You can get your own NIST API key from https://nvd.nist.gov/developers/request-an-api-key", colors.yellow)
        apiKey = None
    except PermissionError:
        print_colored("Permission denied while trying to read api.txt!", colors.red)
        apiKey = None

def check_nmap():
    # Check if nmap is installed
    # If not, install it
    # also add a function to install nmap on windows
    try:
        nmap_checker = check_call(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)
    except FileNotFoundError:
        print_colored("Nmap is not installed. Auto installing...", colors.yellow)
        try:
            debian_installer = check_call(["sudo", "apt-get", "install", "nmap", "-y"], stderr=DEVNULL)
        except CalledProcessError:
            try:
                arch_instller = check_call(["sudo", "pacman", "-S", "nmap", "--noconfirm"], stderr=DEVNULL)
            except CalledProcessError:
                try:
                    fedore_installer = check_call(["sudo", "dnf", "install", "nmap"], stderr=DEVNULL)
                except CalledProcessError:
                    try:
                        yum_installer = check_call(["sudo", "yum", "install", "nmap"], stderr=DEVNULL)
                    except CalledProcessError:
                        print_colored("nmap installation failed. Please install nmap manually.", colors.red)
                        exit(1)


def DetectIPRange():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = s.getsockname()[0]
    target = str(str(PrivateIPAdress.split('.')[0]) + '.' + str(PrivateIPAdress.split('.')[1]) + '.' + PrivateIPAdress.split('.')[2] + '.0/24')
    return target

def GetTarget():
    if args.target:
        target = args.target
    else:
        if args.hostfile:
            # read targets from host file and insert all of them into an array
            try:
                target = open(args.hostfile,'r').read().splitlines()
            except FileNotFoundError:
                print_colored("Host file not found!", colors.red)
                target = DetectIPRange()
            except PermissionError:
                print_colored("Permission denied while trying to read host file!", colors.red)
                target = DetectIPRange()
            except Exception:
                print_colored("Unknown error while trying to read host file!", colors.red)
                target = DetectIPRange()
        else:
            if DontAskForConfirmation:
                target = DetectIPRange()
            else:
                target = input("Enter target range to scan : ")
    return target

targetarg = GetTarget()

if args.mode.lower() == "evade":
    scanmode = "evade"
    scanspeed = 2
    print_colored("Evasion mode enabled!", colors.yellow)
elif args.mode.lower() == "noise":
    scanmode = "noise"
    print_colored("Noise mode enabled!", colors.yellow)
elif args.mode.lower() == "normal":
    scanmode = "normal"
else:
    print_colored("Invalid mode specified! %s" % (args.mode), colors.red)
    print_colored("Using default mode : normal", colors.cyan)
    scanmode = "normal"

OutputBanner(targetarg, scantype, scanspeed, args.hostfile)

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
                WriteToFile("User refused to run a port scan on these hosts.")
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
            wannavulnscan = input().lower()
            if wannavulnscan == 'y' or wannavulnscan == 'yes':
                return True
                break
            elif wannavulnscan == 'n' or wannavulnscan == 'no':
                WriteToFile("User refused to do a version based vulnerability detection.")
                return False
            else:
                print("Please say Y or N!")

#post scan stuff
def FurtherEnumuration(hosts):
    for host in hosts:
        print(host.center(60))
        WriteToFile(host.center(60))
    if UserWantsPortScan():
        for host in hosts:
            WriteToFile("\n" + "-" * 60)
            PortScanResults = PortScan(host, scanspeed, scanmode)
            PortArray = AnalyseScanResults(PortScanResults,host)
            if len(PortArray) > 0:
                if UserWantsVulnerabilityDetection():
                    SearchSploits(PortArray, apiKey)
            else:
                print("Skipping vulnerability detection for " + str(host))
                WriteToFile("Skipped vulnerability detection for " + str(host))
            WriteToFile("\n" + "-" * 60)

#main function
def main():
    check_nmap()
    OnlineHosts = DiscoverHosts(targetarg, scantype, scanspeed, scanmode)
    FurtherEnumuration(OnlineHosts)

#only run the script if its not imported as a module (directly interpreted with python3)
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_colored("Ctrl+C pressed. Exiting.", colors.red)
        WriteToFile("Ctrl+C pressed. Exiting.")
