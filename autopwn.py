#!/usr/bin/env python3
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM
from os import getuid
from subprocess import check_call, CalledProcessError, DEVNULL
from enum import Enum
from configparser import ConfigParser
from modules.color import print_colored, colors, bcolors
from modules.banners import print_banner
from modules.searchvuln import SearchSploits
from modules.scanner import AnalyseScanResults, PortScan, DiscoverHosts, ScanMode, ScanType, NoiseScan
from modules.outfile import InitializeOutput, WriteToFile, OutputBanner

__author__ = 'GamehunterKaan'
__version__ = '1.1.5'

#parse command line arguments
argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument("-o", "--output", help="Output file name. (Default : autopwn.log)", default="autopwn.log", type=str, required=False)
argparser.add_argument("-t", "--target", help="Target range to scan. This argument overwrites the hostfile argument. (192.168.0.1 or 192.168.0.0/24)", type=str, required=False, default=None,)
argparser.add_argument("-hf", "--hostfile", help="File containing a list of hosts to scan.", type=str, required=False, default=None)
argparser.add_argument("-st", "--scantype", help="Scan type.", type=str, required=False, default=None, choices=["arp", "ping"])
argparser.add_argument("-nf", "--nmapflags", help="Custom nmap flags to use for portscan. (Has to be specified like : -nf=\"-O\")", default="", type=str, required=False)
argparser.add_argument("-s", "--speed", help="Scan speed. (Default : 3)", default=3, type=int, required=False, choices=range(0,6))
argparser.add_argument("-a", "--api", help="Specify API key for vulnerability detection for faster scanning. (Default : None)", default=None, type=str, required=False)
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)",action="store_true", required=False, default=False)
argparser.add_argument("-m", "--mode", help="Scan mode.", default="normal", type=str, required=False, choices=["evade", "noise", "normal"])
argparser.add_argument("-nt", "--noisetimeout", help="Noise mode timeout. (Default : None)", default=None, type=int, required=False, metavar="TIMEOUT")
argparser.add_argument("-c", "--config", help="Specify a config file to use. (Default : None)", default=None, required=False, metavar="CONFIG", type=str)
argparser.add_argument("-v", "--version", help="Print version and exit.", action="store_true")
args = argparser.parse_args()

if args.version:
    print("AutoPWN Suite v" + __version__)
    exit(0)

#print a beautiful banner
print_banner()

if args.config:
    try:
        config = ConfigParser()
        config.read(args.config)
        if config.has_option('AUTOPWN', 'output'):
            args.output = config.get('AUTOPWN', 'output').lower()
        if config.has_option('AUTOPWN', 'target'):
            args.target = config.get('AUTOPWN', 'target').lower()
        if config.has_option('AUTOPWN', 'hostfile'):
            args.hostfile = config.get('AUTOPWN', 'hostfile').lower()
        if config.has_option('AUTOPWN', 'scantype'):
            args.scantype = config.get('AUTOPWN', 'scantype').lower()
        if config.has_option('AUTOPWN', 'nmapflags'):
            args.nmapflags = config.get('AUTOPWN', 'nmapflags').lower()
        if config.has_option('AUTOPWN', 'speed'):
            args.speed = config.get('AUTOPWN', 'speed').lower()
        if config.has_option('AUTOPWN', 'apikey'):
            args.api = config.get('AUTOPWN', 'apikey').lower()
        if config.has_option('AUTOPWN', 'auto'):
            args.yesplease = True
        if config.has_option('AUTOPWN', 'mode'):
            args.mode = config.get('AUTOPWN', 'mode').lower()
        if config.has_option('AUTOPWN', 'noisetimeout'):
            args.noisetimeout = config.get('AUTOPWN', 'noisetimeout').lower()
    except FileNotFoundError:
        print_colored("Config file not found!", colors.red)
        exit(1)
    except PermissionError:
        print_colored("Permission denied while trying to read config file!", colors.red)
        exit(1)
    except Exception as e:
        print_colored("Unknown error while trying to read config file! " + str(e), colors.red)
        exit(1)

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
        scantype = ScanType.Ping
    else:
        scantype = ScanType.Arp
elif args.scantype == "ping":
    scantype = ScanType.Ping
elif args.scantype == "" or type(args.scantype) == None or args.scantype == None:
    if is_root():
        scantype = ScanType.ARP
    else:
        scantype = ScanType.Ping

nmapflags = args.nmapflags
scanspeed = int(args.speed)

if is_root() == False:
    print_colored("It's recommended to run this script as root since it's more silent and accurate.", colors.red)

if args.api:
    apiKey = args.api
else:
    try:
        with open("api.txt", "r") as f:
            apiKey = f.readline().strip("\n")
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
    # TODO : Add a function to install nmap on windows
    try:
        nmap_checker = check_call(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)
    except FileNotFoundError:
        print_colored("Nmap is not installed. Auto installing...", colors.yellow)
        try:
            debian_installer = check_call(["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"], stderr=DEVNULL)
        except CalledProcessError:
            try:
                arch_instller = check_call(["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"], stderr=DEVNULL)
            except CalledProcessError:
                try:
                    fedore_installer = check_call(["/usr/bin/sudo", "dnf", "install", "nmap"], stderr=DEVNULL)
                except CalledProcessError:
                    try:
                        yum_installer = check_call(["/usr/bin/sudo", "yum", "install", "nmap"], stderr=DEVNULL)
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

if args.mode == "evade":
    if is_root():
        scanmode = ScanMode.Evade
        scanspeed = 2
        print_colored("Evasion mode enabled!", colors.yellow)
    else:
        print_colored("You must be root to use evasion mode! Switching back to normal mode...", colors.red)
        scanmode = ScanMode.Normal
elif args.mode == "noise":
    scanmode = ScanMode.Noise
    print_colored("Noise mode enabled!", colors.yellow)
elif args.mode == "normal":
    scanmode = ScanMode.Normal

# print everything inside args class to screen
if args.config:
    print_colored("\n┌─[ Config file " + args.config + " was used. ]", colors.bold)
    print_colored("├─[ Scanning with the following parameters. ]", colors.bold)
else:
    print_colored("\n┌─[ Scanning with the following parameters. ]", colors.bold)

print_colored("├" + "─" * 59, colors.bold)
print_colored("│\tTarget : " + str(targetarg), colors.bold)
print_colored("│\tScan type : " + str(scantype.name), colors.bold)
print_colored("│\tScan mode : " + str(scanmode.name), colors.bold)
print_colored("│\tScan speed : " + str(scanspeed), colors.bold)
print_colored("│\tNmap flags : " + str(nmapflags), colors.bold)
print_colored("│\tAPI key : " + str(apiKey), colors.bold)
print_colored("│\tOutput file : " + str(outputfile), colors.bold)
print_colored("│\tDont ask for confirmation : " + str(DontAskForConfirmation), colors.bold)
print_colored("│\tHost file : " + str(args.hostfile), colors.bold)
print_colored("└" + "─" * 59, colors.bold)

OutputBanner(targetarg, scantype, scanspeed, args.hostfile, scanmode)

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
    if len(hosts) == 0:
        print_colored("No hosts found!", colors.red)
        exit(0)
    index = 0
    for host in hosts:
        print(("%s[%s%d%s]%s %s" % (bcolors.red, bcolors.endc, index, bcolors.red, bcolors.endc, host)).center(60))
        WriteToFile(("[%d] %s" % (index, host)).center(60))
        index += 1
    if not DontAskForConfirmation:
        print_colored("\nEnter the index number of the host you would like to enumurate further.", colors.yellow)
        print_colored("Enter 'all' to enumurate all hosts.", colors.yellow)
        print_colored("Enter 'exit' to exit.\n", colors.yellow)
        while True:
            host = input(bcolors.blue + "----> " + bcolors.endc)
            if host == 'all':
                Targets = hosts
                break
            elif host == 'exit':
                exit(0)
            elif host in hosts:
                Targets = [host]
                break
            elif int(host) < len(hosts) and int(host) >= 0:
                Targets = [hosts[int(host)]]
                break
            else:
                print_colored("Please enter a valid host number or 'all' or 'exit'", colors.red)
    else:
        Targets = hosts
    if UserWantsPortScan():
        if UserWantsVulnerabilityDetection():
            for host in Targets:
                PortScanResults = PortScan(host, scanspeed, scanmode, nmapflags)
                PortArray = AnalyseScanResults(PortScanResults,host)
                if len(PortArray) > 0:
                    SearchSploits(PortArray, apiKey)
        else:
            for host in Targets:
                PortScanResults = PortScan(host, scanspeed, scanmode, nmapflags)
                PortArray = AnalyseScanResults(PortScanResults,host)
    else:
        exit(0)

#main function
def main():
    check_nmap()
    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, scantype, args.noisetimeout)
    OnlineHosts = DiscoverHosts(targetarg, scantype, scanspeed, scanmode)
    FurtherEnumuration(OnlineHosts)

#only run the script if its not imported as a module (directly interpreted with python3)
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_colored("Ctrl+C pressed. Exiting.", colors.red)
        WriteToFile("Ctrl+C pressed. Exiting.")
