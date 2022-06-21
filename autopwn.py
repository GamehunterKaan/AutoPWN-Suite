#!/usr/bin/env python3
try:
    from argparse import ArgumentParser
    from socket import socket, AF_INET, SOCK_DGRAM
    from os import getuid
    from subprocess import check_call, CalledProcessError, DEVNULL
    from enum import Enum
    from datetime import datetime
    from platform import system as system_name
    from configparser import ConfigParser
    from modules.report import InitializeReport, ReportType, ReportMail, ReportWebhook
    from modules.banners import print_banner
    from modules.searchvuln import SearchSploits
    from modules.scanner import AnalyseScanResults, PortScan, DiscoverHosts, ScanMode, ScanType, NoiseScan
    from modules.getexploits import GetExploitsFromArray
    from modules.web.webvuln import webvuln
    from modules.logger import info, error, warning, success, println, banner, InitializeLogger, print_colored, colors, bcolors
except ImportError as e:
    print("[!] ImportError: " + str(e))
    exit(1)

__author__ = 'GamehunterKaan'
__version__ = '1.5.0'

#parse command line arguments
argparser = ArgumentParser(description="AutoPWN Suite")
argparser.add_argument("-v", "--version", help="Print version and exit.", action="store_true")
argparser.add_argument("-y", "--yesplease", help="Don't ask for anything. (Full automatic mode)",action="store_true", required=False, default=False)
argparser.add_argument("-c", "--config", help="Specify a config file to use. (Default : None)", default=None, required=False, metavar="CONFIG", type=str)

scanargs = argparser.add_argument_group('Scanning', 'Options for scanning')
scanargs.add_argument("-t", "--target", help="Target range to scan. This argument overwrites the hostfile argument. (192.168.0.1 or 192.168.0.0/24)", type=str, required=False, default=None,)
scanargs.add_argument("-hf", "--hostfile", help="File containing a list of hosts to scan.", type=str, required=False, default=None)
scanargs.add_argument("-st", "--scantype", help="Scan type.", type=str, required=False, default=None, choices=["arp", "ping"])
scanargs.add_argument("-nf", "--nmapflags", help="Custom nmap flags to use for portscan. (Has to be specified like : -nf=\"-O\")", default="", type=str, required=False)
scanargs.add_argument("-s", "--speed", help="Scan speed. (Default : 3)", default=3, type=int, required=False, choices=range(0,6))
scanargs.add_argument("-a", "--api", help="Specify API key for vulnerability detection for faster scanning. (Default : None)", default=None, type=str, required=False)
scanargs.add_argument("-m", "--mode", help="Scan mode.", default="normal", type=str, required=False, choices=["evade", "noise", "normal"])
scanargs.add_argument("-nt", "--noisetimeout", help="Noise mode timeout. (Default : None)", default=None, type=int, required=False, metavar="TIMEOUT")

reportargs = argparser.add_argument_group('Reporting', 'Options for reporting')
reportargs.add_argument("-o", "--output", help="Output file name. (Default : autopwn.log)", default="autopwn.log", type=str, required=False)
reportargs.add_argument("-rp", "--report", help="Report sending method.", type=str, required=False, default=None, choices=["email", "webhook"])
reportargs.add_argument("-rpe", "--reportemail", help="Email address to use for sending report.", type=str, required=False, default=None, metavar="EMAIL")
reportargs.add_argument("-rpep", "--reportemailpassword", help="Password of the email report is going to be sent from.", type=str, required=False, default=None, metavar="PASSWORD")
reportargs.add_argument("-rpet", "--reportemailto", help="Email address to send report to.", type=str, required=False, default=None, metavar="EMAIL")
reportargs.add_argument("-rpef", "--reportemailfrom", help="Email to send from.", type=str, required=False, default=None, metavar="EMAIL")
reportargs.add_argument("-rpes", "--reportemailserver", help="Email server to use for sending report.", type=str, required=False, default=None, metavar="SERVER")
reportargs.add_argument("-rpesp", "--reportemailserverport", help="Port of the email server.", type=int, required=False, default=None, metavar="PORT")
reportargs.add_argument("-rpw", "--reportwebhook", help="Webhook to use for sending report.", type=str, required=False, default=None, metavar="WEBHOOK")

args = argparser.parse_args()

def is_root(): # this function is used everywhere, so it's better to put it here
    return getuid() == 0

def InitArgsConf():
    if not args.config:
        return None
    try:
        config = ConfigParser()
        config.read(args.config)
        if config.has_option('AUTOPWN', 'target'):
            args.target = config.get('AUTOPWN', 'target').lower()
        if config.has_option('AUTOPWN', 'hostfile'):
            args.hostfile = config.get('AUTOPWN', 'hostfile').lower()
        if config.has_option('AUTOPWN', 'scantype'):
            args.scantype = config.get('AUTOPWN', 'scantype').lower()
        if config.has_option('AUTOPWN', 'nmapflags'):
            args.nmapflags = config.get('AUTOPWN', 'nmapflags').lower()
        if config.has_option('AUTOPWN', 'speed'):
            try:
                args.speed = int(config.get('AUTOPWN', 'speed'))
            except ValueError:
                error("[!] Invalid speed value in config file. (Default : 3)")
        if config.has_option('AUTOPWN', 'apikey'):
            args.api = config.get('AUTOPWN', 'apikey').lower()
        if config.has_option('AUTOPWN', 'auto'):
            args.yesplease = True
        if config.has_option('AUTOPWN', 'mode'):
            args.mode = config.get('AUTOPWN', 'mode').lower()
        if config.has_option('AUTOPWN', 'noisetimeout'):
            args.noisetimeout = config.get('AUTOPWN', 'noisetimeout').lower()
        if config.has_option('REPORT', 'output'):
            args.output = config.get('AUTOPWN', 'output').lower()
        if config.has_option('REPORT', 'method'):
            args.report = config.get('REPORT', 'method').lower()
        if config.has_option('REPORT', 'email'):
            args.reportemail = config.get('REPORT', 'email').lower()
        if config.has_option('REPORT', 'email_password'):
            args.reportemailpassword = config.get('REPORT', 'email_password').lower()
        if config.has_option('REPORT', 'email_to'):
            args.reportemailto = config.get('REPORT', 'email_to').lower()
        if config.has_option('REPORT', 'email_from'):
            args.reportemailfrom = config.get('REPORT', 'email_from').lower()
        if config.has_option('REPORT', 'email_server'):
            args.reportemailserver = config.get('REPORT', 'email_server').lower()
        if config.has_option('REPORT', 'email_port'):
            args.reportemailserverport = config.get('REPORT', 'email_port').lower()
        if config.has_option('REPORT', 'webhook'):
            args.reportwebhook = config.get('REPORT', 'webhook').lower()

    except FileNotFoundError:
        error("Config file not found!")
        exit(1)
    except PermissionError:
        error("Permission denied while trying to read config file!")
        exit(1)
    except Exception as e:
        error("Unknown error while trying to read config file! " + str(e))
        exit(1)


def InitArgsScanType():
    if args.scantype == "arp":
        if not is_root():
            error("You must be root to do an arp scan!")
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
    return scantype

def InitArgsAPI():
    if args.api:
        apiKey = args.api
    else:
        try:
            with open("api.txt", "r") as f:
                apiKey = f.readline().strip("\n")
        except FileNotFoundError:
            warning("No API key specified and no api.txt file found. Vulnerability detection is going to be slower!")
            warning("You can get your own NIST API key from https://nvd.nist.gov/developers/request-an-api-key")
            apiKey = None
        except PermissionError:
            error("Permission denied while trying to read api.txt!")
            apiKey = None
    return apiKey

def install_nmap_linux():
    try:
        debian_installer = check_call(["/usr/bin/sudo", "apt-get", "install", "nmap", "-y"], stderr=DEVNULL)
    except CalledProcessError:
        try:
            arch_installer = check_call(["/usr/bin/sudo", "pacman", "-S", "nmap", "--noconfirm"], stderr=DEVNULL)
        except CalledProcessError:
            try:
                fedora_installer = check_call(["/usr/bin/sudo", "dnf", "install", "nmap"], stderr=DEVNULL)
            except CalledProcessError:
                try:
                    yum_installer = check_call(["/usr/bin/sudo", "yum", "install", "nmap"], stderr=DEVNULL)
                except CalledProcessError:
                    error("Couldn't install nmap! (Linux)")

def install_nmap_windows():
    # TODO: implement this
    """shut up, pylint"""
    try:
        check_call(["powershell", "winget", "install", "nmap", "--silent"], stderr=DEVNULL)
    except CalledProcessError:
        error("Couldn't install nmap! (Windows)")

def install_nmap_mac():
    try:
        check_call(["/usr/bin/sudo", "brew", "install", "nmap"], stderr=DEVNULL)
    except CalledProcessError:
        error("Couldn't install nmap! (Mac)")

def check_nmap():
    # Check if nmap is installed
    # If not, install it
    try:
        nmap_checker = check_call(["nmap", "-h"], stdout=DEVNULL, stderr=DEVNULL)
    except FileNotFoundError:
        warning("Nmap is not installed. Auto installing...")
        if platform.system() == "Linux":
            install_nmap_linux()
        elif system_name() == "Windows":
            install_nmap_windows()
        elif system_name() == "Darwin":
            install_nmap_mac()
        else:
            error("Unknown OS! Auto installation not supported!")
            exit(1)

def DetectIPRange():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = s.getsockname()[0]
    target = str(str(PrivateIPAdress.split('.')[0]) + '.' + str(PrivateIPAdress.split('.')[1]) + '.' + PrivateIPAdress.split('.')[2] + '.0/24')
    return target

def InitArgsTarget():
    if args.target:
        target = args.target
    else:
        if args.hostfile:
            # read targets from host file and insert all of them into an array
            try:
                target = open(args.hostfile,'r').read().splitlines()
            except FileNotFoundError:
                error("Host file not found!")
                target = DetectIPRange()
            except PermissionError:
                error("Permission denied while trying to read host file!")
                target = DetectIPRange()
            except Exception:
                error("Unknown error while trying to read host file!")
                target = DetectIPRange()
        else:
            if DontAskForConfirmation:
                target = DetectIPRange()
            else:
                try:
                    target = input("Enter target range to scan : ")
                except KeyboardInterrupt:
                    print()
                    error("Ctrl+C pressed. Exiting.")
                    exit(0)
    return target

def InitArgsMode():
    if args.mode == "evade":
        if is_root():
            scanmode = ScanMode.Evade
            scanspeed = 2
            info("Evasion mode enabled!")
        else:
            error("You must be root to use evasion mode! Switching back to normal mode...")
            scanmode = ScanMode.Normal
    elif args.mode == "noise":
        scanmode = ScanMode.Noise
        warning("Noise mode enabled!")
    elif args.mode == "normal":
        scanmode = ScanMode.Normal
    
    return scanmode

def InitReport():
    if not args.report:
        return ReportType.NONE, None

    if args.report == "email":
        Method = ReportType.EMAIL
        if args.reportemail:
            ReportEmail = args.reportemail
        else:
            ReportEmail = input("Enter your email address : ")
        if args.reportemailpassword:
            ReportMailPassword = args.reportemailpassword
        else:
            ReportMailPassword = getpass("Enter your email password : ")
        if args.reportemailto:
            ReportMailTo = args.reportemailto
        else:
            ReportMailTo = input("Enter the email address to send the report to : ")
        if args.reportemailfrom:
            ReportMailFrom = args.reportemailfrom
        else:
            ReportMailFrom = ReportEmail
        if args.reportemailserver:
            ReportMailServer = args.reportemailserver
        else:
            ReportMailServer = input("Enter the email server to send the report from : ")
            if ReportMailServer == "smtp.gmail.com":
                error("Google no longer supports sending mails via SMTP! Canceling report via email.")
                return ReportType.NONE, None
        if args.reportemailserverport:
            ReportMailPort = args.reportemailserverport
        else:
            while True:
                ReportMailPort = input("Enter the email port to send the report from : ")
                try:
                    ReportMailPorT = int(ReportMailPort)
                    break
                except ValueError:
                    error("Invalid port number!")

        EmailObj = ReportMail(ReportEmail, ReportMailPassword, ReportMailTo, ReportMailFrom, ReportMailServer, int(ReportMailPort), args.output)

        return Method, EmailObj

    elif args.report == "webhook":
        Method = ReportType.WEBHOOK
        if args.reportwebhook:
            Webhook = args.reportwebhook
        else:
            Webhook = input("Enter your webhook URL : ")

        WebhookObj = ReportWebhook(Webhook, args.output)
        
        return Method, WebhookObj

def ParamPrint():
    # print everything inside args class to screen
    if args.config:
        println("\n┌─[ Config file " + args.config + " was used. ]")
        println("├─[ Scanning with the following parameters. ]")
    else:
        println("\n┌─[ Scanning with the following parameters. ]")

    println("├" + "─" * 59)
    println("│\tTarget : " + str(targetarg))
    println("│\tScan type : " + str(scantype.name))
    println("│\tScan mode : " + str(scanmode.name))
    println("│\tScan speed : " + str(scanspeed))
    println("│\tNmap flags : " + str(nmapflags))
    println("│\tAPI key : " + str(apiKey))
    println("│\tOutput file : " + str(outputfile))
    println("│\tDont ask for confirmation : " + str(DontAskForConfirmation))
    println("│\tHost file : " + str(args.hostfile))
    println("│\tReporting method : " + str(args.report))
    println("└" + "─" * 59)

def Confirmation(message):
    if DontAskForConfirmation:
        return True
    confirmation = input(message)
    return confirmation.lower() != "n"

def UserConfirmation():
    if DontAskForConfirmation:
        return True, True, True
    portscan = Confirmation("Do you want to scan ports? [Y/n] : ")
    if portscan == False:
        return False, False, False
    vulnscan = Confirmation("Do you want to scan for vulnerabilities? [Y/n] : ")
    if vulnscan == False:
        return True, False, False
    downloadexploits = Confirmation("Do you want to download exploits? [Y/n] : ")
    return portscan, vulnscan, downloadexploits

def WebScan():
    return Confirmation("Do you want to scan for web vulnerabilities? [Y/n] : ")

def GetHostsToScan(hosts):
    if len(hosts) == 0:
        error("No hosts found!")
        println(str(datetime.now().strftime("%b %d %Y %H:%M:%S")) + " - Scan completed.")
        exit(0)
    index = 0
    for host in hosts:
        println((bcolors.red + "[" + bcolors.endc + str(index) + bcolors.red + "] " + bcolors.endc + host).center(60))
        index += 1
    if DontAskForConfirmation:
        return hosts
    print_colored("\nEnter the index number of the host you would like to enumurate further.", colors.yellow)
    print_colored("Enter 'all' to enumurate all hosts.", colors.yellow)
    print_colored("Enter 'exit' to exit.\n", colors.yellow)
    while True:
        host = input(bcolors.blue + "────> " + bcolors.endc)
        if host == 'all':
            Targets = hosts
            break
        elif host == 'exit':
            println(str(datetime.now().strftime("%b %d %Y %H:%M:%S")) + " - Scan completed.")
            exit(0)
        elif host in hosts:
            Targets = [host]
            break
        elif host == "":
            Targets = hosts
            break
        else:
            try:
                if int(host) < len(hosts) and int(host) >= 0:
                    Targets = [hosts[int(host)]]
                    break
            except:
                print_colored("Please enter a valid host number or 'all' or 'exit'", colors.red)

    return Targets

#post scan stuff
def FurtherEnumuration(hosts):
    Targets = GetHostsToScan(hosts)
    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()

    for host in Targets:
        if ScanPorts:
            PortScanResults = PortScan(host, scanspeed, scanmode, nmapflags)
            PortArray = AnalyseScanResults(PortScanResults,host)
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, apiKey)
                if DownloadExploits and len(VulnsArray) > 0:
                    GetExploitsFromArray(VulnsArray, host)

        if ScanWeb:
            webvuln(host)

#main function
def main():
    if args.version:
        println("AutoPWN Suite v" + __version__)
        exit(0)
    if args.config:
        InitArgsConf()
    
    global targetarg, scantype, scanmode, scanspeed, nmapflags, apiKey, outputfile, DontAskForConfirmation, hostfile, noisetimeout

    outputfile = args.output
    InitializeLogger(outputfile)
    print_banner()

    DontAskForConfirmation = args.yesplease
    targetarg = InitArgsTarget()
    scantype = InitArgsScanType()
    scanmode = InitArgsMode()
    scanspeed = args.speed
    nmapflags = args.nmapflags
    apiKey = InitArgsAPI()
    hostfile = args.hostfile
    noisetimeout = args.noisetimeout
    ReportMethod, ReportObject = InitReport()

    if is_root() == False:
        error("It's recommended to run this script as root since it's more silent and accurate.")
    ParamPrint()
    check_nmap()
    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, scantype, noisetimeout)
    OnlineHosts = DiscoverHosts(targetarg, scantype, scanspeed, scanmode)
    FurtherEnumuration(OnlineHosts)
    InitializeReport(ReportMethod, ReportObject)
    print(" " * 200, end="\r")
    println(str(datetime.now().strftime("%b %d %Y %H:%M:%S")) + " - Scan completed.")

#only run the script if its not imported as a module (directly interpreted with python3)
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        error("Ctrl+C pressed. Exiting.")
        exit(0)