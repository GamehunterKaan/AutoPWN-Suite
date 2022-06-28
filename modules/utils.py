try:
    import distro
    from os import getuid
    from ctypes import windll
except ImportError:
    pass

from socket import socket, AF_INET, SOCK_DGRAM
from subprocess import check_call, DEVNULL, CalledProcessError
from sys import platform as sys_platform
from platform import platform, system
from configparser import ConfigParser


def is_root(): # this function is used everywhere, so it's better to put it here
    try:
        return getuid() == 0
    except Exception as e:
        return windll.shell32.IsUserAnAdmin() == 1


def DetectIPRange():
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        PrivateIPAdress = str(s.getsockname()[0]).split(".")
        target = (
                f"{PrivateIPAdress[0]}.",
                f"{PrivateIPAdress[1]}.",
                f"{PrivateIPAdress[2]}.0/24"
            )
    except ConnectionError:
        raise SystemExit
    else:
        return target



def InitArgsAPI(args, log):
    if args.api:
        apiKey = args.api

    else:
        apiKey = None
        try:
            with open("api.txt", "r", encoding="utf-8") as f:
                apiKey = f.readline().strip("\n")
        except FileNotFoundError:
            log.logger(
                "warning",
                "No API key specified and no api.txt file found. "
                + "Vulnerability detection is going to be slower!"
                + "You can get your own NIST API key from "
                + "https://nvd.nist.gov/developers/request-an-api-key"
            )
        except PermissionError:
            log.logger(
                "error", "Permission denied while trying to read api.txt!"
            )

    return apiKey


def InitArgsScanType(args, ScanType):
    scantype = ScanType.Ping
    if args.scantype == "arp" or args.scantype is None or args.scantype == "":
        if is_root():
            scantype = ScanType.ARP

    return scantype


def InitArgsConf(args, log):
    if not args.config:
        return None

    try:
        config = ConfigParser()
        config.read(args.config)

        if config.has_option("AUTOPWN", "target"):
            args.target = config.get("AUTOPWN", "target").lower()

        if config.has_option("AUTOPWN", "hostfile"):
            args.hostfile = config.get("AUTOPWN", "hostfile").lower()

        if config.has_option("AUTOPWN", "scantype"):
            args.scantype = config.get("AUTOPWN", "scantype").lower()

        if config.has_option("AUTOPWN", "nmapflags"):
            args.nmapflags = config.get("AUTOPWN", "nmapflags").lower()

        if config.has_option("AUTOPWN", "speed"):
            try:
                args.speed = int(config.get("AUTOPWN", "speed"))
            except ValueError:
                log.logger(
                    "error",
                    "Invalid speed value in config file. (Default : 3)"
                )

        if config.has_option("AUTOPWN", "apikey"):
            args.api = config.get("AUTOPWN", "apikey").lower()

        if config.has_option("AUTOPWN", "auto"):
            args.yesplease = True

        if config.has_option("AUTOPWN", "mode"):
            args.mode = config.get("AUTOPWN", "mode").lower()

        if config.has_option("AUTOPWN", "noisetimeout"):
            args.noisetimeout = config.get("AUTOPWN", "noisetimeout").lower()

        if config.has_option("REPORT", "output"):
            args.output = config.get("AUTOPWN", "output").lower()

        if config.has_option("REPORT", "method"):
            args.report = config.get("REPORT", "method").lower()

        if config.has_option("REPORT", "email"):
            args.reportemail = config.get("REPORT", "email").lower()

        if config.has_option("REPORT", "email_password"):
            args.reportemailpassword = config.get(
                    "REPORT", "email_password"
                ).lower()

        if config.has_option("REPORT", "email_to"):
            args.reportemailto = config.get("REPORT", "email_to").lower()

        if config.has_option("REPORT", "email_from"):
            args.reportemailfrom = config.get("REPORT", "email_from").lower()

        if config.has_option("REPORT", "email_server"):
            args.reportemailserver = config.get(
                    "REPORT", "email_server"
                ).lower()

        if config.has_option("REPORT", "email_port"):
            args.reportemailserverport = config.get(
                    "REPORT", "email_port"
                ).lower()

        if config.has_option("REPORT", "webhook"):
            args.reportwebhook = config.get("REPORT", "webhook").lower()

    except FileNotFoundError:
        log.logger("error", "Config file not found!")
        raise SystemExit
    except PermissionError:
        log.logger(
            "error", "Permission denied while trying to read config file!"
        )
        raise SystemExit


def install_nmap_linux(log):
    distro_ = distro.id().lower()
    while True:
        try:
            if distro_ in ["ubuntu", "debian", "linuxmint", "raspbian"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "apt-get",
                        "install",
                        "nmap",
                        "-y"
                        ],
                    stderr=DEVNULL
                )
            elif distro_ in ["arch", "manjaro"]:
                check_call(
                        [
                            "/usr/bin/sudo",
                            "pacman",
                            "-S",
                            "nmap",
                            "--noconfirm"
                            ],
                        stderr=DEVNULL
                )
            elif distro_ in ["fedora", "oracle"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "dnf",
                        "install",
                        "nmap",
                        "-y"
                        ],
                    stderr=DEVNULL
                )
            elif distro in ["rhel", "centos"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "yum",
                        "install",
                        "nmap",
                        "-y"
                        ],
                    stderr=DEVNULL
                )
            elif distro in ["sles", "opensuse"]:
                check_call(
                    [
                        "/usr/bin/sudo",
                        "zypper",
                        "install",
                        "nmap",
                        "--non-interactive"
                        ],
                    stderr=DEVNULL
                )
            else:
                raise CalledProcessError

        except CalledProcessError:
            _distro_ = input(
                    "Cannot recognize the needed package manager for your "
                    + f"system that seems to be running in: {distro_} and "
                    + f"{sys_platform}, {platform()}, kindly select the "
                    + "correct package manager below to proceed to the "
                    + "installation, else, select, n.\n\t0 Abort installation\n"
                    + "\t1 apt-get\n\t2 dnf\n\t3 yum\n\t4 pacman\n\t5 zypper."
                    + "\nSelect option [0-5] >"
                )
            if _distro_ == 1:
                distro_ = "ubuntu"
            elif _distro_ == 2:
                distro_ = "fedora"
            elif _distro_ == 3:
                distro_ = "centos"
            elif _distro_ == 4:
                distro_ = "arch"
            elif _distro_ == 5:
                distro_ = "opensuse"
            else:
                log.logger("error", "Couldn't install nmap (Linux)")
                break
            continue


def install_nmap_windows(log):
    # TODO: implement this
    """shut up, pylint"""
    try:
        check_call(
            [
                "powershell",
                "winget",
                "install",
                "nmap",
                "--silent"
                ],
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Windows)")


def install_nmap_mac(log):
    try:
        check_call(
            [
                "/usr/bin/sudo",
                "brew",
                "install",
                "nmap"
                ],
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("error", "Couldn't install nmap! (Mac)")


def check_nmap(log):
    # Check if nmap is installed if not, install it
    try:
        check_call(
            ["nmap", "-h"],
            stdout=DEVNULL,
            stderr=DEVNULL
        )
    except CalledProcessError:
        log.logger("warning", "Nmap is not installed.")
        auto_install = input(
                f"Install Nmap on your system ({distro.id()}: {platform()})? "
            )
        if auto_install in ["y", "Y"]:
            platform_ = system().lower()
            if  platform_ == "linux":
                install_nmap_linux()
            if platform_ == "windows":
                install_nmap_windows()
            elif platform_ == "darwin":
                install_nmap_mac()
            else:
                raise SystemExit(
                    "Unknown OS! Auto installation not supported!"
                )
        else:
            log.logger("error", "Denied permission to install Nmap.")
            raise SystemExit

def ParamPrint(
        args,
        targetarg,
        scantype_name,
        scanmode_name,
        scanspeed,
        nmapflags,
        apiKey,
        outputfile,
        DontAskForConfirmation,
        console,
        term_width
    ):
    # print everything inside args class to screen
    if args.config:
        console.print(f"\n┌─[ Config file {args.config} was used. ]")
        console.print("├─[ Scanning with the following parameters. ]")
    else:
        console.print("\n┌─[ Scanning with the following parameters. ]")

    console.print(
        "├" + "─" * (term_width-1)
        + f"\n│\tTarget : {targetarg}\n"
        + f"│\tScan type : {scantype_name}\n"
        + f"│\tScan mode : {scanmode_name}\n"
        + f"│\tScan speed : {scanspeed}\n"
        + f"│\tNmap flags : {nmapflags}\n"
        + f"│\tAPI key : {apiKey}\n"
        + f"│\tOutput file : {outputfile}\n"
        + f"│\tDont ask for confirmation : {DontAskForConfirmation}\n"
        + f"│\tHost file : {args.hostfile}\n"
        + f"│\tReporting method : {args.report}\n"
        + "└" + "─" * (term_width-1)
    )
