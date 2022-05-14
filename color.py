#https://stackoverflow.com/a/287944
class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_blue(text):
    print(bcolors.BLUE + str(text) + bcolors.ENDC)

def print_cyan(text):
    print(bcolors.CYAN + str(text) + bcolors.ENDC)

def print_green(text):
    print(bcolors.GREEN + str(text) + bcolors.ENDC)

def print_yellow(text):
    print(bcolors.YELLOW + str(text) + bcolors.ENDC)

def print_red(text):
    print(bcolors.RED + str(text) + bcolors.ENDC)

def print_bold(text):
    print(bcolors.BOLD + str(text) + bcolors.ENDC)

def print_underline(text):
    print(bcolors.UNDERLINE + str(text) + bcolors.ENDC)
