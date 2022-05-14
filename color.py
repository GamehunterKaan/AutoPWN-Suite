#!/usr/bin/env python3

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

def print_colored(text,color):
    if color == 'blue':
        print(bcolors.BLUE + str(text) + bcolors.ENDC)
    elif color == 'cyan':
        print(bcolors.CYAN + str(text) + bcolors.ENDC)
    elif color == 'green':
        print(bcolors.GREEN + str(text) + bcolors.ENDC)
    elif color == 'yellow':
        print(bcolors.YELLOW + str(text) + bcolors.ENDC)
    elif color == 'red':
        print(bcolors.RED + str(text) + bcolors.ENDC)
    elif color == 'bold':
        print(bcolors.BOLD + str(text) + bcolors.ENDC)
    elif color == 'underline':
        print(bcolors.UNDERLINE + str(text) + bcolors.ENDC)
    elif color == 'no_new_line':
        print(str(text), end='')