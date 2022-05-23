#!/usr/bin/env python3

#https://stackoverflow.com/a/287944

#colors
class bcolors:
    header = '\033[95m'
    blue = '\033[94m'
    cyan = '\033[96m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    endc = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

#colors but string
class colors:
    blue = 'blue'
    cyan = 'cyan'
    green = 'green'
    yellow = 'yellow'
    red = 'red'
    bold = 'bold'
    underline = 'underline'
    no_new_line = 'no_new_line'
    endc = 'endc'

#print the text with specified color
def print_colored(text,color):
    if color == 'blue':
        print(bcolors.blue + str(text) + bcolors.endc)
    elif color == 'cyan':
        print(bcolors.cyan + str(text) + bcolors.endc)
    elif color == 'green':
        print(bcolors.green + str(text) + bcolors.endc)
    elif color == 'yellow':
        print(bcolors.yellow + str(text) + bcolors.endc)
    elif color == 'red':
        print(bcolors.red + str(text) + bcolors.endc)
    elif color == 'bold':
        print(bcolors.bold + str(text) + bcolors.endc)
    elif color == 'underline':
        print(bcolors.underline + str(text) + bcolors.endc)
    elif color == 'no_new_line':
        print(str(text), end='')