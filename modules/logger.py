def InitializeLogger(context):
    global outfile
    outfile = context
    file = open(outfile, 'w')
    file.close()

# https://stackoverflow.com/a/287944
class bcolors:
    header = '\033[95m'
    blue = '\033[94m'
    cyan = '\033[96m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    purple = '\033[38;5;93m'
    endc = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

class colors:
    blue = 'blue'
    cyan = 'cyan'
    green = 'green'
    yellow = 'yellow'
    red = 'red'
    purple = 'purple'
    bold = 'bold'
    underline = 'underline'
    no_new_line = 'no_new_line'
    endc = 'endc'

def WriteToFile(data):
    colors = [bcolors.blue, bcolors.red, bcolors.yellow, bcolors.green, bcolors.cyan, bcolors.endc, bcolors.bold, bcolors.underline]
    for colorcode in colors:
        data = data.replace(colorcode, "")
    filename = outfile
    file = open(filename, 'a')
    file.write("\n" + data)
    file.close()

def info(msg):
    print(bcolors.blue + "[+] " + bcolors.endc + str(msg))
    WriteToFile("[+] " + msg)

def error(msg):
    print(bcolors.red + "[-] " + bcolors.endc + str(msg))
    WriteToFile("[-] " + msg)

def warning(msg):
    print(bcolors.yellow + "[*] " + bcolors.endc + str(msg))
    WriteToFile("[*] " + msg)

def success(msg):
    print(bcolors.green + "[+] " + bcolors.endc + str(msg))
    WriteToFile("[+] " + msg)

def println(msg):
    print(msg)
    WriteToFile(msg)

def banner(msg, color):
    print_colored("\n" + "─" * 60, color)
    print_colored(str(msg).center(60), color)
    print_colored("─" * 60 + "\n", color)
    WriteToFile("\n" + "─" * 60)
    WriteToFile((msg).center(60))
    WriteToFile("─" * 60 + "\n")

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
    elif color == "purple":
        print(bcolors.purple + str(text) + bcolors.endc)
    elif color == 'bold':
        print(bcolors.bold + str(text) + bcolors.endc)
    elif color == 'underline':
        print(bcolors.underline + str(text) + bcolors.endc)
    elif color == 'no_new_line':
        print(str(text), end='')