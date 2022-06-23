from platform import system as system_name


def InitializeLogger(context):
    global outfile
    outfile = context
    with open(outfile, "w", encoding="utf-8") as file:
        file.close()


# https://stackoverflow.com/a/287944
class bcolors:
    header = "\033[95m"
    blue = "\033[94m"
    cyan = "\033[96m"
    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    purple = "\033[38;5;93m"
    endc = "\033[0m"
    bold = "\033[1m"
    underline = "\033[4m"


class colors:
    blue = "blue"
    cyan = "cyan"
    green = "green"
    yellow = "yellow"
    red = "red"
    purple = "purple"
    bold = "bold"
    underline = "underline"
    no_new_line = "no_new_line"
    endc = "endc"


def WriteToFile(data):
    colors = [
            bcolors.blue,
            bcolors.red,
            bcolors.yellow,
            bcolors.green,
            bcolors.cyan,
            bcolors.endc,
            bcolors.bold,
            bcolors.underline
        ]

    for colorcode in colors:
        data = data.replace(colorcode, "")

    filename = outfile
    with open(filename, "ab", encoding="utf-8") as file:
        if system_name() == "Windows":
            file.write(b"\n" + bytes(data))
        else:
            file.write(f"\n{data}")


def info(msg):
    print(f"{bcolors.blue}[+] {bcolors.endc} {msg}")
    WriteToFile(f"[+] {msg}")


def error(msg):
    print(f"{bcolors.blue}[-] {bcolors.endc} {msg}")
    WriteToFile(f"[-] {msg}")


def warning(msg):
    print(f"{bcolors.blue}[*] {bcolors.endc} {msg}")
    WriteToFile(f"[*] {msg}")


def success(msg):
    print(f"{bcolors.blue}[+] {bcolors.endc} {msg}")
    WriteToFile(f"[+] {msg}")


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
    if color == "blue":
        print(f"{bcolors.blue} {text} {bcolors.endc}")
    elif color == "cyan":
        print(f"{bcolors.cyan} {text} {bcolors.endc}")
    elif color == "green":
        print(f"{bcolors.green} {text} {bcolors.endc}")
    elif color == "yellow":
        print(f"{bcolors.yellow} {text} {bcolors.endc}")
    elif color == "red":
        print(f"{bcolors.red} {text} {bcolors.endc}")
    elif color == "purple":
        print(f"{bcolors.purple} {text} {bcolors.endc}")
    elif color == "bold":
        print(f"{bcolors.bold} {text} {bcolors.endc}")
    elif color == "underline":
        print(f"{bcolors.underline} {text} {bcolors.endc}")
    elif color == "no_new_line":
        print(text, end="")
