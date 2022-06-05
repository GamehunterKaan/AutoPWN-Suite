from modules.color import print_colored, colors

#https://patorjk.com/software/taag/
def print_banner():
    banner = """\033[0m│        \033[94m___           __          ____  _       __ _   __   _____         _  __\033[0m         │
│       \033[94m/   |  __  __ / /_ ____   / __ \| |     / // | / /  / ___/ __  __ (_)/ /_ ___\033[0m    │
│      \033[94m/ /| | / / / // __// __ \ / /_/ /| | /| / //  |/ /   \__ \ / / / // // __// _ \\\033[0m   │ 
│     \033[94m/ ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ // /|  /   ___/ // /_/ // // /_ /  __/\033[0m   │
│    \033[94m/_/  |_|\__,_/ \__/ \____//_/      |__/|__//_/ |_/   /____/ \__,_//_/ \__/ \___/\033[0m    │
│                                                                                        │"""

    print_colored("\nDeveloped by GamehunterKaan. (https://auto.pwnspot.com)", colors.bold)
    print_colored("\n" + "┌" + "─" * 88 + "┐", colors.bold)
    print_colored(banner.center(90), colors.blue)
    print_colored("└" + "─" * 88 + "┘" + "\n", colors.bold)
    print_colored("I am not responsible if you are doing something illegal using this program! \n", colors.bold)
