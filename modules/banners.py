from modules.logger import println, colors, warning, info

# https://patorjk.com/software/taag/
def print_banner():
    banner = """\033[0m│        \033[94m___           __          ____  _       __ _   __   _____         _  __\033[0m         │
│       \033[94m/   |  __  __ / /_ ____   / __ \| |     / // | / /  / ___/ __  __ (_)/ /_ ___\033[0m    │
│      \033[94m/ /| | / / / // __// __ \ / /_/ /| | /| / //  |/ /   \__ \ / / / // // __// _ \\\033[0m   │ 
│     \033[94m/ ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ // /|  /   ___/ // /_/ // // /_ /  __/\033[0m   │
│    \033[94m/_/  |_|\__,_/ \__/ \____//_/      |__/|__//_/ |_/   /____/ \__,_//_/ \__/ \___/\033[0m    │
│                                                                                        │"""

    print()
    info("Developed by GamehunterKaan. (https://auto.pwnspot.com)")
    println("\n" + "┌" + "─" * 88 + "┐")
    println(banner.center(90))
    println("└" + "─" * 88 + "┘" + "\n")
    warning("I am not responsible if you are doing something illegal using this program! \n")