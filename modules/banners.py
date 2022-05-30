from modules.color import print_colored, colors

#https://patorjk.com/software/taag/
def print_banner():
    banner = """

        ___           __          ____  _       __ _   __   _____         _  __      
       /   |  __  __ / /_ ____   / __ \| |     / // | / /  / ___/ __  __ (_)/ /_ ___ 
      / /| | / / / // __// __ \ / /_/ /| | /| / //  |/ /   \__ \ / / / // // __// _ \\
     / ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ // /|  /   ___/ // /_/ // // /_ /  __/
    /_/  |_|\__,_/ \__/ \____//_/      |__/|__//_/ |_/   /____/ \__,_//_/ \__/ \___/ 

"""

    print_colored("\nDeveloped by GamehunterKaan. (https://auto.pwnspot.com)", colors.bold)
    print_colored("\n" + "-" * 90, colors.bold)
    print_colored(banner, colors.blue)
    print_colored("-" * 90 + "\n", colors.bold)
    print_colored("I am not responsible if you are doing something illegal using this program! \n", colors.bold)
