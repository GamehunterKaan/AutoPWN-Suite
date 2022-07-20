from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from modules.utils import get_terminal_width


# https://patorjk.com/software/taag/
def print_banner(console) -> None:
    width = get_terminal_width()
    height = 8
    banner = """\
___           __          ____  _       __ _   __   _____         _  __
    /   |  __  __ / /_ ____   / __ \| |     / // | / /  / ___/ __  __ (_)/ /_ ___
   / /| | / / / // __// __ \ / /_/ /| | /| / //  |/ /   \__ \ / / / // // __// _ \\
  / ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ // /|  /   ___/ // /_/ // // /_ /  __/
 /_/  |_|\____/ \__/ \____//_/      |__/|__//_/ |_/   /____/ \____//_/ \__/ \___/
"""

    banner_small = """\
╔═╗┬ ┬┌┬┐┌─┐╔═╗╦ ╦╔╗╔  ╔═╗┬ ┬┬┌┬┐┌─┐
╠═╣│ │ │ │ │╠═╝║║║║║║  ╚═╗│ ││ │ ├┤ 
╩ ╩└─┘ ┴ └─┘╩  ╚╩╝╝╚╝  ╚═╝└─┘┴ ┴ └─┘
"""

    if width < 90:
        banner = banner_small
        height = 5

    panel = Panel(
        Align(
            Text(banner, justify="center", style="blue"),
            vertical="middle",
            align="center",
        ),
        width=width,
        height=height,
        subtitle="by GamehunterKaan (https://auto.pwnspot.com)",
    )
    console.print(panel)
