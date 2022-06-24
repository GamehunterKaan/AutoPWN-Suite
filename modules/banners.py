from os import get_terminal_size

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align


# https://patorjk.com/software/taag/
def print_banner():
    console = Console()

    banner = """\
    ___           __          ____  _       __ _   __   _____         _  __
        /   |  __  __ / /_ ____   / __ \| |     / // | / /  / ___/ __  __ (_)/ /_ ___
       / /| | / / / // __// __ \ / /_/ /| | /| / //  |/ /   \__ \ / / / // // __// _ \\
      / ___ |/ /_/ // /_ / /_/ // ____/ | |/ |/ // /|  /   ___/ // /_/ // // /_ /  __/
     /_/  |_|\__,_/ \__/ \____//_/      |__/|__//_/ |_/   /____/ \__,_//_/ \__/ \___/
    """
    width, _ = get_terminal_size()


    panel = Panel(
        Align(
            Text(
                banner,
                justify="center",
                style="blue"
            ),
            vertical="middle", align="center"
        ),
        width=width, height=8
    )
    console.print(
        "[blue]Developed by GamehunterKaan. (https://auto.pwnspot.com)[/blue]"
    )
    console.print(panel)
    console.print(
        "I am not responsible if you are doing something"
        + " illegal using this program!", style="red"
    )
