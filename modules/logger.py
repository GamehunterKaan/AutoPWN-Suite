import logging
from os import get_terminal_size

from rich.logging import RichHandler
from rich.text import Text


def banner(msg, color, console) -> None:
    log = Logger()

    term_width, _ = get_terminal_size()

    console.print("─"*term_width, style=color)
    console.print(Text(msg), justify="center", style=color)
    console.print("─"*term_width, style=color)


class Logger:
    """
    Custom logger
    """

    def __init__(self) -> None:
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO,
            datefmt="[%X]",
            handlers=[RichHandler()]
        )

        RichHandler.KEYWORDS = [
                "[+]",
                "[-]",
                "[*]"
            ]

        self.log: object = logging.getLogger("rich")


    def logger(
            self,
            exception_: str,
            message: str,
        ) -> None:
        """
        * Log the proccesses with the passed message depending on the
        * exception_ variable

        @args
            exception_: str, determines what type of log level to use
                (1.) info
                (2.) error
                (3.) warning
                (4.) success
            message: str, message to be logged.

        ? Returns none.
        """

        if exception_ == "info":
            self.log.info(f"[+] {message}")
        elif exception_ == "error":
            self.log.error(f"[-] {message}")
        elif exception_ == "warning":
            self.log.warning(f"[*] {message}")
        elif exception_ == "success":
            self.log.info(f"[+] {message}")
