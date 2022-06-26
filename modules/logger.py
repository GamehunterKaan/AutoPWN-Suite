import logging
from os import get_terminal_size

from rich.logging import RichHandler
from rich.console import Console
from rich.text import Text


def banner(msg, color):
    console = Console()
    log = Logger()

    term_width, _ = get_terminal_size()

    console.print("─"*term_width, style=color)
    console.print(Text(msg, justify="center"), style=color)
    console.print("─"*term_width, style=color)
    log.logger("info", msg)


class Logger:
    """
    Custom logger
    """

    def __init__(self, filename: str = None) -> None:
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

        file_log: object = logging.FileHandler(filename="output.log")
        if filename is not None:
            file_log: object = logging.FileHandler(filename="autopwn.log")

        file_log.setLevel(logging.INFO)
        file_log.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.log.addHandler(file_log)

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
            self.log.warning(f"[-] {message}")
        elif exception_ == "warning":
            self.log.info(f"[*] {message}")
        elif exception_ == "success":
            self.log.info(f"[+] {message}")
