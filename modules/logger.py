import logging
from os import get_terminal_size

from rich.logging import RichHandler
from rich.console import Console
from rich.text import Text


def banner(msg, color):
    console = Console()
    log = Logger()

    term_width, _ = get_terminal_size()

    console.print("-"*term_width, style=color)
    console.print(Text(msg, justify="center"), style=color)
    console.print("-"*term_width, style=color)
    log.logger("info", msg, stream_=False)


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
        file_log: object = logging.FileHandler(filename="output.log")

        file_log.setLevel(logging.INFO)
        file_log.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.log.addHandler(file_log)

    def logger(
            self,
            exception_: str,
            message: str,
            stream_: bool = True
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

        self.stream_to_console(exception_, message, stream_)

    def stream_to_console(
            self,
            exception_: str,
            message: str,
            stream_: bool
        ) -> None:
        """
        * Steam the output to console.

        ? Returns none.
        """

        console = Console()

        if stream_:
            if exception_ == "info":
                console.print(f"[+] {message}", style="blue")
            elif exception_ == "error":
                console.print(f"[+] {message}", style="red")
            elif exception_ == "warning":
                console.print(f"[+] {message}", style="red")
            elif exception_ == "success":
                console.print(f"[+] {message}", style="green")
