import logging

from rich.logging import RichHandler
from rich.console import Console


def banner(msg, color):
    console = Console()

    console.print(
        f"[{color}]\n" + "─"*60
        + f"{msg}".center(60)
        + f"\n" + "─"*60 + +"[/{color}]"
    )


class Logger:
    """
    Custom logger
    """

    def __init__(self, filename_: str) -> None:
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO,
            datefmt="[%X]",
            handlers=[RichHandler()]
        )
        RichHandler.KEYWORDS = [
                "[+]",
                "[-]",
                "[*]",
            ]
        self.log: object = logging.getLogger("rich")
        file_log: object = logging.FileHandler(filename=filename_)

        file_log.setLevel(logging.INFO)
        file_log.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.log.addHandler(file_log)

    def logger(self, exception_: str, message: str) -> None:
        """
        * Log the proccesses with the passed message depending on the
        * exception_ variable

        ? Returns none.
        """

        # for major error that is not handled by exception
        match exception_:
            case "info":
                self.log.info(f"[+] {message}")
            case "error":
                self.log.warning(f"[-] {message}")
            case "warning":
                self.log.info(f"[*] {message}")
            case "success":
                self.log.info(f"[+] {message}")
