# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import logging

from rich.logging import RichHandler
from rich.markup import escape
from rich.text import Text

from autopwn_suite.utils import get_terminal_width
from autopwn_suite.web.findings import printable


def banner(msg, color, console) -> None:
    term_width = get_terminal_width()

    console.print("─" * term_width, style=color)
    console.print(Text(printable(msg)), justify="center", style=color)
    console.print("─" * term_width, style=color)


def markup_safe(value) -> str:
    """Escape target, NVD or Exploit-DB text so Rich prints it literally instead of parsing markup."""
    return escape(str(value))


def console_safe(value) -> str:
    """Text that a scanned host, the NVD, Exploit-DB or a copied database controls, ready for `console.print` or a
    table cell: one line without control or layout characters (`printable`) and without Rich markup. The cleaning
    comes first, because a control character inside "[/red]" must not be removed after the escaping."""
    return markup_safe(printable(str(value)))


class Logger:
    """
    Custom logger
    """

    def __init__(self, console) -> None:
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO,
            datefmt="[%X]",
            handlers=[RichHandler(console=console)],
        )

        RichHandler.KEYWORDS = ["[+]", "[-]", "[*]"]

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

        # Last line of defence: a message can quote text a host or a provider controls. Our own messages may span
        # lines, so a newline stays; the sources clean that text to one line before it is quoted here.
        message = printable(str(message), multiline=True)
        if exception_ == "info":
            self.log.info(f"[+] {message}")
        elif exception_ == "error":
            self.log.error(f"[-] {message}")
        elif exception_ == "warning":
            self.log.warning(f"[*] {message}")
        elif exception_ == "success":
            self.log.info(f"[+] {message}")
