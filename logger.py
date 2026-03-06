import logging
import sys

from rich.logging import RichHandler
from utils.console import console



# ---------- ANSI COLORS ----------
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ORANGE = "\033[38;5;208m"
RED = "\033[91m"
BLUE = "\033[94m"


class NeoSpyderFormatter(logging.Formatter):
    """
    Custom formatter with:
    - Green -> email success
    - Yellow -> INFO
    - Orange -> WARNING
    - Red -> ERROR/CRITICAL
    - Blue -> everything else
    """

    def format(self, record):
        message = super().format(record)

        # --- Custom rule: email success always green ---
        if "email sent" in record.getMessage().lower():
            return f"{GREEN}{message}{RESET}"

        # --- Level based coloring ---
        if record.levelno == logging.INFO:
            return f"{YELLOW}{message}{RESET}"

        elif record.levelno == logging.WARNING:
            return f"{ORANGE}{message}{RESET}"

        elif record.levelno in (logging.ERROR, logging.CRITICAL):
            return f"{RED}{message}{RESET}"

        else:
            return f"{BLUE}{message}{RESET}"



def setup_logger():
    logger = logging.getLogger("NeoSpyder")

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_time=True,
        show_path=False
    )

    formatter = logging.Formatter(
        "%(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger