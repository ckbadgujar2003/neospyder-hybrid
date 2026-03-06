# utils/console.py

import os
import sys
from rich.console import Console


def _configure_environment():
    """
    Configure terminal environment safely.
    Handles Windows encoding + cross platform behavior.
    Runs once at import time.
    """

    # Force UTF-8 globally
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    # Windows UTF-8 console fix
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass


def create_console():
    """
    Create Rich console safely across versions.
    Avoids version-specific parameters like encoding=.
    """

    return Console(
        force_terminal=True,
        soft_wrap=True,
        legacy_windows=False
    )


# ---------- initialize automatically ----------
_configure_environment()

# global console instance (singleton)
console = create_console()