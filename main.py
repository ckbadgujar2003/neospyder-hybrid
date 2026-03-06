import sys
import os

# --- FORCE UTF-8 OUTPUT (Windows fix) - MUST BE FIRST ---
if os.name == "nt":
    os.environ["PYTHONUTF8"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except:
        pass

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from contextlib import contextmanager
import logging

from rich.live import Live
from rich.table import Table
from rich import box
from rich.console import Group
from rich.panel import Panel

from utils.network_diagnostics import NetworkDiagnostics
from utils.driver_factory import get_driver
from utils.console import console

# =====================================================
# CUSTOM LOGGER THAT CAPTURES TO BOX
# =====================================================

class LogCapture(logging.Handler):
    """Custom handler that captures logs for display"""
    def __init__(self):
        super().__init__()
        self.messages = []
        self.max_messages = 20  # Show last 20 log messages
        
    def emit(self, record):
        try:
            msg = self.format(record)
            timestamp = time.strftime("%H:%M:%S", time.localtime(record.created))
            
            # Color based on level
            if record.levelname == "ERROR":
                formatted = f"[red]{timestamp} ERROR[/red] {msg}"
            elif record.levelname == "WARNING":
                formatted = f"[yellow]{timestamp} WARN[/yellow] {msg}"
            elif "email sent successfully" in msg.lower():
                formatted = f"[green]{timestamp} INFO[/green] {msg}"
            else:
                formatted = f"[cyan]{timestamp} INFO[/cyan] {msg}"
            
            self.messages.append(formatted)
            if len(self.messages) > self.max_messages:
                self.messages.pop(0)
        except Exception:
            pass

# Create log capture
log_capture = LogCapture()

# Setup logger
logger = logging.getLogger("NeoSpyder")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    log_capture.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(log_capture)


# =====================================================
# GLOBAL STATE
# =====================================================

status_lock = Lock()

vendor_status = {}
vendor_done = {}

THREAD_VENDORS = {}
ASYNC_VENDORS = {}
ALL_VENDORS = {}


# =====================================================
# LAZY VENDOR LOADER (STARTUP OPTIMIZATION)
# =====================================================

def load_vendor_classes():
    """
    Lazy load vendor classes only when needed.
    Prevents heavy imports at startup.
    Improves boot speed and memory usage.
    """

    global THREAD_VENDORS, ASYNC_VENDORS, ALL_VENDORS

    # Selenium / threaded vendors
    from oems.cisco import CiscoOEM
    from oems.paloalto import PaloAltoOEM

    # HTTP / async vendors
    from oems.fortinet import FortinetOEM
    from oems.checkpoint import CheckPointOEM
    from oems.trendmicro import TrendMicroOEM
    from oems.sentinelone import SentinelOneOEM

    THREAD_VENDORS = {
        "cisco": CiscoOEM,
        "paloalto": PaloAltoOEM,
    }

    ASYNC_VENDORS = {
        "fortinet": FortinetOEM,
        "checkpoint": CheckPointOEM,
        "trendmicro": TrendMicroOEM,
        "sentinelone": SentinelOneOEM
    }

    ALL_VENDORS = {**THREAD_VENDORS, **ASYNC_VENDORS}


# =====================================================
# STDOUT SUPPRESSION (selenium spam fix)
# =====================================================

@contextmanager
def suppress_stdout():
    """Suppress ONLY stdout (selenium noise) without breaking Rich logging."""
    old_stdout = sys.stdout

    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
        yield
    finally:
        sys.stdout.close()
        sys.stdout = old_stdout


# =====================================================
# DISPLAY BUILDER
# =====================================================

def build_display():
    """Build logs panel + status dashboard"""
    
    # Build logs panel
    if log_capture.messages:
        logs_text = "\n".join(log_capture.messages)
    else:
        logs_text = "[dim]Waiting for activity...[/dim]"
    
    logs_panel = Panel(
        logs_text,
        title="[bold yellow]Activity Log[/bold yellow]",
        border_style="yellow",
        padding=(0, 1),
        height=24  # Fixed height for scrolling effect
    )
    
    # Build status table
    table = Table(
        title="[bold cyan]NeoSpyder SOC Dashboard[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        title_justify="center"
    )

    table.add_column("Vendor", style="bold white", width=15)
    table.add_column("Status", justify="left", width=50)

    with status_lock:
        for vendor, status in vendor_status.items():
            vendor_name = vendor.capitalize()

            if not vendor_done[vendor]:
                status_render = f"[yellow]{status}[/yellow]"
            else:
                if "sent" in status.lower():
                    status_render = f"[green]{status}[/green]"
                elif "error" in status.lower() or "failed" in status.lower():
                    status_render = f"[red]{status}[/red]"
                else:
                    status_render = status

            table.add_row(vendor_name, status_render)

    # Combine logs and dashboard
    return Group(logs_panel, table)


def update_status(name, text):
    with status_lock:
        vendor_status[name] = text


def mark_done(name, text):
    with status_lock:
        vendor_status[name] = text
        vendor_done[name] = True


# =====================================================
# THREAD WORKER (Selenium vendors)
# =====================================================

def run_thread_vendor(name, scraper_class, loop):

    driver = None

    try:
        update_status(name, "Launching browser...")

        with suppress_stdout():
            driver = get_driver()

        update_status(name, "Fetching advisory...")

        scraper = scraper_class(driver)
        data = scraper.parse_advisory()

        update_status(name, "Sending email...")
        
        from notifier.emailer import format_email, send_email
        msg = format_email(data)
        send_email(msg, vendor=name)

        mark_done(name, "Email sent")

    except Exception as e:
        logger.error(f"{name} error: {str(e)}")
        error_msg = str(e).encode("ascii", "ignore").decode()
        mark_done(name, f"Error: {error_msg[:35]}")

    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass


# =====================================================
# ASYNC WORKER (HTTP vendors)
# =====================================================

async def run_async_vendor(name, scraper_class):

    try:
        update_status(name, "Fetching advisory...")

        scraper = scraper_class()
        data = await asyncio.to_thread(scraper.parse_advisory)

        update_status(name, "Sending email...")
        
        from notifier.emailer import format_email, send_email
        msg = format_email(data)
        await asyncio.to_thread(send_email, msg, name)

        mark_done(name, "Email sent")

    except Exception as e:
        logger.error(f"{name} error: {str(e)}")
        error_msg = str(e).encode("ascii", "ignore").decode()
        mark_done(name, f"Error: {error_msg[:35]}")


# =====================================================
# THREAD ENGINE
# =====================================================

async def run_thread_engine():

    loop = asyncio.get_running_loop()

    with ThreadPoolExecutor(max_workers=len(THREAD_VENDORS)) as executor:
        tasks = [
            loop.run_in_executor(
                executor,
                run_thread_vendor,
                name,
                cls,
                loop
            )
            for name, cls in THREAD_VENDORS.items()
        ]

        await asyncio.gather(*tasks)


# =====================================================
# ASYNC ENGINE
# =====================================================

async def run_async_engine():

    tasks = [
        run_async_vendor(name, cls)
        for name, cls in ASYNC_VENDORS.items()
    ]

    await asyncio.gather(*tasks)


# =====================================================
# MAIN ORCHESTRATOR
# =====================================================

async def main():

    console.print("\n[bold cyan]NeoSpyder Hybrid Engine Starting[/bold cyan]\n")

    # ---------- lazy load vendors ----------
    load_vendor_classes()

    # ---------- network diagnostics ----------
    NetworkDiagnostics().run()

    # ---------- initialize state ----------
    for vendor in ALL_VENDORS:
        vendor_status[vendor] = "Waiting..."
        vendor_done[vendor] = False

    console.print("\n")

    # ✅ Use Live display with proper configuration
    with Live(
        build_display(),
        console=console,
        refresh_per_second=4,
        screen=False,
        transient=False
    ) as live:

        # Background task to update display
        async def update_display():
            while True:
                live.update(build_display())
                await asyncio.sleep(0.25)

        # Start display updater
        display_task = asyncio.create_task(update_display())

        try:
            # Run scrapers
            await asyncio.gather(
                run_thread_engine(),
                run_async_engine()
            )
        finally:
            # Cancel display updater
            display_task.cancel()
            try:
                await display_task
            except asyncio.CancelledError:
                pass
            
            # Final update
            live.update(build_display())

    # Print completion message
    console.print("\n[bold green]✓ NeoSpyder run completed[/bold green]\n")


# =====================================================
# ENTRY
# =====================================================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]\n")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]\n")
        import traceback
        traceback.print_exc()