import socket
import requests
import time
from rich.table import Table
from rich import box
from utils.console import console


class NetworkDiagnostics:
    def __init__(self):
        # Add vendors here anytime
        self.targets = {
            "Internet": "https://www.google.com",
            "Cisco": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
            "PaloAlto": "https://security.paloaltonetworks.com/",
            "Fortinet": "https://www.fortiguard.com/psirt",
            "CheckPoint": "https://advisories.checkpoint.com/advisories/",
            "TrendMicro": "https://www.zerodayinitiative.com/advisories/published/",
            "SentinelOne": "https://www.sentinelone.com/vulnerability-database/"
        }

    # ----------------------------
    # DNS CHECK
    # ----------------------------
    def check_dns(self, url):
        try:
            domain = url.split("//")[1].split("/")[0]
            socket.gethostbyname(domain)
            return True, "DNS OK"
        except Exception:
            return False, "DNS Failed"

    # ----------------------------
    # HTTP CHECK
    # ----------------------------
    def check_http(self, url, timeout=10):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code < 400:
                return True, f"HTTP {r.status_code}"
            return False, f"HTTP {r.status_code}"
        except requests.exceptions.Timeout:
            return False, "Timeout"
        except requests.exceptions.ConnectionError:
            return False, "Connection Failed"
        except Exception as e:
            return False, str(e)

    # ----------------------------
    # RUN DIAGNOSTICS
    # ----------------------------
    def run(self):
        console.print("\n[bold cyan]Running NeoSpyder Network Diagnostics[/bold cyan]\n")

        table = Table(
            title="Network Health Check",
            box=box.ROUNDED,
            title_justify="center"
        )
        table.add_column("Service", style="cyan")
        table.add_column("DNS", justify="center")
        table.add_column("HTTP", justify="center")
        table.add_column("Status", justify="center")

        overall_ok = True

        for name, url in self.targets.items():
            dns_ok, dns_msg = self.check_dns(url)

            if dns_ok:
                http_ok, http_msg = self.check_http(url)
            else:
                http_ok, http_msg = False, "-"

            if dns_ok and http_ok:
                status = "[green]✓ Ready[/green]"
            else:
                status = "[red]✗ Problem[/red]"
                overall_ok = False

            table.add_row(
                name,
                f"[green]{dns_msg}[/green]" if dns_ok else f"[red]{dns_msg}[/red]",
                f"[green]{http_msg}[/green]" if http_ok else f"[red]{http_msg}[/red]",
                status
            )

            time.sleep(0.3)  # small delay for nice UX

        console.print(table)

        if not overall_ok:
            console.print(
                "\n[bold yellow]Warning: Some vendor portals are unreachable."
                " Scrapers may fail.[/bold yellow]\n"
            )
        else:
            console.print("\n[bold green]✓ All network checks passed[/bold green]\n")

        return overall_ok