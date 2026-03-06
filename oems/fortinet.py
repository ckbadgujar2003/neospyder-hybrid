from .base import BaseOEM
from bs4 import BeautifulSoup
import requests, re
from logger import setup_logger

logger = setup_logger()

FORTINET_PSIRT_URL = "https://www.fortiguard.com/psirt"


class FortinetOEM(BaseOEM):

    def _get_field_value(self, soup: BeautifulSoup, label_text: str) -> str | None:
        """
        Fortinet renders fields in a table:
        <tr><td>Label</td><td>Value</td></tr>
        """
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) != 2:
                continue

            label = cols[0].get_text(" ", strip=True)
            if re.search(label_text, label, re.I):
                value = cols[1].get_text(" ", strip=True)
                return value

        return None


    # ---------------- STEP 1: GET LATEST URL ----------------
    def get_latest_advisory_url(self) -> str:
        logger.info("Opening Fortinet PSIRT listing page")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        r = requests.get(FORTINET_PSIRT_URL, headers=headers, timeout=20)
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "lxml")
        text = soup.get_text(" ", strip=True)

        ids = re.findall(r"FG-IR-\d{2}-\d{3}", text)
        if not ids:
            raise RuntimeError("No Fortinet advisory IDs found")

        advisory_id = ids[0]
        url = f"{FORTINET_PSIRT_URL}/{advisory_id}"

        logger.info(f"Latest Fortinet advisory URL: {url}")
        return url

    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        h1 = soup.find("h1")
        return h1.get_text(strip=True) if h1 else "Fortinet Security Advisory"

    def extract_advisory_id(self, soup: BeautifulSoup) -> str:
        text = soup.get_text(" ", strip=True)
        match = re.search(r"FG-IR-\d{2}-\d{3}", text)
        return match.group(0) if match else "Not available"

    def extract_first_published(self, soup: BeautifulSoup) -> str:
        value = self._get_field_value(soup, "Published Date")
        return value if value else "Not available"

    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        result = {"base": "Not available", "vector": "Not available"}

        score = self._get_field_value(soup, "CVSSv3 Score")
        if score:
            result["base"] = score

        # Fortinet rarely shows vector – keep as Not available
        return result


    def extract_severity(self, soup: BeautifulSoup) -> str:
        sev = self._get_field_value(soup, "Severity")
        if sev:
            m = re.search(r"(Critical|High|Medium|Low)", sev, re.I)
            if m:
                return m.group(1).capitalize()
        return "Not available"


    def extract_cves(self, soup: BeautifulSoup) -> list[str]:
        text = soup.get_text(" ", strip=True)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        return cves if cves else ["Not listed"]

    def extract_description(self, soup: BeautifulSoup) -> str:
        header = soup.find(string=re.compile("Summary", re.I))
        if header:
            p = header.find_next("p")
            if p:
                text = p.get_text(" ", strip=True)
                if len(text) > 40:
                    return text
        return "Not available"

    def extract_affected_products(self, soup: BeautifulSoup) -> list[str]:
        """
        Extract affected products from Fortinet Version/Affected/Solution table.
        A product is affected if ANY of its rows does NOT say 'Not affected'.
        """

        affected_products = set()

        # Find the table that has Version / Affected / Solution headers
        table = soup.find("table")
        if not table:
            return ["Not listed"]

        rows = table.find_all("tr")
        if len(rows) < 2:
            return ["Not listed"]

        for row in rows[1:]:  # skip header
            cols = [c.get_text(" ", strip=True) for c in row.find_all(["td", "th"])]
            if len(cols) < 3:
                continue

            version_col = cols[0]
            affected_col = cols[1]

            # Extract product name from "FortiOS 7.4" → "FortiOS"
            product_match = re.match(r"(Forti\w+)", version_col)
            if not product_match:
                continue

            product = product_match.group(1)

            # If affected column is NOT "Not affected", mark product affected
            if not re.search(r"Not affected", affected_col, re.I):
                affected_products.add(product)

        return sorted(affected_products) if affected_products else ["Not listed"]




    # ---------------- MAIN PARSER ----------------
    def parse_advisory(self) -> dict:
        url = self.get_latest_advisory_url()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "lxml")

        cvss = self.extract_cvss(soup)

        advisory = {
            "vendor": "Fortinet",
            "advisory_id": self.extract_advisory_id(soup),
            "title": self.extract_title(soup),
            "first_published": self.extract_first_published(soup),
            "cvss": cvss["base"],
            "vector": cvss["vector"],
            "severity": self.extract_severity(soup),
            "cves": self.extract_cves(soup),
            "description": self.extract_description(soup),
            "affected_products": self.extract_affected_products(soup),
            "source_url": url,
        }

        logger.info("Fortinet advisory parsed cleanly")
        return advisory
