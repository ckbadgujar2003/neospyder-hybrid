from .base import BaseOEM
from bs4 import BeautifulSoup
from logger import setup_logger
import requests, re

logger = setup_logger()

CP_ARCHIVE = "https://advisories.checkpoint.com/advisories/"
CP_BASE = "https://advisories.checkpoint.com"


class CheckPointOEM(BaseOEM):

    # ---------------- PAGE FETCH ----------------
    def _fetch_page(self, url: str) -> BeautifulSoup:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        return BeautifulSoup(r.text, "lxml")

    # ---------------- STEP 1: GET LATEST ADVISORY URL ----------------
    def get_latest_advisory_url(self) -> str:
        soup = self._fetch_page(CP_ARCHIVE)

        table = soup.find("table")
        if not table:
            raise RuntimeError("Check Point advisory table not found")

        rows = table.find_all("tr")[1:]  # skip header
        if not rows:
            raise RuntimeError("No advisories found in table")

        latest_row = rows[0]  # top row = latest advisory

        link = latest_row.find("a", href=True)
        if not link:
            raise RuntimeError("Advisory link missing in table row")

        href = link["href"]

        # 🔥 Normalize full URL
        if not href.startswith("http"):
            href = CP_BASE + href

        logger.info(f"Latest Check Point advisory URL: {href}")
        return href

    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        h1 = soup.find("h1")
        return h1.get_text(strip=True) if h1 else "Check Point Security Advisory"

    def extract_advisory_id(self, url: str) -> str:
        return url.split("/")[-1].replace(".html", "")

    def extract_first_published(self, soup: BeautifulSoup) -> str:
        text = soup.get_text(" ", strip=True)
        m = re.search(r"(\d{1,2}\s+\w+\s+\d{4})", text)
        return m.group(1) if m else "Not available"

    def extract_cves(self, soup: BeautifulSoup) -> list[str]:
        text = soup.get_text(" ", strip=True)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        return cves if cves else ["Not listed"]

    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        result = {"base": "Not available", "vector": "Not available", "severity": "Not available"}

        text = soup.get_text(" ", strip=True)

        m_score = re.search(r"CVSS.*?([0-9]\.[0-9])", text)
        if m_score:
            result["base"] = m_score.group(1)

        m_vec = re.search(r"(CVSS:[0-9.]+/[A-Z:/\.]+)", text)
        if m_vec:
            result["vector"] = m_vec.group(1)

        m_sev = re.search(r"Severity[:\s]*(Critical|High|Medium|Low)", text, re.I)
        if m_sev:
            result["severity"] = m_sev.group(1).capitalize()

        return result

    def _get_field_by_label(self, soup: BeautifulSoup, label: str) -> str:
        rows = soup.find_all("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) < 2:
                continue

            key = cols[0].get_text(strip=True).lower()
            if label.lower() in key:
                return cols[1].get_text("\n", strip=True)

        return "Not available"

    def extract_description(self, soup: BeautifulSoup) -> str:
        desc = self._get_field_by_label(soup, "Vulnerability Description")
        return desc if desc else "Not available"

    def extract_affected_products(self, soup: BeautifulSoup) -> list[str]:
        vuln = self._get_field_by_label(soup, "Who is Vulnerable")
        if vuln == "Not available":
            return ["Not listed"]

        # Split lines properly
        products = [line.strip() for line in vuln.split("\n") if line.strip()]
        return products if products else ["Not listed"]




    # ---------------- MAIN PARSER ----------------
    def parse_advisory(self) -> dict:
        url = self.get_latest_advisory_url()
        soup = self._fetch_page(url)

        cvss = self.extract_cvss(soup)

        advisory = {
            "vendor": "Check Point",
            "advisory_id": self.extract_advisory_id(url),
            "title": self.extract_title(soup),
            "first_published": self.extract_first_published(soup),
            "cvss": cvss["base"],
            "vector": cvss["vector"],
            "severity": cvss["severity"],
            "cves": self.extract_cves(soup),
            "description": self.extract_description(soup),
            "affected_products": self.extract_affected_products(soup),
            "source_url": url,
        }

        logger.info("Check Point advisory parsed cleanly")
        return advisory
