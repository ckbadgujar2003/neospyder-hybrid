from .base import BaseOEM
from bs4 import BeautifulSoup
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from logger import setup_logger
import re, time
#from config.settings import CHROMEDRIVER_LOC

logger = setup_logger()


class PaloAltoOEM(BaseOEM):

    # ---------------- UTILS ----------------

    def __init__(self, driver):
        self.driver = driver


    # ---------------- STEP 1: GET LATEST URL ----------------
    def get_latest_advisory_url(self) -> str:
        driver = self.driver
        try:
            logger.info("Opening Palo Alto advisory listing page")
            driver.get("https://security.paloaltonetworks.com/")

            WebDriverWait(driver, 60).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a[href^='/PAN-SA-']"))
            )

            links = driver.find_elements(By.CSS_SELECTOR, "a[href^='/PAN-SA-']")
            if not links:
                logger.warning("No advisory links found — trying alternative selector")
                links = driver.find_elements(By.CSS_SELECTOR, "div.listing a")

            href = links[0].get_attribute("href")
            if href.startswith("/"):
                href = "https://security.paloaltonetworks.com" + href

            logger.info(f"Latest Palo Alto advisory URL: {href}")
            return href
        finally:
            pass

    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        titles = []
        h1 = soup.find("h1")
        h2 = soup.find("h2")
        if h1: titles.append(h1.get_text(strip=True))
        if h2: titles.append(h2.get_text(strip=True))
        return " | ".join(titles) if titles else "Palo Alto Security Advisory"

    def extract_advisory_id(self, soup: BeautifulSoup) -> str:
        text = soup.get_text(" ", strip=True)
        match = re.search(r"PAN-SA-\d{4}-\d+", text)
        return match.group(0) if match else "Not available"

    def extract_first_published(self, soup: BeautifulSoup) -> str:
        # Try <time datetime=""> first
        time_tag = soup.find("time")
        if time_tag and time_tag.get("datetime"):
            return time_tag["datetime"].split("T")[0]

        # Fallback to regex search in text
        text = soup.get_text(" ", strip=True)
        match = re.search(r"Published[:\s]*(\d{4}-\d{2}-\d{2})", text, re.I)
        if match: return match.group(1)
        return "Not available"

    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        """
        Extract CVSS vector and base score if present in text.
        """
        result = {"base": "Not available", "vector": "Not available"}
        text = soup.get_text(" ", strip=True)

        # Find CVSS vector in text
        match_vector = re.search(r"(CVSS:[0-9.]+/[A-Z:/.]+)", text)
        if match_vector:
            vector = match_vector.group(1)
            result["vector"] = vector

            # Try to extract approximate CVSS base score from vector (CVSS-BT or CVSS-B)
            match_base = re.search(r"CVSS-BT[:\s]*([0-9.]+)|CVSS-B[:\s]*([0-9.]+)", text)
            if match_base:
                result["base"] = match_base.group(1) if match_base.group(1) else match_base.group(2)

        return result

    def extract_severity(self, soup: BeautifulSoup) -> str:
        """
        Extract vendor-assigned severity. Fallback: CVSS-based estimate.
        """
        text = soup.get_text(" ", strip=True)

        # Vendor severity (Product Status section)
        match_vendor = re.search(
            r"Severity\s*[:\-]?\s*(Critical|High|Medium|Low|Info|LOW|MEDIUM|HIGH|CRITICAL)",
            text, re.I
        )
        if match_vendor:
            return match_vendor.group(1).capitalize()

        # Fallback: estimate severity from CVSS base
        cvss_data = self.extract_cvss(soup)
        try:
            base = float(cvss_data["base"])
            if base >= 9.0: return "Critical"
            elif base >= 7.0: return "High"
            elif base >= 4.0: return "Medium"
            else: return "Low"
        except Exception:
            return "Not available"

    def extract_cves(self, soup: BeautifulSoup) -> list[str]:
        text = soup.get_text(" ", strip=True)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        return cves if cves else ["Not listed"]

    def extract_description(self, soup: BeautifulSoup) -> str:
        """
        Extract description, including hidden/collapsible content.
        """
        # Overview / Description headers
        for header in ["Overview", "Description"]:
            h = soup.find("h3", string=re.compile(header, re.I))
            if h:
                p = h.find_next(["p", "div", "li"])
                if p:
                    text = p.get_text(" ", strip=True)
                    if len(text) > 30:
                        return text

        # Hidden sections
        for d in soup.find_all(["details", "div"], class_=re.compile("collapse|accordion", re.I)):
            text = d.get_text(" ", strip=True)
            if len(text) > 30:
                return text

        # Fallback
        for p in soup.find_all("p"):
            text = p.get_text(" ", strip=True)
            if len(text) > 40:
                return text

        return "Not available"

    def extract_affected_products(self, soup: BeautifulSoup) -> dict:
        """
        Extract affected products along with affected/unaffected versions.
        Returns structured dict:
        {
            "Prisma Browser": {"affected": ["< 142.15.2.60"], "unaffected": [">= 142.15.6.60"]},
            ...
        }
        """
    
        affected_products = {}
    
        # Look for all tables with Versions / Affected / Unaffected headers
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            if not all(x in headers for x in ["versions", "affected", "unaffected"]):
                continue  # skip irrelevant tables
    
            for row in table.find_all("tr")[1:]:  # skip header
                cols = [c.get_text(" ", strip=True).replace("\xa0", " ") for c in row.find_all("td")]
                if len(cols) < 3:
                    continue
    
                product = cols[0]
                affected = [cols[1]] if cols[1] else []
                unaffected = [cols[2]] if cols[2] else []
    
                # Decode HTML entities
                affected = [re.sub(r"&lt;", "<", a) for a in affected]
                affected = [re.sub(r"&gt;", ">", a) for a in affected]
                unaffected = [re.sub(r"&lt;", "<", u) for u in unaffected]
                unaffected = [re.sub(r"&gt;", ">", u) for u in unaffected]
    
                if product in affected_products:
                    affected_products[product]["affected"].extend(affected)
                    affected_products[product]["unaffected"].extend(unaffected)
                else:
                    affected_products[product] = {"affected": affected, "unaffected": unaffected}
    
        # Fallback: if no tables found, check text for product mentions
        if not affected_products:
            text = soup.get_text(" ", strip=True)
            for prod in ["Prisma Browser", "Chromium", "Cortex XDR", "PAN-OS"]:
                if prod.lower() in text.lower():
                    affected_products[prod] = {"affected": [], "unaffected": []}
    
        return affected_products if affected_products else {"Not listed": {"affected": [], "unaffected": []}}



    # ---------------- MAIN PARSER ----------------
    def parse_advisory(self) -> dict:
        url = self.get_latest_advisory_url()
        driver = self.driver
        driver.get(url)
        time.sleep(3)
        soup = BeautifulSoup(driver.page_source, "lxml")

        cvss = self.extract_cvss(soup)
        severity = self.extract_severity(soup)

        advisory = {
            "vendor": "Palo Alto",
            "advisory_id": self.extract_advisory_id(soup),
            "title": self.extract_title(soup),
            "first_published": self.extract_first_published(soup),
            "cvss": cvss["base"],
            "vector": cvss["vector"],
            "severity": severity,
            "cves": self.extract_cves(soup),
            "description": self.extract_description(soup),
            "affected_products": self.extract_affected_products(soup),
            "source_url": url,
        }

        logger.info("Palo Alto advisory parsed cleanly")
        return advisory
