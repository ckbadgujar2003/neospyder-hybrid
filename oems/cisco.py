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
#from config.settings import CHROMEDRIVER_LOC, CISCO_BASE_URL

logger = setup_logger()

class CiscoOEM(BaseOEM):
    # ---------------- UTILS ----------------
    def __init__(self, driver):
        self.driver = driver
    
    # ---------------- STEP 1: GET LATEST URL ----------------
    def get_latest_advisory_url(self, retries: int = 3, delay: int = 5) -> str:
        """Fetch the latest advisory URL via Selenium."""
        for attempt in range(1, retries + 1):
            driver = None
            try:
                logger.info(f"Opening Cisco advisory listing page, attempt {attempt}")
                driver = self.driver
                driver.get("https://sec.cloudapps.cisco.com/security/center/publicationListing.x")
    
                wait = WebDriverWait(driver, 20)
                link = wait.until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "table tbody tr td a"))
                )
                url = link.get_attribute("href")
                logger.info(f"Latest Cisco advisory URL: {url}")
                return url
    
            except Exception as e:
                logger.warning(f"Failed to fetch latest advisory URL: {e}, retrying in {delay}s")
                time.sleep(delay)
    
            finally:
                if driver:
                    pass
    
        raise RuntimeError("Unable to fetch latest Cisco advisory URL")
    
    
    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        """Fetch all h1 tags and join their text."""
        h1_tags = soup.find_all("h1")
        if h1_tags:
            return " | ".join(h.get_text(strip=True) for h in h1_tags)
        return "Cisco Security Advisory"
    
    
    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        """
        Extract full CVSS base score, vector, and severity.
        Returns dict: {"base": "10.0", "vector": "CVSS:3.1/AV:N/.../RC:X", "severity": "Critical"}
        """
        result = {"base": "Not available", "vector": "Not available", "severity": "Not available"}
    
        # ---- 1. Check hidden input for full CVSS ----
        hidden_input = soup.find("input", {"id": "hdncvssvector"})
        if hidden_input and hidden_input.get("value"):
            value = hidden_input["value"].strip()
            # Base score
            match_base = re.search(r"Base\s+([0-9.]+)", value)
            if match_base:
                result["base"] = match_base.group(1)
            # CVSS vector
            match_vector = re.search(r"(CVSS:[0-9.]+/[A-Z:NACPL/]+)", value)
            if match_vector:
                result["vector"] = match_vector.group(1)
    
        # ---- 2. Fallback: visible text nodes ----
        if result["base"] == "Not available" or result["vector"] == "Not available":
            text_nodes = soup.find_all(string=re.compile(r"CVSS|Base"))
            page_text = " ".join(node.strip() for node in text_nodes)
            if result["base"] == "Not available":
                match_base = re.search(r"Base\s+([0-9.]+)", page_text)
                if match_base:
                    result["base"] = match_base.group(1)
            if result["vector"] == "Not available":
                match_vector = re.search(r"(CVSS:[0-9./A-Z]+)", page_text)
                if match_vector:
                    result["vector"] = match_vector.group(1)
    
        # ---- 3. Severity ----
        text = soup.get_text(" ", strip=True)
        match_sev = re.search(r"Severity\s*[:\-]?\s*(\w+)", text, re.I)
        if match_sev:
            result["severity"] = match_sev.group(1)
        else:
            # Optional: derive severity from base score
            try:
                base_float = float(result["base"])
                if base_float >= 9.0:
                    result["severity"] = "Critical"
                elif base_float >= 7.0:
                    result["severity"] = "High"
                elif base_float >= 4.0:
                    result["severity"] = "Medium"
                else:
                    result["severity"] = "Low"
            except Exception:
                pass
        return result
    
    def extract_advisory_id(self, url: str) -> str:
        return url.rstrip("/").split("/")[-1]
    
    
    def extract_first_published(self, soup: BeautifulSoup) -> str:
        # primary selector
        label = soup.find(string=lambda s: s and "First Published" in s)
        if label:
            text = label.find_parent().get_text(" ", strip=True)
            match = re.search(r"(\d{4}-\d{2}-\d{2}|\d{4}\s+\w+\s+\d{1,2})", text)
            if match:
                return match.group(1)
    
        # fallback: search entire text
        text = soup.get_text(" ", strip=True)
        match = re.search(r"First Published[:\s]+(\d{4}-\d{2}-\d{2}|\d{4}\s+\w+\s+\d{1,2})", text)
        return match.group(1) if match else "Not available"
    
    
    
    def extract_cves(self, soup: BeautifulSoup) -> list[str]:
        text = soup.get_text(" ", strip=True)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        return cves if cves else ["Not listed"]
    
    
    def extract_description(self, soup: BeautifulSoup) -> str:
        # primary: summary paragraph
        summary = soup.find("h2", string=lambda s: s and s.strip().lower() == "summary")
        if summary:
            p = summary.find_next("p")
            if p:
                text = p.get_text(" ", strip=True)
                if len(text) > 30:
                    return text
    
        # fallback: first paragraph with enough length
        paragraphs = soup.find_all("p")
        for p in paragraphs:
            text = p.get_text(" ", strip=True)
            if len(text) > 30:
                return text
    
        return "Not available"
    
    
    def extract_affected_products(self, soup: BeautifulSoup) -> list[str]:
        """
        Extract affected products with multiple fallback strategies.
        Cisco advisories may present products in various formats:
        - Unordered lists
        - Tables
        - Paragraphs with product names
        """
        affected = []

        # Strategy 1: Look for "Vulnerable Products" or "Affected Products" header with <ul>
        for header_text in ["Vulnerable Products", "Affected Products", "Products Affected"]:
            header = soup.find("h2", string=lambda s: s and header_text in s)
            if header:
                # Check for unordered list
                ul = header.find_next("ul")
                if ul:
                    for li in ul.find_all("li"):
                        product = li.get_text(strip=True)
                        if product and len(product) > 3:  # filter out empty/invalid entries
                            affected.append(product)
                    if affected:
                        logger.info(f"Found {len(affected)} products via header+ul strategy")
                        return affected
                
                # Check for table after header
                table = header.find_next("table")
                if table:
                    for row in table.find_all("tr")[1:]:  # skip header row
                        cols = row.find_all("td")
                        if cols:
                            product = cols[0].get_text(strip=True)
                            if product and len(product) > 3:
                                affected.append(product)
                    if affected:
                        logger.info(f"Found {len(affected)} products via header+table strategy")
                        return affected

        # Strategy 2: Look for "Vulnerable Products" div or section
        vulnerable_section = soup.find(["div", "section"], 
                                       class_=lambda c: c and "vulnerable" in c.lower())
        if vulnerable_section:
            # Try <ul> in section
            ul = vulnerable_section.find("ul")
            if ul:
                for li in ul.find_all("li"):
                    product = li.get_text(strip=True)
                    if product and len(product) > 3:
                        affected.append(product)
            
            # Try table in section
            if not affected:
                table = vulnerable_section.find("table")
                if table:
                    for row in table.find_all("tr")[1:]:
                        cols = row.find_all("td")
                        if cols:
                            product = cols[0].get_text(strip=True)
                            if product and len(product) > 3:
                                affected.append(product)
            
            if affected:
                logger.info(f"Found {len(affected)} products via vulnerable section strategy")
                return affected

        # Strategy 3: Search all tables for product information
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            # Check if this looks like a product table
            if any(keyword in " ".join(headers) for keyword in ["product", "version", "release", "affected"]):
                for row in table.find_all("tr")[1:]:
                    cols = row.find_all("td")
                    if cols:
                        product = cols[0].get_text(strip=True)
                        # Filter out common non-product entries
                        if (product and 
                            len(product) > 3 and 
                            not product.lower().startswith(("yes", "no", "not", "n/a"))):
                            affected.append(product)
        
        if affected:
            # Remove duplicates while preserving order
            seen = set()
            unique_affected = []
            for product in affected:
                if product not in seen:
                    seen.add(product)
                    unique_affected.append(product)
            logger.info(f"Found {len(unique_affected)} products via table search strategy")
            return unique_affected

        # Strategy 4: Text-based extraction - look for common Cisco product patterns
        text = soup.get_text(" ", strip=True)
        
        # Common Cisco product patterns
        product_patterns = [
            r"Cisco\s+(?:Unified\s+)?(?:Communications\s+Manager|Webex|Unity\s+Connection|IP\s+Phone|Catalyst|Nexus|ASA|Firepower)[^\n.;]{0,50}",
            r"(?:Unified\s+CM|Unified\s+CM\s+SME|Unified\s+CM\s+IM&P)",
        ]
        
        for pattern in product_patterns:
            matches = re.findall(pattern, text, re.I)
            affected.extend([m.strip() for m in matches if len(m.strip()) > 5])
        
        if affected:
            # Remove duplicates and limit to reasonable entries
            seen = set()
            unique_affected = []
            for product in affected[:20]:  # limit to first 20 matches
                normalized = re.sub(r'\s+', ' ', product).strip()
                if normalized not in seen and len(normalized) > 5:
                    seen.add(normalized)
                    unique_affected.append(normalized)
            if unique_affected:
                logger.info(f"Found {len(unique_affected)} products via text pattern strategy")
                return unique_affected

        logger.warning("No affected products found - returning 'Not listed'")
        return ["Not listed"]
    
    
    # ---------------- MAIN PARSER ----------------
    def parse_advisory(self) -> dict:
        """
        Returns a CLEAN, SOC-ready Cisco advisory object.
        """
        url = self.get_latest_advisory_url()
    
        driver = self.driver
        driver.get(url)
        time.sleep(3)  # ensure JS content is loaded
        soup = BeautifulSoup(driver.page_source, "lxml")
    
        cvss = self.extract_cvss(soup)
        advisory = {
            "vendor": "Cisco",
            "advisory_id": self.extract_advisory_id(url),
            "title": self.extract_title(soup),
            "first_published": self.extract_first_published(soup),
            #"cvss": extract_cvss(soup),
            "cvss": cvss["base"],
            "vector": cvss["vector"],
            "severity": cvss["severity"],
            "cves": self.extract_cves(soup),
            "description": self.extract_description(soup),
            "affected_products": self.extract_affected_products(soup),
            "source_url": url,
        }
    
    
        logger.info("Cisco advisory parsed cleanly")
        return advisory