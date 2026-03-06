from .base import BaseOEM
from bs4 import BeautifulSoup
from logger import setup_logger
import requests, re
from datetime import datetime

logger = setup_logger()

# SentinelOne tracks CVEs in their vulnerability database
S1_VULN_DB = "https://www.sentinelone.com/vulnerability-database/"
S1_BASE = "https://www.sentinelone.com"


class SentinelOneOEM(BaseOEM):

    # ---------------- PAGE FETCH ----------------
    def _fetch_page(self, url: str) -> BeautifulSoup:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        return BeautifulSoup(r.text, "lxml")

    # ---------------- STEP 1: GET LATEST ADVISORY URL ----------------
    def get_latest_advisory_url(self) -> str:
        """
        Get the latest CVE from SentinelOne's vulnerability database.
        The database lists CVEs - we'll get the most recent one.
        """
        soup = self._fetch_page(S1_VULN_DB)

        # Look for CVE links in the vulnerability database
        # Format: /vulnerability-database/cve-YYYY-NNNNN/
        cve_links = soup.find_all("a", href=re.compile(r"/vulnerability-database/cve-\d{4}-\d+", re.I))
        
        if not cve_links:
            raise RuntimeError("No CVE links found in SentinelOne vulnerability database")
        
        # Get first CVE link (should be most recent)
        first_link = cve_links[0]
        href = first_link.get("href")
        
        # Build full URL
        if not href.startswith("http"):
            href = S1_BASE + href
        
        # Extract CVE ID from URL
        cve_match = re.search(r"(cve-\d{4}-\d+)", href, re.I)
        cve_id = cve_match.group(1).upper() if cve_match else "Unknown"
        
        logger.info(f"Latest SentinelOne tracked CVE: {cve_id}")
        logger.info(f"URL: {href}")
        
        return href

    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        # Look for h1
        h1 = soup.find("h1")
        if h1:
            return h1.get_text(strip=True)
        
        # Fallback to title tag
        title = soup.find("title")
        if title:
            title_text = title.get_text(strip=True)
            # Remove " | SentinelOne" suffix
            return title_text.split("|")[0].strip()
        
        return "SentinelOne CVE Advisory"

    def extract_advisory_id(self, url: str) -> str:
        # Extract CVE-YYYY-NNNNN from URL
        match = re.search(r"(CVE-\d{4}-\d+)", url, re.I)
        if match:
            return match.group(1).upper()
        return "Not available"

    def extract_first_published(self, soup: BeautifulSoup) -> str:
        # SentinelOne pages may have publication dates in various formats
        text = soup.get_text(" ", strip=True)
        
        # Look for "Published:" or similar patterns
        match = re.search(r"Published[:\s]*(\w+\s+\d{1,2},\s+\d{4})", text, re.I)
        if match:
            return match.group(1)
        
        # Look for date patterns
        match = re.search(r"(\w+\s+\d{1,2},\s+\d{4})", text)
        if match:
            return match.group(1)
        
        match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if match:
            return match.group(1)
        
        return "Not available"

    def extract_cves(self, url: str, soup: BeautifulSoup) -> list[str]:
        # Primary: Extract from URL
        cve = self.extract_advisory_id(url)
        if cve != "Not available":
            return [cve]
        
        # Fallback: Extract from page
        text = soup.get_text(" ", strip=True)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        return cves if cves else ["Not listed"]

    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        result = {
            "base": "Not available",
            "vector": "Not available",
            "severity": "Not available"
        }

        text = soup.get_text(" ", strip=True)

        # Look for CVSS Score in structured data
        # Format: "CVSS Score: 7.2" or "CVSS: 8.1" or "CVSS v3.1 Base Score: 8.8"
        match = re.search(r"CVSS\s+(?:v?3\.\d+\s+)?(?:Base\s+)?Score[:\s]*([0-9.]+)", text, re.I)
        if match:
            result["base"] = match.group(1)
        else:
            match = re.search(r"CVSS[:\s]*([0-9.]+)", text, re.I)
            if match:
                result["base"] = match.group(1)

        # Look for CVSS Vector
        # Format: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
        match = re.search(r"(CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])", text, re.I)
        if match:
            result["vector"] = match.group(1)
        else:
            # Alternative: just the vector part without CVSS prefix
            match = re.search(r"(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])", text, re.I)
            if match:
                result["vector"] = f"CVSS:3.0/{match.group(1)}"

        # Look for Severity
        # Format: "Severity: HIGH" or "HIGH severity" or just "HIGH"
        match = re.search(r"Severity[:\s]*(CRITICAL|HIGH|MEDIUM|LOW)", text, re.I)
        if match:
            result["severity"] = match.group(1).capitalize()
        else:
            # Derive from CVSS score
            try:
                base = float(result["base"])
                if base >= 9.0:
                    result["severity"] = "Critical"
                elif base >= 7.0:
                    result["severity"] = "High"
                elif base >= 4.0:
                    result["severity"] = "Medium"
                else:
                    result["severity"] = "Low"
            except:
                pass

        return result

    def extract_description(self, soup: BeautifulSoup) -> str:
        text = soup.get_text(" ", strip=True)
        
        # Strategy 1: Look for meta description
        meta_desc = soup.find("meta", {"name": "description"})
        if meta_desc and meta_desc.get("content"):
            desc = meta_desc["content"]
            if len(desc) > 50:
                return desc[:400] + "..." if len(desc) > 400 else desc
        
        # Strategy 2: Look for description after CVE ID
        # Usually formatted as "CVE-XXXX-YYYY is a [type] vulnerability..."
        cve_id = self.extract_advisory_id(soup.get_text())
        if cve_id != "Not available":
            match = re.search(rf"{cve_id}\s+is\s+(.+?)(?:\.|This|The vulnerability|Learn more|Technical|Impact|Affected|$)", text, re.DOTALL | re.I)
            if match:
                desc = match.group(0).strip()
                return desc[:400] + "..." if len(desc) > 400 else desc
        
        # Strategy 3: Look for first substantial paragraph with vulnerability keywords
        paragraphs = soup.find_all("p")
        for p in paragraphs:
            p_text = p.get_text(" ", strip=True)
            if len(p_text) > 50 and any(kw in p_text.lower() for kw in ["vulnerability", "allows", "attacker", "exploit", "flaw", "execute", "arbitrary code"]):
                return p_text[:400] + "..." if len(p_text) > 400 else p_text
        
        return "Not available"

    def extract_affected_products(self, soup: BeautifulSoup) -> list[str]:
        text = soup.get_text(" ", strip=True)
        products = []
        
        # Strategy 1: Look for "Affected Products" or "Affected Versions" section
        match = re.search(r"Affected\s+(?:Products?|Versions?|Systems?)[:\s]*(.+?)(?:CVE|CVSS|Impact|Exploitation|Mitigation|Technical|$)", text, re.DOTALL | re.I)
        if match:
            product_text = match.group(1).strip()
            # Clean up and extract product names
            lines = [line.strip() for line in product_text.split("\n") if len(line.strip()) > 3]
            # Take first 5 lines as products
            products.extend(lines[:5])
        
        # Strategy 2: Look for product name in title
        if not products:
            title = self.extract_title(soup)
            
            # Common product patterns in titles
            product_patterns = [
                r"(?:Microsoft|Windows|Office|Exchange|SharePoint)\s+[\w\s]+",
                r"(?:VMware|ESXi|vCenter|Workspace)\s+[\w\s]+",
                r"(?:Adobe|Acrobat|Reader|Photoshop)\s+[\w\s]+",
                r"(?:Cisco|IOS|ASA|Firepower)\s+[\w\s]+",
                r"(?:Apache|HTTPD|Tomcat|Log4j)\s+[\w\s]+",
                r"(?:NVIDIA|vGPU|CUDA)\s+[\w\s]+",
                r"(?:F5|BIG-IP|NGINX)\s+[\w\s]+",
                r"(?:Fortinet|FortiGate|FortiOS)\s+[\w\s]+",
            ]
            
            for pattern in product_patterns:
                match = re.search(pattern, title, re.I)
                if match:
                    product = match.group(0).strip()
                    products.append(product)
                    break
        
        # Strategy 3: Extract from first part of title (before vulnerability type)
        if not products:
            title = self.extract_title(soup)
            # Remove CVE ID from title
            title_clean = re.sub(r"CVE-\d{4}-\d+[:\s]*", "", title, flags=re.I).strip()
            # Extract first few words (likely product name)
            words = title_clean.split()[:4]  # First 4 words
            if len(words) >= 2:
                products.append(" ".join(words))
        
        # Remove duplicates and return
        if products:
            seen = set()
            unique = []
            for p in products:
                p_clean = re.sub(r'\s+', ' ', p).strip()
                if p_clean.lower() not in seen and len(p_clean) > 2:
                    seen.add(p_clean.lower())
                    unique.append(p_clean)
            return unique[:5] if unique else ["Not listed"]
        
        return ["Not listed"]

    # ---------------- MAIN PARSER ----------------
    def parse_advisory(self) -> dict:
        url = self.get_latest_advisory_url()
        soup = self._fetch_page(url)

        cvss = self.extract_cvss(soup)

        advisory = {
            "vendor": "SentinelOne (Vulnerability DB)",
            "advisory_id": self.extract_advisory_id(url),
            "title": self.extract_title(soup),
            "first_published": self.extract_first_published(soup),
            "cvss": cvss["base"],
            "vector": cvss["vector"],
            "severity": cvss["severity"],
            "cves": self.extract_cves(url, soup),
            "description": self.extract_description(soup),
            "affected_products": self.extract_affected_products(soup),
            "source_url": url,
        }

        logger.info(f"SentinelOne CVE {advisory['advisory_id']} parsed")
        return advisory