from .base import BaseOEM
from bs4 import BeautifulSoup
from logger import setup_logger
import requests, re
from datetime import datetime

logger = setup_logger()

ZDI_PUBLISHED = "https://www.zerodayinitiative.com/advisories/published/"
ZDI_BASE = "https://www.zerodayinitiative.com"


class TrendMicroOEM(BaseOEM):

    # ---------------- PAGE FETCH ----------------
    def _fetch_page(self, url: str) -> BeautifulSoup:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        return BeautifulSoup(r.text, "lxml")

    def _parse_date(self, date_str: str) -> datetime:
        """Parse date in format YYYY-MM-DD"""
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except:
            return datetime(1900, 1, 1)

    # ---------------- STEP 1: GET LATEST ADVISORY URL ----------------
    def get_latest_advisory_url(self) -> str:
        """
        Get the latest ZDI advisory from the published list.
        Sorted by published date descending.
        Also stores metadata from the table for later use.
        """
        soup = self._fetch_page(ZDI_PUBLISHED)

        # Find the advisories table
        table = soup.find("table")
        if not table:
            raise RuntimeError("ZDI advisories table not found")

        # Get all rows (skip header)
        rows = table.find_all("tr")[1:]
        if not rows:
            raise RuntimeError("No advisories found in table")

        # Parse advisories and sort by published date
        advisories = []
        
        for row in rows[:20]:  # Check first 20 rows
            cols = row.find_all("td")
            if len(cols) < 8:
                continue
            
            try:
                # Column structure:
                # 0: ZDI ID
                # 1: ZDI CAN
                # 2: AFFECTED VENDOR(S)
                # 3: CVE
                # 4: CVSS
                # 5: PUBLISHED
                # 6: UPDATED
                # 7: TITLE (with link)
                
                zdi_id = cols[0].get_text(strip=True)
                vendor = cols[2].get_text(strip=True)
                cve = cols[3].get_text(strip=True)
                cvss = cols[4].get_text(strip=True)
                published_str = cols[5].get_text(strip=True)
                
                # Get advisory link from title column
                link = cols[7].find("a", href=True)
                if not link:
                    continue
                
                href = link["href"]
                title = link.get_text(strip=True)
                
                # Build full URL
                if not href.startswith("http"):
                    href = ZDI_BASE + href
                
                # Parse date
                published_date = self._parse_date(published_str)
                
                advisories.append({
                    "url": href,
                    "zdi_id": zdi_id,
                    "vendor": vendor,
                    "cve": cve,
                    "cvss": cvss,
                    "title": title,
                    "published_date": published_date,
                    "published_str": published_str,
                })
                
            except Exception as e:
                logger.warning(f"Error parsing row: {e}")
                continue
        
        if not advisories:
            raise RuntimeError("No valid advisories found")
        
        # Sort by published date (most recent first)
        advisories.sort(key=lambda x: x["published_date"], reverse=True)
        
        latest = advisories[0]
        
        # Store metadata for later use
        self._table_metadata = latest
        
        logger.info(f"Latest ZDI advisory: {latest['zdi_id']} - {latest['title'][:60]}")
        logger.info(f"URL: {latest['url']}")
        
        return latest["url"]

    # ---------------- FIELD EXTRACTORS ----------------
    def extract_title(self, soup: BeautifulSoup) -> str:
        # Look for h1
        h1 = soup.find("h1")
        if h1:
            return h1.get_text(strip=True)
        
        # Fallback to title tag
        title = soup.find("title")
        if title:
            return title.get_text(strip=True).split("|")[0].strip()
        
        return "Trend Micro ZDI Advisory"

    def extract_advisory_id(self, url: str) -> str:
        # Extract ZDI-YY-XXX from URL
        match = re.search(r"(ZDI-\d{2}-\d+)", url, re.I)
        if match:
            return match.group(1)
        return "Not available"

    def extract_first_published(self, soup: BeautifulSoup) -> str:
        text = soup.get_text(" ", strip=True)
        
        # Look for "Published:" pattern
        match = re.search(r"Published:\s*(\d{4}-\d{2}-\d{2})", text, re.I)
        if match:
            return match.group(1)
        
        # Alternative format
        match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if match:
            return match.group(1)
        
        return "Not available"

    def extract_cves(self, soup: BeautifulSoup) -> list[str]:
        cves = []
        
        # Strategy 1: Use metadata from table
        if hasattr(self, '_table_metadata') and self._table_metadata.get('cve'):
            table_cve = self._table_metadata['cve'].strip()
            if table_cve and table_cve != "":
                cves.append(table_cve)
        
        # Strategy 2: Extract from detail page
        text = soup.get_text(" ", strip=True)
        page_cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
        cves.extend(page_cves)
        
        # Remove duplicates and sort
        cves = sorted(set(cves))
        return cves if cves else ["Not listed"]

    def extract_cvss(self, soup: BeautifulSoup) -> dict:
        result = {
            "base": "Not available",
            "vector": "Not available",
            "severity": "Not available"
        }

        # Strategy 1: Use metadata from table (most reliable)
        if hasattr(self, '_table_metadata') and self._table_metadata.get('cvss'):
            result["base"] = self._table_metadata['cvss']
        else:
            # Strategy 2: Parse from detail page
            text = soup.get_text(" ", strip=True)
            match = re.search(r"CVSS[:\s]*([0-9.]+)", text, re.I)
            if match:
                result["base"] = match.group(1)

        # Extract CVSS vector from detail page
        text = soup.get_text(" ", strip=True)
        match = re.search(r"(CVSS:[0-9.]+/[A-Z:/\.]+)", text)
        if match:
            result["vector"] = match.group(1)

        # Derive severity from CVSS
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
        # ZDI advisories have structured content
        # Look for the vulnerability description
        
        # Strategy 1: Look for specific ZDI patterns
        text = soup.get_text(" ", strip=True)
        
        # Look for description after "This vulnerability allows"
        match = re.search(r"This vulnerability allows\s+(.+?)(?:\.|Affected|An attacker|The specific|$)", text, re.DOTALL)
        if match:
            desc = match.group(0).strip()
            # Limit to first 300 chars
            return desc[:300] + "..." if len(desc) > 300 else desc
        
        # Strategy 2: Extract first substantial paragraph
        paragraphs = soup.find_all("p")
        for p in paragraphs:
            p_text = p.get_text(" ", strip=True)
            if len(p_text) > 50 and any(kw in p_text.lower() for kw in ["vulnerability", "allows", "attacker", "exploit"]):
                return p_text[:300] + "..." if len(p_text) > 300 else p_text
        
        # Strategy 3: Get text after ZDI ID
        zdi_id = self.extract_advisory_id(soup.get_text())
        if zdi_id != "Not available":
            match = re.search(rf"{zdi_id}[:\s]+(.{{50,300}})", text, re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return "Not available"

    def extract_affected_products(self, soup: BeautifulSoup) -> list[str]:
        products = []
        
        # Strategy 1: Use vendor from table metadata
        if hasattr(self, '_table_metadata'):
            vendor = self._table_metadata.get('vendor', '').strip()
            title = self._table_metadata.get('title', '').lower()
            
            if vendor:
                # Extract product name from title
                # Format: "Vendor Product Feature Vulnerability Type"
                # Example: "Siemens SINEC NMS Uncontrolled Search Path..."
                
                # Remove vendor name from title
                title_without_vendor = title.replace(vendor.lower(), '').strip()
                
                # Extract product name (usually first few words after vendor)
                # Look for common patterns
                product_match = re.match(r'^([A-Za-z0-9\s\-]+?)(?:\s+(?:Uncontrolled|Use-After-Free|Out-Of-Bounds|Heap-based|Stack-based|Command|Missing|Directory|Buffer|Type|Memory|Deserialization|SQL|Authentication|Cross-Site|Remote|Local|Privilege|Denial|Information|Security))', title_without_vendor, re.I)
                
                if product_match:
                    product_name = product_match.group(1).strip()
                    if product_name:
                        products.append(f"{vendor} {product_name}")
                elif vendor:
                    # Fallback: just use vendor
                    products.append(vendor)
        
        # Strategy 2: Look for "Affected Product:" section in detail page
        text = soup.get_text(" ", strip=True)
        match = re.search(r"Affected Product[s]?:\s*(.+?)(?:CVE|ZDI|Vendor|Published|$)", text, re.DOTALL | re.I)
        if match:
            product_text = match.group(1).strip()
            # Clean up and add
            page_products = [p.strip() for p in re.split(r'[\n,]', product_text) if len(p.strip()) > 3]
            if page_products:
                products.extend(page_products[:3])
        
        # Remove duplicates
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
            "vendor": "Trend Micro (ZDI)",
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

        logger.info(f"ZDI advisory {advisory['advisory_id']} parsed")
        return advisory