# NeoSpyder Hybrid

A Python-based security advisory aggregator that scrapes the latest vulnerability bulletins from major cybersecurity vendors and delivers them via email. Built with a hybrid architecture combining Selenium for JavaScript-heavy sites and async HTTP requests for static pages.

## 🎯 Overview

NeoSpyder Hybrid automates the collection of security advisories from:
- **Cisco** - Security Center publications
- **Palo Alto Networks** - Security advisories
- **Fortinet** - FortiGuard PSIRT bulletins
- **Check Point** - Security advisories
- **Trend Micro** - Zero Day Initiative (ZDI) published advisories
- **SentinelOne** - Vulnerability database CVEs

The tool runs network diagnostics, scrapes each vendor concurrently, extracts structured security data, and sends formatted email notifications to your SOC team.

## 🏗️ Architecture

### Hybrid Execution Engine

**Thread Pool (Selenium vendors):**
- Cisco
- Palo Alto Networks

**Async Engine (HTTP vendors):**
- Fortinet
- Check Point
- Trend Micro (ZDI)
- SentinelOne

Both engines run concurrently using Python's `asyncio` with a live dashboard showing real-time scraping progress.

## 📋 Features

### 1. Network Diagnostics
Before scraping, NeoSpyder performs comprehensive network checks:
- DNS resolution for each vendor domain
- HTTP connectivity verification
- Status reporting with color-coded health indicators

### 2. Live Dashboard
Real-time terminal UI built with Rich library:
- Per-vendor status updates
- Progress indicators
- Color-coded completion status (green ✓ = success, red ✗ = error)

### 3. Vendor-Specific Scrapers

#### **Cisco OEM**
- Uses Selenium WebDriver for JavaScript-rendered content
- Extracts CVSS base score, vector, and severity from hidden inputs and visible text
- Parses affected products from tables, lists, and text patterns
- Handles multiple date formats (YYYY-MM-DD, "YYYY Month DD")

#### **Palo Alto OEM**
- Selenium-based scraper for dynamic advisory pages
- Extracts CVSS vector from detail pages
- Parses affected products with version information (affected/unaffected ranges)
- Handles collapsible/accordion sections for hidden content

#### **Fortinet OEM**
- HTTP-based scraper using BeautifulSoup
- Regex extraction of advisory IDs (FG-IR-XX-XXX format)
- Parses structured table data (Published Date, CVSSv3 Score, Severity)
- Determines affected products by analyzing version/affected/solution tables

#### **Check Point OEM**
- HTTP-based scraper for advisory archive
- Extracts latest advisory from table listing
- Parses "Vulnerability Description" and "Who is Vulnerable" fields
- Handles multi-line product listings

#### **Trend Micro (ZDI) OEM**
- Scrapes Zero Day Initiative published advisories table
- Extracts metadata from table columns (ZDI ID, CVE, CVSS, published date)
- Sorts by published date to get most recent
- Intelligent product name extraction from vendor + title parsing
- Stores table metadata for efficient data extraction

#### **SentinelOne OEM**
- Scrapes vulnerability database for latest CVEs
- Multi-strategy product extraction from affected products sections
- CVSS score and vector parsing with multiple pattern matching
- Meta description extraction for vulnerability details

### 4. Data Extraction

Each scraper extracts:
- **Advisory ID**: Vendor-specific identifier
- **Title**: Full advisory name
- **Published Date**: First publication date
- **CVSS Score**: Base score (0.0-10.0)
- **CVSS Vector**: Full vector string (e.g., CVSS:3.1/AV:N/AC:L/...)
- **Severity**: Critical/High/Medium/Low (derived from CVSS if not explicit)
- **CVE IDs**: All associated CVE identifiers
- **Description**: Vulnerability summary
- **Affected Products**: Product names and versions
- **Source URL**: Link to original advisory

### 5. Email Notifications

Formatted HTML emails include:
- Advisory metadata table
- CVE links to MITRE database
- Description and affected products
- Direct link to source advisory
- UTC timestamp

Sent via SMTP with STARTTLS encryption.

## 🚀 Setup

### Prerequisites
```bash
Python 3.10+
Chrome browser (for Selenium vendors)
```

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/ckbadgujar2003/neospyder-hybrid.git
cd neospyder-hybrid
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables:**

Create `config/settings.py`:
```python
# SMTP Configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_MAIL = "your-email@gmail.com"
SENDER_MAIL_PASSWORD = "your-app-password"  # Use App Password for Gmail
RECEIVER_MAIL = "soc-team@company.com"
```

### Gmail Setup

For Gmail SMTP:
1. Enable 2-Factor Authentication
2. Generate App Password: Google Account → Security → App Passwords
3. Use the 16-character app password in `SENDER_MAIL_PASSWORD`

## 💻 Usage

Run the scraper:
```bash
python main.py
```

### Execution Flow

1. **Network Diagnostics**: Validates connectivity to all vendor portals
2. **Concurrent Scraping**: Both engines (thread pool + async) run simultaneously
3. **Live Dashboard**: Real-time status updates for each vendor
4. **Email Delivery**: Formatted advisories sent upon successful extraction
5. **Completion Report**: Summary of successful/failed scrapes

### Sample Output

```
NeoSpyder Hybrid Engine Starting

Running NeoSpyder Network Diagnostics

┌─────────────────────────────────────┐
│     Network Health Check            │
├─────────────┬──────┬───────┬────────┤
│ Service     │ DNS  │ HTTP  │ Status │
├─────────────┼──────┼───────┼────────┤
│ Cisco       │ ✓    │ ✓     │ ✓ Ready│
│ PaloAlto    │ ✓    │ ✓     │ ✓ Ready│
│ Fortinet    │ ✓    │ ✓     │ ✓ Ready│
└─────────────┴──────┴───────┴────────┘

┌──────────────────────────────────┐
│  NeoSpyder SOC Dashboard         │
├──────────────┬───────────────────┤
│ Vendor       │ Status            │
├──────────────┼───────────────────┤
│ Cisco        │ ✓ Email sent      │
│ Paloalto     │ ✓ Email sent      │
│ Fortinet     │ ✓ Email sent      │
│ Checkpoint   │ ✓ Email sent      │
│ Trendmicro   │ ✓ Email sent      │
│ Sentinelone  │ ✓ Email sent      │
└──────────────┴───────────────────┘

✓ NeoSpyder run completed
```

## 📁 Project Structure

```
neospyder-hybrid/
├── main.py                 # Entry point with hybrid orchestrator
├── logger.py              # Rich-based colored logging
├── config/
│   └── settings.py        # SMTP and configuration
├── oems/                  # Vendor-specific scrapers
│   ├── base.py           # Abstract base class
│   ├── cisco.py          # Cisco scraper (Selenium)
│   ├── paloalto.py       # Palo Alto scraper (Selenium)
│   ├── fortinet.py       # Fortinet scraper (HTTP)
│   ├── checkpoint.py     # Check Point scraper (HTTP)
│   ├── trendmicro.py     # Trend Micro ZDI scraper (HTTP)
│   └── sentinelone.py    # SentinelOne scraper (HTTP)
├── notifier/
│   └── emailer.py        # Email formatting and delivery
└── utils/
    ├── console.py         # Rich console configuration
    ├── driver_factory.py  # Selenium WebDriver factory
    └── network_diagnostics.py  # Connectivity checks
```

## 🛠️ Technical Details

### Selenium Configuration
- Headless Chrome with `--headless=new`
- GPU disabled for compatibility
- Logs suppressed to `/dev/null`
- WebDriverWait for dynamic content loading

### HTTP Requests
- Custom User-Agent headers
- 20-30 second timeouts
- BeautifulSoup with lxml parser
- Connection error handling

### Concurrency Model
- ThreadPoolExecutor for Selenium vendors (separate browser instances)
- asyncio.gather() for HTTP vendors (shared event loop)
- Thread-safe status updates with Lock()
- Rich Live display with 8 refreshes/second

### Error Handling
- Per-vendor try/catch blocks
- Non-blocking failures (one vendor failure doesn't stop others)
- ASCII sanitization for Windows console compatibility
- Graceful WebDriver cleanup in finally blocks

## 🔒 Security Considerations

- **SMTP Authentication**: Use app passwords, never plain passwords
- **Credential Storage**: Keep `settings.py` out of version control (.gitignore)
- **HTTPS Only**: All vendor URLs use TLS
- **Input Sanitization**: CVE regex validation, URL normalization
- **Timeout Protection**: All network calls have timeouts

## 🐛 Troubleshooting

### Common Issues

**Selenium vendors failing:**
- Install Chrome/Chromium browser
- Verify chromedriver version matches Chrome version
- Check firewall rules for webdriver connections

**SMTP authentication errors:**
- Enable 2FA on Gmail
- Generate and use App Password (not account password)
- Verify `SENDER_MAIL` and `SENDER_MAIL_PASSWORD` in settings.py

**Network diagnostics showing failures:**
- Check corporate proxy/firewall settings
- Verify DNS resolution for vendor domains
- Test connectivity with curl/wget manually

**Windows encoding errors:**
- Script sets `PYTHONUTF8=1` automatically
- Verify terminal supports UTF-8
- Use Windows Terminal instead of cmd.exe

## 📝 Adding New Vendors

1. Create scraper in `oems/new_vendor.py` inheriting from `BaseOEM`
2. Implement `get_latest_advisory_url()` and `parse_advisory()`
3. Add to `main.py`:
   - Import: `from oems.new_vendor import NewVendorOEM`
   - Add to `THREAD_VENDORS` or `ASYNC_VENDORS` dict
4. Add to `utils/network_diagnostics.py` targets

## 📊 Dependencies

Core libraries:
- `selenium` - Browser automation
- `beautifulsoup4` - HTML parsing
- `lxml` - Fast XML/HTML parser
- `requests` - HTTP client
- `rich` - Terminal UI and logging

Email:
- `smtplib` (stdlib) - SMTP client
- `email` (stdlib) - MIME message construction

Async:
- `asyncio` (stdlib) - Async runtime
- `concurrent.futures` (stdlib) - Thread pool

## 📄 License

This project is provided as-is for educational and SOC automation purposes.

## ⚖️ Legal Disclaimer

**The author is NOT responsible for any illegal, unethical, or unauthorized activities performed using this code.**

This tool is provided for **educational and legitimate security operations purposes only**. By using NeoSpyder Hybrid, you accept full responsibility for your actions and agree to:

- ✅ Use only for authorized security monitoring and SOC automation
- ✅ Comply with all applicable laws, regulations, and terms of service
- ✅ Implement reasonable rate limiting and respect vendor policies
- ✅ Obtain proper authorization before scraping any systems

- ❌ **DO NOT** use for unauthorized access, data theft, or malicious purposes
- ❌ **DO NOT** violate website terms of service or applicable laws
- ❌ **DO NOT** use for denial of service or excessive automated requests

**This software is provided "AS IS" without warranty. You are solely responsible for how you use it.**

If you do not agree with these terms, do not use this software.

## 👨‍💻 Author

**Chirayu Badgujar**

- GitHub: [@ckbadgujar2003](https://github.com/ckbadgujar2003)
- Repository v1: [neospyder-core](https://github.com/ckbadgujar2003/neospyder-core) 
- Repository v2: [neospyder-hybrid](https://github.com/ckbadgujar2003/neospyder-hybrid)
- LinkedIn: [Chirayu Badgujar](https://www.linkedin.com/in/chirayu-badgujar-477128223/)

---

**Built with Python, Selenium, and asyncio for efficient security advisory monitoring.**
