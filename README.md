# 🗺️ OsintKitPlus

**Unified OSINT Intelligence Engine**  
Point it at any IP or domain — OsintKitPlus pulls data from NVD, Shodan, VirusTotal, and public DNS/GeoIP APIs and merges everything into a single structured report.

> ⚠️ For educational and authorized research use only.

---

## 🎯 What It Does

```
  ╔════════════════════════════════════════════════════════╗
  ║  OsintKitPlus INTELLIGENCE REPORT                      ║
  ║  Target : example.com                                  ║
  ║  Time   : 2025-01-01T12:00:00Z                        ║
  ╠════════════════════════════════════════════════════════╣
  ├─ NETWORK INTELLIGENCE ───────────────────────────────
  │  IP Address             93.184.216.34
  │  Organization           Edgecast Inc.
  │  Country                🇺🇸 United States / Los Angeles
  ├─ SHODAN — OPEN PORTS & SERVICES ─────────────────────
  │  Open Ports             80, 443
  │  :80  tcp               Apache httpd  2.4.41
  │  :443 tcp               OpenSSL  1.1.1
  ├─ CVE INTELLIGENCE (3 results) ───────────────────────
  │  CVE-2021-41773         [HIGH] CVSS:7.5 — Path traversal...
  ├─ VIRUSTOTAL REPUTATION ──────────────────────────────
  │  Detections             0 malicious / 0 suspicious [92 engines]
  ├─ ALERTS (1) ─────────────────────────────────────────
  │  ⚠ [CVE]  CVE-2021-41773 HIGH CVSS:7.5
  ╚════════════════════════════════════════════════════════╝

  Risk Summary:  0 HIGH  1 MEDIUM  0 LOW
```

---

## 🗂️ Modules

| Module | Data Source | What It Fetches |
|--------|------------|-----------------|
| **GeoIP** | ip-api.com (free, no key) | Country, city, ASN, org, proxy/VPN detection, abuse contact |
| **WHOIS** | python-whois | Registrar, creation/expiry dates, nameservers |
| **DNS** | System resolver / dnspython | A, AAAA, MX, NS, TXT, SPF, DMARC, SOA |
| **Shodan** | Shodan API (free key) | Open ports, banners, OS fingerprint, Shodan CVE list |
| **CVE / NVD** | NVD REST API v2 (free) | CVEs by keyword, sorted by CVSS score |
| **VirusTotal** | VT API v3 (free key) | Malicious/suspicious detections, categories, reputation score |

---

## 🚀 Installation

```bash
git clone https://github.com/ozancolhak/OsintKitPlus
cd OsintKitPlus
pip install -r requirements.txt

# Recommended extras
pip install python-whois dnspython
```

**Free API keys (2 minutes to get):**
- Shodan: https://account.shodan.io/register
- VirusTotal: https://www.virustotal.com/gui/join-us

---

## 📖 Usage

```bash
# Basic scan — no API keys needed (GeoIP + DNS + NVD)
python3 OsintKitPlus.py example.com
python3 OsintKitPlus.py 8.8.8.8

# Full scan with all sources
python3 OsintKitPlus.py example.com \
    --shodan-key YOUR_SHODAN_KEY \
    --vt-key YOUR_VT_KEY

# Custom CVE keyword search
python3 OsintKitPlus.py example.com --cve apache nginx openssl

# Save JSON report
python3 OsintKitPlus.py example.com --output report.json

# Run specific modules only
python3 OsintKitPlus.py example.com --only geo dns virustotal

# Skip slow modules
python3 OsintKitPlus.py example.com --skip shodan cve
```

---

## 📊 Alert Levels

| Level | Trigger Examples |
|-------|-----------------|
| 🔴 HIGH | VT malicious detections > 0, Shodan CVEs, high-risk ports (RDP/Redis/MongoDB) |
| 🟡 MEDIUM | VT suspicious detections, missing SPF/DMARC, datacenter IP, notable ports |
| ⚪ LOW | Missing DNSSEC, p=none DMARC policy, informational findings |

---

## 📄 JSON Report Structure

```json
{
  "target": "example.com",
  "timestamp": "2025-01-01T12:00:00Z",
  "sections": {
    "geo": {
      "ip": "93.184.216.34",
      "org": "Edgecast Inc.",
      "country": "United States",
      "is_proxy": false
    },
    "shodan": {
      "ports": [80, 443],
      "services": [{"port": 80, "product": "Apache", "risk": "LOW"}],
      "vulns": ["CVE-2021-41773"]
    },
    "cves": [
      {
        "id": "CVE-2021-41773",
        "severity": "HIGH",
        "cvss": "7.5",
        "desc": "Path traversal and RCE in Apache 2.4.49..."
      }
    ],
    "virustotal": {
      "malicious": 0,
      "suspicious": 0,
      "total": 92,
      "reputation": 5
    }
  },
  "alerts": [
    {"level": "MEDIUM", "source": "DNS", "message": "No DMARC record found."}
  ]
}
```

---

## 🏗️ Project Structure

```
OsintKitPlus/
├── OsintKitPlus.py           # Main CLI
├── requirements.txt
├── modules/
│   ├── geo.py                # GeoIP + WHOIS
│   ├── dns_intel.py          # DNS records + SPF/DMARC
│   ├── shodan_intel.py       # Shodan API
│   ├── cve_intel.py          # NVD CVE search
│   └── virustotal.py         # VirusTotal API
└── utils/
    ├── report.py             # Terminal renderer + JSON export
    └── banner.py             # Terminal output helpers
```

---

## ⚙️ Requirements

- Python 3.8+
- `requests` (required)
- `python-whois` (optional — WHOIS lookups)
- `dnspython` (optional — more accurate DNS)
- Shodan API key — free tier at shodan.io
- VirusTotal API key — free tier at virustotal.com

---

## 📜 License

MIT License — Educational and authorized security research use only.
