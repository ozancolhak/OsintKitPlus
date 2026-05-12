"""
ThreatMapper - CVE / NVD Intelligence Modülü
API: NVD (National Vulnerability Database) — ücretsiz, kayıtsız
Arama: Ürün/vendor adı, keyword veya CVE ID ile
"""

import requests
import socket
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.report import ThreatReport

requests.packages.urllib3.disable_warnings()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "NONE":     "\033[90m",
}

def parse_cve(item: dict) -> dict:
    cve_id  = item.get("cve", {}).get("id", "N/A")
    descs   = item.get("cve", {}).get("descriptions", [])
    desc    = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

    metrics = item.get("cve", {}).get("metrics", {})
    cvss_score = "N/A"
    severity   = "UNKNOWN"

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            data       = metrics[version][0]
            cvss_score = data.get("cvssData", {}).get("baseScore", "N/A")
            severity   = data.get("cvssData", {}).get("baseSeverity",
                         data.get("baseSeverity", "UNKNOWN"))
            break

    published = item.get("cve", {}).get("published", "")[:10]
    refs      = [r["url"] for r in item.get("cve", {}).get("references", [])[:2]]

    return {
        "id":        cve_id,
        "desc":      desc[:120],
        "cvss":      cvss_score,
        "severity":  severity.upper(),
        "published": published,
        "refs":      refs,
    }

def search_nvd(keyword: str, results_per_page: int = 10, api_key: str = None) -> list:
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_BASE, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return [parse_cve(item) for item in data.get("vulnerabilities", [])]
        else:
            warn(f"NVD API error: {r.status_code}")
    except Exception as e:
        warn(f"NVD request error: {e}")
    return []

def get_cve_by_id(cve_id: str) -> dict:
    try:
        r = requests.get(NVD_BASE, params={"cveId": cve_id}, timeout=10)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                return parse_cve(vulns[0])
    except Exception as e:
        warn(f"CVE lookup error: {e}")
    return {}

def detect_keywords(target: str) -> list:
    """Hedeften otomatik arama keyword'leri çıkarır."""
    keywords = []

    # IP ise Shodan'dan ürün bilgisi gelmeden önce generic tarama
    try:
        socket.inet_aton(target)
        keywords.append(target)
        return keywords
    except:
        pass

    # Domain'den TLD ve alt domainleri çıkar
    parts = target.split(".")
    if len(parts) >= 2:
        # wordpress, apache, nginx, drupal gibi CMS/server ipuçları
        common_keywords = [
            "apache", "nginx", "iis", "tomcat", "wordpress",
            "drupal", "joomla", "jenkins", "gitlab", "confluence"
        ]
        for kw in common_keywords:
            if kw in target.lower():
                keywords.append(kw)

    return keywords or [parts[0]]  # en azından subdomain adı

def check_cve(target: str, report: ThreatReport,
              keywords: list = None, max_results: int = 10, nvd_key: str = None):
    section(f"CVE / NVD Intelligence — {target}")

    search_terms = keywords if keywords else detect_keywords(target)
    all_cves     = []

    for kw in search_terms[:3]:  # Max 3 keyword
        info(f"Searching NVD: '{kw}' ...")
        cves = search_nvd(kw, results_per_page=max_results, api_key=nvd_key)
        if cves:
            ok(f"Found {len(cves)} CVEs for '{kw}'")
            all_cves.extend(cves)
        else:
            info(f"No CVEs found for '{kw}'")

    # Dedup + sort by CVSS
    seen = set()
    unique_cves = []
    for c in all_cves:
        if c["id"] not in seen:
            seen.add(c["id"])
            unique_cves.append(c)

    def cvss_sort(c):
        try:    return float(c["cvss"])
        except: return 0.0

    unique_cves.sort(key=cvss_sort, reverse=True)

    # Print
    if unique_cves:
        info(f"Top CVEs (sorted by CVSS):")
        for cve in unique_cves[:10]:
            sev   = cve["severity"]
            score = cve["cvss"]
            c     = SEVERITY_COLOR.get(sev, "\033[90m")
            print(f"\n    {c}{cve['id']}\033[0m  [{sev}]  CVSS: {score}  ({cve['published']})")
            print(f"    \033[90m{cve['desc'][:100]}\033[0m")

            if sev in ("CRITICAL", "HIGH"):
                report.add_alert("HIGH", "CVE",
                                 f"{cve['id']} [{sev} CVSS:{score}] — {cve['desc'][:70]}")
            elif sev == "MEDIUM":
                report.add_alert("MEDIUM", "CVE",
                                 f"{cve['id']} [MEDIUM CVSS:{score}]")
    else:
        ok("No CVEs found for this target.")

    report.add_section("cves", unique_cves[:10])
