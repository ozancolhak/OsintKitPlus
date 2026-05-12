"""
ThreatMapper - VirusTotal Intelligence Modülü
API: VirusTotal v3 (ücretsiz API key — virustotal.com)
Çeker: Reputation, kategoriler, engine detections, son analiz tarihi
"""

import requests
import socket
import datetime
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.report import ThreatReport

requests.packages.urllib3.disable_warnings()
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "User-Agent": "ThreatMapper/1.0"}

def fetch_vt_domain(domain: str, api_key: str) -> dict:
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}",
                         headers=vt_headers(api_key), timeout=12)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
        elif r.status_code == 401:
            warn("VirusTotal: Invalid API key.")
        elif r.status_code == 404:
            info("VirusTotal: Domain not found in database.")
        else:
            warn(f"VirusTotal API: {r.status_code}")
    except Exception as e:
        warn(f"VirusTotal error: {e}")
    return {}

def fetch_vt_ip(ip: str, api_key: str) -> dict:
    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}",
                         headers=vt_headers(api_key), timeout=12)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
        elif r.status_code == 401:
            warn("VirusTotal: Invalid API key.")
        else:
            warn(f"VirusTotal API: {r.status_code}")
    except Exception as e:
        warn(f"VirusTotal error: {e}")
    return {}

def parse_vt_data(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    # Kategoriler
    cats_raw = attrs.get("categories", {})
    cats = list(set(cats_raw.values()))[:6]

    # Tags
    tags = attrs.get("tags", [])

    # Reputation score (-100 kötü, +100 iyi)
    reputation = attrs.get("reputation", 0)

    # Son analiz tarihi
    last_ts = attrs.get("last_analysis_date", 0)
    last_date = ""
    if last_ts:
        last_date = datetime.datetime.utcfromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M UTC")

    # Kötü amaçlı engine'ler
    engines = attrs.get("last_analysis_results", {})
    flagged = [
        {"engine": name, "result": data.get("result", ""), "category": data.get("category", "")}
        for name, data in engines.items()
        if data.get("category") in ("malicious", "suspicious")
    ]

    return {
        "malicious":          malicious,
        "suspicious":         suspicious,
        "harmless":           harmless,
        "total":              total,
        "categories":         cats,
        "tags":               tags,
        "reputation":         reputation,
        "last_analysis_date": last_date,
        "flagged_engines":    flagged[:10],
    }

def check_virustotal(target: str, report: ThreatReport, api_key: str = None):
    section(f"VirusTotal Reputation — {target}")

    if not api_key:
        info("VirusTotal skipped — use --vt-key <API_KEY> to enable")
        info("Free API key: https://www.virustotal.com/gui/join-us")
        return

    # IP mi domain mi?
    try:
        socket.inet_aton(target)
        is_ip = True
    except:
        is_ip = False

    attrs = fetch_vt_ip(target, api_key) if is_ip else fetch_vt_domain(target, api_key)
    if not attrs:
        return

    vt = parse_vt_data(attrs)

    # Reputation score
    rep = vt["reputation"]
    rep_c = "\033[91m" if rep < -10 else "\033[93m" if rep < 0 else "\033[92m"
    ok(f"Reputation Score : {rep_c}{rep}\033[0m  (-100 = malicious, +100 = trusted)")

    # Detection stats
    mal = vt["malicious"]
    sus = vt["suspicious"]
    tot = vt["total"]
    c   = "\033[91m" if mal > 0 else "\033[93m" if sus > 0 else "\033[92m"
    ok(f"Engine Results   : {c}{mal} malicious / {sus} suspicious\033[0m / {vt['harmless']} harmless  [{tot} total]")

    if vt["last_analysis_date"]:
        ok(f"Last Scanned     : {vt['last_analysis_date']}")

    if vt["categories"]:
        ok(f"Categories       : {', '.join(vt['categories'])}")

    if vt["tags"]:
        warn(f"Tags             : {', '.join(vt['tags'])}")

    # Flagged engines
    if vt["flagged_engines"]:
        warn(f"Flagged by {len(vt['flagged_engines'])} engine(s):")
        for e in vt["flagged_engines"][:5]:
            print(f"    \033[91m✖\033[0m  {e['engine']:<25} → {e['result'] or e['category']}")

    # Alerts
    if mal > 5:
        report.add_alert("HIGH", "VirusTotal",
                         f"{mal}/{tot} engines flagged as MALICIOUS.")
    elif mal > 0:
        report.add_alert("MEDIUM", "VirusTotal",
                         f"{mal}/{tot} engines flagged as malicious.")
    elif sus > 3:
        report.add_alert("MEDIUM", "VirusTotal",
                         f"{sus} engines flagged as suspicious.")
    elif rep < -20:
        report.add_alert("HIGH", "VirusTotal",
                         f"Very low reputation score: {rep}")
    else:
        ok("Clean — no significant detections.")

    report.add_section("virustotal", vt)
