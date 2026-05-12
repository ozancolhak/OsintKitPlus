"""
ThreatMapper - Shodan Intelligence Modülü
API: Shodan (ücretsiz API key gerekli — shodan.io)
Çeker: Açık portlar, servisler, banner'lar, CVE listesi
"""

import requests
import socket
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.report import ThreatReport

requests.packages.urllib3.disable_warnings()

HIGH_RISK_PORTS = {
    21, 23, 111, 135, 139, 445, 1433, 1521, 2375,
    3306, 3389, 5432, 5900, 6379, 7001, 8888, 9200, 27017
}
MEDIUM_RISK_PORTS = {25, 53, 80, 110, 143, 389, 8080, 8443, 4369, 5000, 9300}

def classify_port_risk(port: int) -> str:
    if port in HIGH_RISK_PORTS:   return "HIGH"
    if port in MEDIUM_RISK_PORTS: return "MEDIUM"
    return "LOW"

def fetch_shodan(ip: str, api_key: str) -> dict:
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=12
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 401:
            warn("Shodan: Invalid API key.")
        elif r.status_code == 404:
            info("Shodan: No data for this IP.")
        else:
            warn(f"Shodan API error: {r.status_code}")
    except Exception as e:
        warn(f"Shodan request error: {e}")
    return {}

def check_shodan(target: str, report: ThreatReport, api_key: str = None):
    section(f"Shodan Intelligence — {target}")

    if not api_key:
        info("Shodan skipped — use --shodan-key <API_KEY> to enable")
        info("Free API key: https://account.shodan.io/register")
        return

    # IP çöz
    try:
        socket.inet_aton(target)
        ip = target
    except:
        try:
            ip = socket.gethostbyname(target)
            info(f"Resolved {target} → {ip}")
        except:
            fail(f"Cannot resolve {target}")
            return

    data = fetch_shodan(ip, api_key)
    if not data:
        return

    ports    = data.get("ports", [])
    hostnames= data.get("hostnames", [])
    os_info  = data.get("os") or "Unknown"
    tags     = data.get("tags", [])
    vulns    = list(data.get("vulns", {}).keys())
    services = []

    ok(f"OS          : {os_info}")
    ok(f"Hostnames   : {', '.join(hostnames[:3]) or 'N/A'}")
    ok(f"Open Ports  : {', '.join(str(p) for p in sorted(ports))}")

    if tags:
        warn(f"Shodan Tags : {', '.join(tags)}")
        for tag in tags:
            if tag in ("honeypot", "malware", "botnet", "scanner"):
                report.add_alert("HIGH", "Shodan", f"Tag detected: {tag}")

    # Servis detayları
    info("Service details:")
    for item in data.get("data", [])[:12]:
        port      = item.get("port", 0)
        transport = item.get("transport", "tcp")
        product   = item.get("product", "unknown")
        version   = item.get("version", "")
        banner    = item.get("data", "")[:60].replace("\n", " ").strip()
        risk      = classify_port_risk(port)
        risk_c    = "\033[91m" if risk == "HIGH" else "\033[93m" if risk == "MEDIUM" else "\033[90m"

        svc = {"port": port, "transport": transport,
               "product": product, "version": version, "risk": risk}
        services.append(svc)

        print(f"    {risk_c}[{risk}]\033[0m  :{port}/{transport}  {product} {version}")
        if banner:
            print(f"           \033[90mBanner: {banner}\033[0m")

        if risk == "HIGH":
            report.add_alert("HIGH", "Shodan",
                             f"High-risk port open: {port}/{transport} ({product} {version})")
        elif risk == "MEDIUM":
            report.add_alert("MEDIUM", "Shodan",
                             f"Notable port open: {port}/{transport} ({product})")

    # CVE'ler
    if vulns:
        bad(f"Shodan CVEs ({len(vulns)}): {', '.join(vulns[:6])}")
        for cve in vulns:
            report.add_alert("HIGH", "Shodan", f"Known vulnerability: {cve}")
    else:
        ok("No CVEs listed in Shodan data.")

    report.add_section("shodan", {
        "ip":       ip,
        "os":       os_info,
        "ports":    sorted(ports),
        "services": services,
        "vulns":    vulns,
        "tags":     tags,
    })
