"""
ThreatMapper - DNS Intelligence Modülü
Kontroller: A, AAAA, MX, NS, TXT, CNAME, SOA kayıtları
"""

import socket
import subprocess
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.report import ThreatReport

def dns_lookup(domain: str, record_type: str) -> list:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        return [str(r) for r in answers]
    except ImportError:
        try:
            result = subprocess.run(
                ["nslookup", f"-type={record_type}", domain],
                capture_output=True, text=True, timeout=8
            )
            lines = [l.strip() for l in result.stdout.splitlines()
                     if "=" in l or "address" in l.lower()]
            return lines[:5]
        except:
            return []
    except Exception:
        return []

def check_dns(target: str, report: ThreatReport):
    section(f"DNS Intelligence — {target}")

    # IP mi domain mi?
    try:
        socket.inet_aton(target)
        info("Target is an IP — DNS lookup skipped.")
        return
    except:
        pass

    dns_data = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        results = dns_lookup(target, rtype)
        if results:
            dns_data[rtype] = results
            ok(f"{rtype:<6} → {results[0][:70]}")
            for r in results[1:3]:
                print(f"         {'':6}  {r[:70]}")
        else:
            info(f"{rtype:<6} → No record")

    # SPF & DMARC özet
    txt_records = dns_data.get("TXT", [])
    spf = [r for r in txt_records if "v=spf1" in r.lower()]
    if spf:
        ok(f"SPF    → {spf[0][:70]}")
    else:
        warn("SPF record not found — email spoofing possible")
        report.add_alert("MEDIUM", "DNS", "No SPF record found — domain may be spoofable.")

    dmarc = dns_lookup(f"_dmarc.{target}", "TXT")
    if dmarc:
        ok(f"DMARC  → {dmarc[0][:70]}")
        if "p=none" in " ".join(dmarc).lower():
            warn("DMARC policy is p=none — monitoring only, no enforcement")
            report.add_alert("LOW", "DNS", "DMARC policy is p=none — no enforcement.")
    else:
        warn("DMARC record not found")
        report.add_alert("MEDIUM", "DNS", "No DMARC record found.")

    report.add_section("dns", dns_data)
