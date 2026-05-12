"""
ThreatMapper - GeoIP & WHOIS Modülü
API: ip-api.com (ücretsiz, kayıtsız), python-whois
"""

import socket
import requests
import datetime
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.report import ThreatReport

requests.packages.urllib3.disable_warnings()

COUNTRY_FLAGS = {
    "US": "🇺🇸 ", "TR": "🇹🇷 ", "DE": "🇩🇪 ", "RU": "🇷🇺 ",
    "CN": "🇨🇳 ", "GB": "🇬🇧 ", "FR": "🇫🇷 ", "NL": "🇳🇱 ",
    "JP": "🇯🇵 ", "KR": "🇰🇷 ", "BR": "🇧🇷 ", "IN": "🇮🇳 ",
    "AU": "🇦🇺 ", "CA": "🇨🇦 ", "SG": "🇸🇬 ", "HK": "🇭🇰 ",
}

SUSPICIOUS_ORGS = [
    "digitalocean", "linode", "vultr", "hetzner", "ovh",
    "choopa", "frantech", "m247", "serverius", "combahton",
]

def resolve_target(target: str) -> tuple:
    """Domain → IP çevirir, IP → hostname dener."""
    try:
        socket.inet_aton(target)
        ip = target
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = ""
        return ip, hostname
    except:
        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except:
            return None, target

def fetch_geoip(ip: str) -> dict:
    """ip-api.com ücretsiz API — kayıt gerektirmez."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"region,city,zip,lat,lon,timezone,isp,org,as,reverse,hosting,proxy,mobile",
            timeout=8
        )
        data = r.json()
        if data.get("status") == "success":
            return data
    except Exception as e:
        warn(f"GeoIP error: {e}")
    return {}

def fetch_abuse_contact(ip: str) -> str:
    """RDAP üzerinden abuse contact."""
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=6)
        data = r.json()
        for entity in data.get("entities", []):
            for role in entity.get("roles", []):
                if role == "abuse":
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "email":
                                return item[3]
    except:
        pass
    return "N/A"

def fetch_whois_basic(domain: str) -> dict:
    """python-whois varsa kullan, yoksa boş döner."""
    try:
        import whois
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]

        expiring_soon = False
        if expires and isinstance(expires, datetime.datetime):
            days_left = (expires - datetime.datetime.utcnow()).days
            expiring_soon = days_left < 30

        return {
            "registrar":    str(w.registrar or "N/A"),
            "created":      str(created)[:10] if created else "N/A",
            "expires":      str(expires)[:10] if expires else "N/A",
            "nameservers":  [str(ns).lower() for ns in (w.name_servers or [])],
            "expiring_soon": expiring_soon,
        }
    except ImportError:
        info("python-whois not installed (pip install python-whois) — WHOIS skipped.")
        return {}
    except Exception as e:
        warn(f"WHOIS error: {e}")
        return {}

def check_geo(target: str, report: ThreatReport):
    section(f"GeoIP / Network Intelligence — {target}")

    ip, hostname = resolve_target(target)
    if not ip:
        fail(f"Could not resolve: {target}")
        return

    info(f"Resolved → {ip}")
    geo = fetch_geoip(ip)

    country_code = geo.get("countryCode", "")
    flag         = COUNTRY_FLAGS.get(country_code, "🌐 ")
    org          = geo.get("org", geo.get("isp", "N/A"))
    asn          = geo.get("as", "N/A")
    city         = geo.get("city", "N/A")
    country      = geo.get("country", "N/A")
    timezone     = geo.get("timezone", "N/A")
    is_hosting   = geo.get("hosting", False)
    is_proxy     = geo.get("proxy", False)
    is_mobile    = geo.get("mobile", False)

    ok(f"IP        : {ip}")
    ok(f"Hostname  : {hostname or 'N/A'}")
    ok(f"Location  : {flag}{country} / {city}  ({timezone})")
    ok(f"Org / ISP : {org}")
    ok(f"ASN       : {asn}")

    if is_proxy:
        bad("Proxy / VPN / Tor exit node detected!")
        report.add_alert("HIGH", "GeoIP", "IP is a known proxy/VPN/Tor exit node.")
    if is_hosting:
        warn("Hosting / datacenter IP — possible bulletproof hosting")
        report.add_alert("MEDIUM", "GeoIP", "IP belongs to a hosting/datacenter provider.")
    for sus in SUSPICIOUS_ORGS:
        if sus in org.lower():
            warn(f"Suspicious hosting provider: {org}")
            report.add_alert("MEDIUM", "GeoIP", f"IP hosted on known abuse-prone provider: {org}")
            break

    abuse = fetch_abuse_contact(ip)
    ok(f"Abuse     : {abuse}")

    report.add_section("geo", {
        "ip":           ip,
        "hostname":     hostname,
        "org":          org,
        "asn":          asn,
        "country":      country,
        "country_flag": flag,
        "city":         city,
        "timezone":     timezone,
        "is_hosting":   is_hosting,
        "is_proxy":     is_proxy,
        "abuse":        abuse,
    })

    # WHOIS
    domain = hostname if hostname and not hostname == ip else target
    if not domain[0].isdigit():
        info("Fetching WHOIS...")
        whois_data = fetch_whois_basic(domain)
        if whois_data:
            ok(f"Registrar  : {whois_data.get('registrar','N/A')}")
            ok(f"Created    : {whois_data.get('created','N/A')}")
            ok(f"Expires    : {whois_data.get('expires','N/A')}")
            if whois_data.get("expiring_soon"):
                warn("Domain expiring within 30 days!")
                report.add_alert("MEDIUM", "WHOIS", "Domain expiring within 30 days.")
            report.add_section("whois", whois_data)
