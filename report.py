"""
ThreatMapper - Merkezi Rapor Motoru
Tüm modüllerden gelen veriyi toplar, terminal tablosu + JSON üretir.
"""

import json
import datetime
from utils.banner import RESET, BOLD, RED, GREEN, YELLOW, BLUE, CYAN, WHITE, GRAY, PURPLE

class ThreatReport:
    def __init__(self, target: str):
        self.target    = target
        self.timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        self.sections  = {}   # module_name -> dict
        self.alerts    = []   # {"level": HIGH/MED/LOW, "source": ..., "msg": ...}

    def add_section(self, name: str, data: dict):
        self.sections[name] = data

    def add_alert(self, level: str, source: str, msg: str):
        self.alerts.append({"level": level, "source": source, "message": msg})

    # ── Terminal print helpers ────────────────────────────────────────────────

    def _row(self, label: str, value: str, color: str = WHITE):
        label_col = f"{GRAY}{label:<22}{RESET}"
        val_col   = f"{color}{value}{RESET}"
        print(f"  │  {label_col} {val_col}")

    def _divider(self, title: str = ""):
        if title:
            pad = "─" * max(0, 52 - len(title))
            print(f"  ├─ {CYAN}{BOLD}{title}{RESET} {GRAY}{pad}{RESET}")
        else:
            print(f"  ├{'─'*56}")

    def _open(self):
        print(f"\n  ╔{'═'*56}╗")
        print(f"  ║  {WHITE}{BOLD}THREATMAPPER INTELLIGENCE REPORT{RESET}{'':>22}  ║")
        print(f"  ║  {GRAY}Target : {WHITE}{self.target:<45}{RESET}  ║")
        print(f"  ║  {GRAY}Time   : {WHITE}{self.timestamp:<45}{RESET}  ║")
        print(f"  ╠{'═'*56}╣")

    def _close(self):
        print(f"  ╚{'═'*56}╝\n")

    def print_report(self):
        self._open()

        # ── GeoIP / WHOIS ────────────────────────────────────────────────
        geo = self.sections.get("geo", {})
        if geo:
            self._divider("NETWORK INTELLIGENCE")
            self._row("IP Address",    geo.get("ip", "N/A"))
            self._row("Hostname",      geo.get("hostname", "N/A"))
            self._row("Organization",  geo.get("org", "N/A"),    CYAN)
            self._row("ASN",           geo.get("asn", "N/A"),    GRAY)
            self._row("Country",       f"{geo.get('country_flag','')}{geo.get('country','N/A')} / {geo.get('city','N/A')}")
            self._row("Abuse Contact", geo.get("abuse", "N/A"),  YELLOW)

        # ── DNS ─────────────────────────────────────────────────────────
        dns = self.sections.get("dns", {})
        if dns:
            self._divider("DNS RECORDS")
            for rtype, vals in dns.items():
                if vals:
                    self._row(rtype, ", ".join(str(v) for v in vals[:3]))

        # ── WHOIS ────────────────────────────────────────────────────────
        whois = self.sections.get("whois", {})
        if whois:
            self._divider("WHOIS")
            self._row("Registrar",   whois.get("registrar", "N/A"))
            self._row("Created",     whois.get("created", "N/A"))
            self._row("Expires",     whois.get("expires", "N/A"),
                      RED if whois.get("expiring_soon") else GREEN)
            self._row("Name Servers", ", ".join(whois.get("nameservers", [])[:2]))

        # ── Shodan ───────────────────────────────────────────────────────
        shodan = self.sections.get("shodan", {})
        if shodan:
            self._divider("SHODAN — OPEN PORTS & SERVICES")
            ports = shodan.get("ports", [])
            if ports:
                self._row("Open Ports", ", ".join(str(p) for p in ports))
            for svc in shodan.get("services", [])[:8]:
                risk_color = RED if svc.get("risk") == "HIGH" else YELLOW if svc.get("risk") == "MEDIUM" else GRAY
                self._row(
                    f"  :{svc['port']} {svc['transport']}",
                    f"{svc['product']}  {svc.get('version','')}",
                    risk_color
                )
            vulns = shodan.get("vulns", [])
            if vulns:
                self._row("Shodan CVEs", ", ".join(vulns[:5]), RED)

        # ── CVE / NVD ────────────────────────────────────────────────────
        cves = self.sections.get("cves", [])
        if cves:
            self._divider(f"CVE INTELLIGENCE ({len(cves)} results)")
            for cve in cves[:8]:
                sev   = cve.get("severity", "UNKNOWN")
                score = cve.get("cvss", "N/A")
                c     = RED if sev in ("CRITICAL","HIGH") else YELLOW if sev == "MEDIUM" else GRAY
                self._row(cve["id"], f"[{sev}] CVSS:{score} — {cve['desc'][:50]}", c)

        # ── VirusTotal ───────────────────────────────────────────────────
        vt = self.sections.get("virustotal", {})
        if vt:
            self._divider("VIRUSTOTAL REPUTATION")
            mal  = vt.get("malicious", 0)
            sus  = vt.get("suspicious", 0)
            har  = vt.get("harmless", 0)
            total = vt.get("total", 0)
            c    = RED if mal > 0 else YELLOW if sus > 0 else GREEN
            self._row("Detections",   f"{mal} malicious / {sus} suspicious / {har} harmless  [{total} engines]", c)
            cats = vt.get("categories", [])
            if cats:
                self._row("Categories",  ", ".join(cats[:4]))
            tags = vt.get("tags", [])
            if tags:
                self._row("Tags",        ", ".join(tags[:6]))
            last_seen = vt.get("last_analysis_date", "")
            if last_seen:
                self._row("Last Scanned", last_seen)

        # ── Alerts ──────────────────────────────────────────────────────
        if self.alerts:
            self._divider(f"ALERTS ({len(self.alerts)})")
            for a in self.alerts:
                c = RED if a["level"] == "HIGH" else YELLOW if a["level"] == "MEDIUM" else GRAY
                icon = "✖" if a["level"] == "HIGH" else "⚠" if a["level"] == "MEDIUM" else "·"
                self._row(f"{c}{icon} [{a['source']}]{RESET}", a["message"], c)

        self._close()

        # Risk özeti
        high = sum(1 for a in self.alerts if a["level"] == "HIGH")
        med  = sum(1 for a in self.alerts if a["level"] == "MEDIUM")
        low  = sum(1 for a in self.alerts if a["level"] == "LOW")
        c    = RED if high > 0 else YELLOW if med > 0 else GREEN
        print(f"  {c}{BOLD}Risk Summary:{RESET}  {RED}{high} HIGH{RESET}  {YELLOW}{med} MEDIUM{RESET}  {GRAY}{low} LOW{RESET}\n")

    def to_dict(self) -> dict:
        return {
            "target":    self.target,
            "timestamp": self.timestamp,
            "sections":  self.sections,
            "alerts":    self.alerts,
        }

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"  Report saved → {path}")
