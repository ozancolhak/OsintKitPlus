#!/usr/bin/env python3
"""
ThreatMapper - Unified OSINT Intelligence Engine
Author: Ozan İsmail Çolhak
"""

import argparse
import sys
from utils.banner import print_banner
from utils.report import ThreatReport
from modules.geo          import check_geo
from modules.dns_intel    import check_dns
from modules.shodan_intel import check_shodan
from modules.cve_intel    import check_cve
from modules.virustotal   import check_virustotal

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="ThreatMapper — Unified OSINT Intelligence Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target",
        help="IP address or domain (e.g. 8.8.8.8 or example.com)")

    # API keys
    parser.add_argument("--shodan-key",  metavar="KEY", help="Shodan API key (shodan.io)")
    parser.add_argument("--vt-key",      metavar="KEY", help="VirusTotal API key (virustotal.com)")
    parser.add_argument("--nvd-key",     metavar="KEY", help="NVD API key (nvd.nist.gov) — optional, increases rate limit")

    # CVE options
    parser.add_argument("--cve",         metavar="KEYWORD", nargs="+",
                        help="Custom keywords for NVD CVE search (e.g. --cve apache nginx)")
    parser.add_argument("--cve-limit",   type=int, default=10,
                        help="Max CVEs per keyword (default: 10)")

    # Module control
    parser.add_argument("--skip",        nargs="+",
                        choices=["geo", "dns", "shodan", "cve", "virustotal"],
                        default=[],
                        help="Skip specific modules")
    parser.add_argument("--only",        nargs="+",
                        choices=["geo", "dns", "shodan", "cve", "virustotal"],
                        help="Run only specified modules")

    # Output
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save full report as JSON (e.g. report.json)")

    args   = parser.parse_args()
    target = args.target.strip().lstrip("https://").lstrip("http://").split("/")[0]

    print(f"  Target   : \033[1m{target}\033[0m")
    print(f"  Modules  : geo · dns · shodan · cve · virustotal\n")

    report = ThreatReport(target)

    modules = {
        "geo":        lambda: check_geo(target, report),
        "dns":        lambda: check_dns(target, report),
        "shodan":     lambda: check_shodan(target, report, args.shodan_key),
        "cve":        lambda: check_cve(target, report, args.cve, args.cve_limit, args.nvd_key),
        "virustotal": lambda: check_virustotal(target, report, args.vt_key),
    }

    run_modules = args.only if args.only else list(modules.keys())
    run_modules = [m for m in run_modules if m not in args.skip]

    for mod in run_modules:
        try:
            modules[mod]()
        except KeyboardInterrupt:
            print("\n  Interrupted.")
            break
        except Exception as e:
            print(f"  [!] Module {mod} error: {e}")

    report.print_report()

    if args.output:
        report.save(args.output)

if __name__ == "__main__":
    main()
