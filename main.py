import argparse
from core.pipeline import run_scan

def main():
    parser = argparse.ArgumentParser(
        description="CT-Driver Subdomain Hunter - a tool for passive subdomain detecction"

    )
    parser.add_argument(
        "domain",
        help="Root domain to scan (e.g., example.com)",
    )
    args = parser.parse_args()

    findings = run_scan(args.domain)

    print(f"\nScan complete. Found {len(findings)} subdomains.\n")
    for f in findings:
        marker = "[NEW]" if f["is_new"] else "     "
        print(
            f"{marker} {f['subdomain']:40s} "
            f"{f['severity']:8s} score={f['risk_score']:3d} "
            f"ip={f['ip'] or '-'}"
        )

if __name__ =="__main__":
    main()