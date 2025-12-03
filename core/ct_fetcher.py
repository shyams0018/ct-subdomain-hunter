import requests
from typing import List, Dict

CRT_SH_URL = "https://crt.sh/"


def fetch_ct_entries(domain: str) -> List[Dict]:
    """
    Fetch raw CT entries for a given domain from crt.sh.
    Uses the public JSON interface.
    """
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    headers = {
        # Helps avoid some WAF / blocking issues
        "User-Agent": "ct-subdomain-hunter/0.1 (+https://github.com/shyams0018/ct-subdomain-hunter)"
    }

    resp = requests.get(CRT_SH_URL, params=params, headers=headers, timeout=30)

    print(
        f"[DEBUG] crt.sh status={resp.status_code}, "
        f"url={resp.url}, content-type={resp.headers.get('Content-Type')}"
    )

    try:
        data = resp.json()
        print(f"[DEBUG] Parsed JSON from crt.sh with {len(data)} entries.")
        return data
    except ValueError:
        # This means we didn't get JSON back (probably HTML error page).
        print("[DEBUG] Failed to parse JSON from crt.sh. First 300 chars of response:")
        print(resp.text[:300])
        return []


def extract_subdomains_from_ct(data: List[Dict]) -> List[str]:
    """
    Extract subdomain names from crt.sh JSON entries.
    name_value can contain multiple DNS names separated by newlines.
    """
    subdomains: List[str] = []
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip()
            if name:
                subdomains.append(name)

    print(f"[DEBUG] Extracted {len(subdomains)} raw subdomain names from CT entries.")
    return subdomains
