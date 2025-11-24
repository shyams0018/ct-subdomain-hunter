import requests
from typing import List, Dict

CRT_SH_URL = "https.//crt.sh/"

def fetch_ct_entries(domain: str) -> List[Dict]:
    """
    Fetch raw CT entries for a given domain from crt.sh.
    Uses public JSON interface.
    """
    params = { 
        "q": f"%{domain}",
        "output": "json"
    }
    resp = requests.get(CRT_SH_URL, params=params, timeout=30)
    resp.raise_for_status()
    try:
        data = resp.json()
    except ValueError:
        data = []
    return data

def extract_subdomains_from_ct(data: List[Dict]) -> List[str]:
    """
    Extract subdomain names from crt.sh (JSON entries).
    name_value can contain multiple DNS names separated by newlines.
    """
    subdomains: List[str] = []
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip()
            if name:
                subdomains.append(name)
    return subdomains