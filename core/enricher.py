from typing import Optional, Dict
import socket
import requests
from ipwhois import IPWhois

def resolve_ip(subdomain: str) -> Optional[str]:
    """
    Resolve a subdomain to an IPv4 address.
    Returns None if resolution fails.
    """
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None

def get_asn_info(ip: str) -> Optional[Dict]:
    """
    Use ipwhois to lookup ASN information for an IP.
    Returns a dict with ASN details or None on error.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
        }
    except Exception:
        return None

def fetch_http_metadata(subdomain: str) -> Dict:
    """
    Fetch basic HTTP metadata for a subdomain (HTTPS first).
    Falls back to HTTP if HTTPS fails.
    """
    def _get(url: str):
        return requests.get(url, timeout=5, allow_redirects=True, verify=True)

    urls_to_try = [f"https://{subdomain}", f"http://{subdomain}"]
    for url in urls_to_try:
        try:
            resp = _get(url)
            text = resp.text or ""
            title = ""
            lower = text.lower()
            if "<title>" in lower and "</title>" in lower:
                start = lower.find("<title>")
                end = lower.find("</title>", start)
                if start != -1 and end != -1:
                    # 7 = len("<title>")
                    title = text[start + 7:end].strip()

            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "title": title,
                "body_snippet": text[:500],
            }
        except Exception:
            continue

    # If all attempts fail:
    return {
        "url": urls_to_try[0],
        "status_code": None,
        "headers": {},
        "title": "",
        "body_snippet": "",
    }
