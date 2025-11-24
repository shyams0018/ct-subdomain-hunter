from typing import List, Dict

from .ct_fetcher import fetch_ct_entries, extract_subdomains_from_ct
from .normalizer import normalize_subdomains
from .enricher import resolve_ip, get_asn_info, fetch_http_metadata
from .classifier import classify
from .storage import init_db, create_scan, upsert_subdomain, insert_finding

def run_scan(root_domain: str) -> List[Dict]:
    """
    Full scan pipeline:
    CT logs → normalize → enrich → classify → store in DB.
    Returns a list of findings for display in UI / CLI.
    """
    init_db()
    scan_id = create_scan(root_domain)

    ct_data = fetch_ct_entries(root_domain)
    raw_subs = extract_subdomains_from_ct(ct_data)
    subs = normalize_subdomains(raw_subs, root_domain)

    results: List[Dict] = []

    for sub in subs:
        ip = resolve_ip(sub)
        asn_info = get_asn_info(ip) if ip else None
        http_meta = fetch_http_metadata(sub)
        risk = classify(sub, http_meta)

        sub_id, is_new = upsert_subdomain(root_domain, sub)

        finding = {
            "root_domain": root_domain,
            "subdomain": sub,
            "ip": ip,
            "asn": asn_info.get("asn") if asn_info else None,
            "asn_description": asn_info.get("asn_description") if asn_info else None,
            "status_code": http_meta.get("status_code"),
            "title": http_meta.get("title"),
            "risk_tags": risk.get("risk_tags"),
            "risk_score": risk.get("risk_score"),
            "severity": risk.get("severity"),
            "is_new": is_new,
        }

        insert_finding(scan_id, sub_id, finding, is_new)
        results.append(finding)

    return results
