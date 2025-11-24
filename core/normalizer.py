from typing import Iterable, Set, List

def normalize_subdomains(raw_subdomains: Iterable[str], root_domain: str) -> List[str]:
    """
    Normalize and filter subdomains:
    - lowercase
    - strip words
    - remove wildcard prefixes 
    - ensure they end with the root_domain
    - exclude the root_domain itself
    - deduplicate results
    """
    normalized: Set[str] = set()
    root = root_domain.lower().strip()

    for sub in raw_subdomains:
        if not sub:
            continue
        s = sub.strip().lower()

        if s.startswith("*."):
            s = s[2:]

        if not s.endswith(root):
            continue

        if s == root:
            continue

        normalized.add(s)
    return sorted(normalized)