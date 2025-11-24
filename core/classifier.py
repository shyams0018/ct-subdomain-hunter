from typing import Dict, List

RISK_KEYWORDS = {
    "admin": 30,
    "login": 15,
    "staging": 20,
    "test": 10,
    "dev": 10,
    "backup": 25,
    "index of /": 40,
    "wp-login.php": 35,
}

def classify(subdomain: str, http_meta: Dict) -> Dict:
    """
    Basic heuristic risk classification based on keywords in:
    - subdomain name
    - URL
    - title
    - body snippet (first 500 chars)
    Returns risk_tags, risk_score, severity.
    """
    risk_tags: List[str] = []
    risk_score = 0

    text = " ".join([
        subdomain,
        http_meta.get("url", ""),
        http_meta.get("title", ""),
        http_meta.get("body_snippet", "")
    ]).lower()

    for keyword, weight in RISK_KEYWORDS.items():
        if keyword in text:
            risk_tags.append(keyword)
            risk_score += weight

    status = http_meta.get("status_code")
    if status and 200 <= status < 400:
        risk_score += 5

    if risk_score >= 60:
        severity = "critical"
    elif risk_score >= 35:
        severity = "high"
    elif risk_score >= 15:
        severity = "medium"
        # low or no obvious risky signals
    else:
        severity = "low"

    return {
        "risk_tags": risk_tags,
        "risk_score": risk_score,
        "severity": severity,
    }
