import sqlite3
import json
from datetime import datetime
from typing import Dict, Tuple

DB_PATH = "ct_hunter.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        root_domain TEXT NOT NULL,
        started_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        root_domain TEXT NOT NULL,
        name TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(root_domain, name)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        subdomain_id INTEGER NOT NULL,
        ip TEXT,
        asn TEXT,
        asn_description TEXT,
        status_code INTEGER,
        title TEXT,
        risk_score INTEGER,
        severity TEXT,
        risk_tags_json TEXT,
        is_new INTEGER,
        FOREIGN KEY(scan_id) REFERENCES scans(id),
        FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
    );
    """)
    conn.commit()
    conn.close()

def create_scan(root_domain: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO scans (root_domain, started_at) VALUES (?, ?)",
        (root_domain, now),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id

def upsert_subdomain(root_domain: str, name: str) -> Tuple[int, bool]:
    """
    Insert or update a subdomain record.
    Returns (subdomain_id, is_new_subdomain).
    """
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    cur.execute(
        "SELECT id FROM subdomains WHERE root_domain=? AND name=?",
        (root_domain, name),
    )
    row = cur.fetchone()

    if row:
        sub_id = row[0]
        cur.execute(
            "UPDATE subdomains SET last_seen=? WHERE id=?",
            (now, sub_id),
        )
        is_new = False
    else:
        cur.execute(
            """
            INSERT INTO subdomains (root_domain, name, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            """,
            (root_domain, name, now, now),
        )
        sub_id = cur.lastrowid
        is_new = True

    conn.commit()
    conn.close()
    return sub_id, is_new

def insert_finding(scan_id: int, subdomain_id: int, finding: Dict, is_new: bool) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO findings (
            scan_id, subdomain_id, ip, asn, asn_description,
            status_code, title, risk_score, severity,
            risk_tags_json, is_new
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            subdomain_id,
            finding.get("ip"),
            finding.get("asn"),
            finding.get("asn_description"),
            finding.get("status_code"),
            finding.get("title"),
            finding.get("risk_score"),
            finding.get("severity"),
            json.dumps(finding.get("risk_tags", [])),
            1 if is_new else 0,
        ),
    )
    conn.commit()
    conn.close()
