"""Database manager — SQLite for device signatures and CVE cache."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from core.logger import get_logger

log = get_logger("database")

DB_DIR = Path(__file__).parent


def get_signatures_db() -> Path:
    return DB_DIR / "device_signatures.db"


def get_cve_cache_db() -> Path:
    return DB_DIR / "cve_cache.db"


def init_databases() -> None:
    """Create database tables if they don't exist."""
    _init_signatures_db()
    _init_cve_cache_db()
    log.info("Databases initialized")


def _init_signatures_db() -> None:
    db_path = get_signatures_db()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oui_vendor (
            prefix TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            device_type TEXT DEFAULT 'unknown'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_signature (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ports TEXT NOT NULL,
            device_type TEXT NOT NULL,
            confidence INTEGER DEFAULT 50
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product_signature (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL,
            device_type TEXT NOT NULL,
            confidence INTEGER DEFAULT 50
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS default_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            device_type TEXT DEFAULT 'generic',
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL DEFAULT ''
        )
    """)

    conn.commit()
    conn.close()


def _init_cve_cache_db() -> None:
    db_path = get_cve_cache_db()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            cvss_score REAL DEFAULT 0.0,
            severity TEXT DEFAULT 'info',
            published_date TEXT,
            affected_product TEXT,
            affected_version TEXT,
            has_exploit INTEGER DEFAULT 0,
            exploit_module TEXT DEFAULT '',
            last_updated TEXT
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_cve_product
        ON cve_entries(affected_product)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_cve_severity
        ON cve_entries(severity)
    """)

    conn.commit()
    conn.close()


def query_cve(product: str, version: str = "") -> list[dict]:
    """Search CVE cache for a product/version."""
    db_path = get_cve_cache_db()
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if version:
        cursor.execute(
            "SELECT * FROM cve_entries WHERE affected_product LIKE ? AND affected_version LIKE ?",
            (f"%{product}%", f"%{version}%"),
        )
    else:
        cursor.execute(
            "SELECT * FROM cve_entries WHERE affected_product LIKE ?",
            (f"%{product}%",),
        )

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def lookup_oui(mac_prefix: str) -> str:
    """Look up vendor from OUI prefix (e.g. '00:0e:22')."""
    db_path = get_signatures_db()
    if not db_path.exists():
        return ""

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT vendor FROM oui_vendor WHERE prefix = ?", (mac_prefix.lower(),))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else ""
