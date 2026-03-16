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
    """Create database tables if they don't exist, seed initial data."""
    _init_signatures_db()
    _seed_signatures_db()
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


def _seed_signatures_db() -> None:
    """Populate device signatures DB with initial data if empty."""
    db_path = get_signatures_db()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Only seed if tables are empty
    cursor.execute("SELECT COUNT(*) FROM oui_vendor")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return

    log.info("Seeding device signatures database...")

    # === OUI Vendors (MAC prefix -> vendor + device type) ===
    oui_data = [
        # IP Cameras
        ("00:80:f0", "Hikvision", "ip_camera"),
        ("54:c4:15", "Hikvision", "ip_camera"),
        ("c0:56:e3", "Hikvision", "ip_camera"),
        ("a4:14:37", "Hikvision", "ip_camera"),
        ("28:57:be", "Hikvision", "ip_camera"),
        ("44:19:b6", "Hikvision", "ip_camera"),
        ("c4:2f:90", "Dahua", "ip_camera"),
        ("3c:ef:8c", "Dahua", "ip_camera"),
        ("a0:bd:1d", "Dahua", "ip_camera"),
        ("e0:50:8b", "Dahua", "ip_camera"),
        ("40:f4:ec", "Dahua", "ip_camera"),
        ("ec:71:db", "Reolink", "ip_camera"),
        ("b8:a4:4f", "Reolink", "ip_camera"),
        ("9c:8e:cd", "Reolink", "ip_camera"),
        ("7c:dd:90", "Axis", "ip_camera"),
        ("00:40:8c", "Axis", "ip_camera"),
        ("ac:cc:8e", "Axis", "ip_camera"),
        ("00:62:6e", "Vivotek", "ip_camera"),
        ("00:02:d1", "Vivotek", "ip_camera"),
        ("00:18:85", "Avigilon", "ip_camera"),
        ("70:b3:d5", "Uniview", "ip_camera"),
        # Routers / Network equipment
        ("00:1a:2b", "Cisco", "router"),
        ("00:1b:0d", "Cisco", "router"),
        ("00:25:45", "Cisco", "router"),
        ("f8:72:ea", "Cisco", "router"),
        ("00:17:0f", "Cisco", "router"),
        ("08:00:27", "Mikrotik", "router"),
        ("00:0c:42", "Mikrotik", "router"),
        ("6c:3b:6b", "Mikrotik", "router"),
        ("e4:8d:8c", "Mikrotik", "router"),
        ("74:4d:28", "Mikrotik", "router"),
        ("d4:01:c3", "TP-Link", "router"),
        ("50:c7:bf", "TP-Link", "router"),
        ("b0:be:76", "TP-Link", "router"),
        ("c0:25:e9", "TP-Link", "router"),
        ("14:cc:20", "TP-Link", "router"),
        ("30:b5:c2", "TP-Link", "router"),
        ("10:fe:ed", "D-Link", "router"),
        ("00:26:5a", "D-Link", "router"),
        ("78:54:2e", "D-Link", "router"),
        ("f0:9f:c2", "Ubiquiti", "router"),
        ("68:72:51", "Ubiquiti", "router"),
        ("24:5a:4c", "Ubiquiti", "router"),
        ("e0:63:da", "Ubiquiti", "router"),
        ("04:18:d6", "Ubiquiti", "router"),
        ("b4:fb:e4", "Ubiquiti", "router"),
        ("00:1e:58", "D-Link", "router"),
        ("c8:be:19", "D-Link", "router"),
        ("00:18:e7", "Netgear", "router"),
        ("a4:2b:8c", "Netgear", "router"),
        ("28:c6:8e", "Netgear", "router"),
        ("e4:f4:c6", "Netgear", "router"),
        ("dc:ef:09", "Netgear", "router"),
        ("c4:04:15", "Netgear", "router"),
        ("10:da:43", "Netgear", "router"),
        ("b0:48:7a", "Asus", "router"),
        ("1c:87:2c", "Asus", "router"),
        ("38:d5:47", "Asus", "router"),
        ("f4:6d:04", "Asus", "router"),
        # Printers
        ("00:1b:a9", "HP", "printer"),
        ("3c:d9:2b", "HP", "printer"),
        ("a0:d3:c1", "HP", "printer"),
        ("9c:b6:54", "HP", "printer"),
        ("00:00:48", "Epson", "printer"),
        ("00:26:ab", "Epson", "printer"),
        ("44:d2:44", "Epson", "printer"),
        ("00:1e:8f", "Canon", "printer"),
        ("18:0c:ac", "Canon", "printer"),
        ("00:15:99", "Samsung", "printer"),
        ("00:21:91", "Samsung", "printer"),
        ("00:16:44", "Lexmark", "printer"),
        ("00:20:00", "Lexmark", "printer"),
        ("00:68:eb", "Brother", "printer"),
        ("00:1b:a9", "Brother", "printer"),
        # Smart/IoT
        ("b8:27:eb", "Raspberry Pi", "iot"),
        ("dc:a6:32", "Raspberry Pi", "iot"),
        ("e4:5f:01", "Raspberry Pi", "iot"),
        ("28:cd:c1", "Raspberry Pi", "iot"),
        ("2c:cf:67", "Raspberry Pi", "iot"),
        ("50:c7:bf", "Espressif", "iot"),
        ("30:ae:a4", "Espressif", "iot"),
        ("24:6f:28", "Espressif", "iot"),
        ("a4:cf:12", "Espressif", "iot"),
        ("cc:50:e3", "Espressif", "iot"),
        ("ac:67:b2", "Espressif", "iot"),
        # Mobile
        ("f8:e0:79", "Motorola", "mobile"),
        ("3c:5a:b4", "Google", "mobile"),
        ("f4:f5:d8", "Google", "mobile"),
        # Apple
        ("3c:22:fb", "Apple", "pc_mac"),
        ("f0:18:98", "Apple", "pc_mac"),
        ("14:7d:da", "Apple", "pc_mac"),
        ("a8:60:b6", "Apple", "pc_mac"),
        ("a4:83:e7", "Apple", "pc_mac"),
        ("3c:06:30", "Apple", "pc_mac"),
        ("f8:ff:c2", "Apple", "pc_mac"),
        # Switches
        ("00:04:96", "Cisco", "switch"),
        ("00:0b:be", "Cisco", "switch"),
        ("00:1c:0e", "Cisco", "switch"),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO oui_vendor (prefix, vendor, device_type) VALUES (?, ?, ?)",
        oui_data,
    )

    # === Port Signatures ===
    port_data = [
        ("80,443,554,8000,8080", "ip_camera", 70),
        ("80,443,554,37777", "ip_camera", 80),          # Dahua
        ("80,443,554,8000,8200", "ip_camera", 80),      # Hikvision
        ("80,443,8443", "router", 50),
        ("22,80,443,8291,8728", "router", 85),           # Mikrotik
        ("22,80,443,8443,8080", "router", 60),
        ("9100,515,631", "printer", 85),
        ("9100,80,443", "printer", 70),
        ("631", "printer", 60),                          # IPP/CUPS
        ("135,139,445,3389", "pc_windows", 80),
        ("135,139,445", "pc_windows", 70),
        ("22,111,2049", "pc_linux", 70),
        ("22,80,443,3306", "server", 65),
        ("22,80,443,5432", "server", 65),
        ("22,80,443,8080,8443", "server", 60),
        ("53,80,443", "router", 60),                     # DNS + web = router
        ("21,22,80,443", "server", 55),
        ("548,5900,7000,62078", "pc_mac", 80),           # AFP, VNC, AirPlay
        ("5353,62078", "mobile", 60),                    # mDNS + Apple mobile
        ("8883,1883", "iot", 70),                        # MQTT
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO port_signature (ports, device_type, confidence) VALUES (?, ?, ?)",
        port_data,
    )

    # === Product Signatures ===
    product_data = [
        ("hikvision", "ip_camera", 95),
        ("dahua", "ip_camera", 95),
        ("reolink", "ip_camera", 95),
        ("axis", "ip_camera", 90),
        ("vivotek", "ip_camera", 90),
        ("avigilon", "ip_camera", 90),
        ("uniview", "ip_camera", 90),
        ("ipcam", "ip_camera", 85),
        ("network camera", "ip_camera", 85),
        ("webcam", "ip_camera", 80),
        ("foscam", "ip_camera", 90),
        ("amcrest", "ip_camera", 90),
        ("mikrotik", "router", 95),
        ("routeros", "router", 95),
        ("dd-wrt", "router", 90),
        ("openwrt", "router", 90),
        ("cisco ios", "router", 90),
        ("ubiquiti", "router", 90),
        ("unifi", "router", 90),
        ("edgeos", "router", 90),
        ("hp laserjet", "printer", 95),
        ("hp officejet", "printer", 95),
        ("hp deskjet", "printer", 95),
        ("epson", "printer", 85),
        ("canon pixma", "printer", 90),
        ("brother", "printer", 85),
        ("lexmark", "printer", 85),
        ("xerox", "printer", 85),
        ("samsung printer", "printer", 90),
        ("cups", "printer", 70),
        ("windows", "pc_windows", 80),
        ("microsoft", "pc_windows", 70),
        ("microsoft-ds", "pc_windows", 75),
        ("samba", "pc_linux", 60),
        ("apache", "server", 60),
        ("nginx", "server", 60),
        ("openssh", "server", 50),
        ("ubuntu", "pc_linux", 80),
        ("debian", "pc_linux", 80),
        ("centos", "pc_linux", 80),
        ("fedora", "pc_linux", 80),
        ("red hat", "pc_linux", 80),
        ("mac os", "pc_mac", 90),
        ("macos", "pc_mac", 90),
        ("raspberry", "iot", 85),
        ("esp8266", "iot", 90),
        ("esp32", "iot", 90),
        ("tasmota", "iot", 85),
        ("home assistant", "iot", 80),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO product_signature (keyword, device_type, confidence) VALUES (?, ?, ?)",
        product_data,
    )

    # === Default Credentials ===
    creds_data = [
        # Hikvision
        ("Hikvision", "ip_camera", "http", "admin", "12345"),
        ("Hikvision", "ip_camera", "http", "admin", "admin12345"),
        ("Hikvision", "ip_camera", "rtsp", "admin", "12345"),
        ("Hikvision", "ip_camera", "http", "admin", ""),
        # Dahua
        ("Dahua", "ip_camera", "http", "admin", "admin"),
        ("Dahua", "ip_camera", "http", "admin", ""),
        ("Dahua", "ip_camera", "http", "888888", "888888"),
        ("Dahua", "ip_camera", "http", "666666", "666666"),
        ("Dahua", "ip_camera", "rtsp", "admin", "admin"),
        # Reolink
        ("Reolink", "ip_camera", "http", "admin", ""),
        ("Reolink", "ip_camera", "http", "admin", "admin"),
        # Axis
        ("Axis", "ip_camera", "http", "root", "pass"),
        ("Axis", "ip_camera", "http", "root", "root"),
        ("Axis", "ip_camera", "http", "root", ""),
        # Vivotek
        ("Vivotek", "ip_camera", "http", "root", ""),
        ("Vivotek", "ip_camera", "http", "root", "root"),
        # Generic cameras
        ("Generic", "ip_camera", "http", "admin", "admin"),
        ("Generic", "ip_camera", "http", "admin", "12345"),
        ("Generic", "ip_camera", "http", "admin", "password"),
        ("Generic", "ip_camera", "http", "admin", ""),
        ("Generic", "ip_camera", "http", "root", "root"),
        ("Generic", "ip_camera", "rtsp", "admin", "admin"),
        ("Generic", "ip_camera", "rtsp", "admin", "12345"),
        # Routers
        ("Mikrotik", "router", "http", "admin", ""),
        ("Mikrotik", "router", "ssh", "admin", ""),
        ("TP-Link", "router", "http", "admin", "admin"),
        ("D-Link", "router", "http", "admin", ""),
        ("D-Link", "router", "http", "admin", "admin"),
        ("Netgear", "router", "http", "admin", "password"),
        ("Netgear", "router", "http", "admin", "1234"),
        ("Asus", "router", "http", "admin", "admin"),
        ("Ubiquiti", "router", "http", "ubnt", "ubnt"),
        ("Ubiquiti", "router", "ssh", "ubnt", "ubnt"),
        ("Cisco", "router", "http", "admin", "admin"),
        ("Cisco", "router", "ssh", "cisco", "cisco"),
        ("Generic", "router", "http", "admin", "admin"),
        ("Generic", "router", "http", "admin", "password"),
        ("Generic", "router", "http", "admin", "1234"),
        # Printers
        ("HP", "printer", "http", "admin", ""),
        ("HP", "printer", "http", "admin", "admin"),
        ("Epson", "printer", "http", "epson", "epson"),
        ("Canon", "printer", "http", "ADMIN", "canon"),
        ("Brother", "printer", "http", "admin", "access"),
        ("Lexmark", "printer", "http", "", ""),
        ("Generic", "printer", "http", "admin", ""),
        ("Generic", "printer", "http", "admin", "admin"),
        # SSH defaults
        ("Generic", "server", "ssh", "root", "root"),
        ("Generic", "server", "ssh", "root", "toor"),
        ("Generic", "server", "ssh", "admin", "admin"),
        ("Raspberry", "iot", "ssh", "pi", "raspberry"),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO default_credentials (vendor, device_type, service, username, password) "
        "VALUES (?, ?, ?, ?, ?)",
        creds_data,
    )

    conn.commit()
    conn.close()
    log.info(f"Seeded: {len(oui_data)} OUI, {len(port_data)} port sigs, "
             f"{len(product_data)} product sigs, {len(creds_data)} credentials")


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
