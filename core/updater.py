"""Handles updating of security databases: Metasploit, Nmap scripts, CVE cache."""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Signal

from core.logger import get_logger

log = get_logger("updater")


class UpdateProgress(QObject):
    """Signals for update progress tracking."""
    started = Signal(str)        # component name
    progress = Signal(str, int)  # component name, percent
    finished = Signal(str, bool, str)  # component name, success, message
    all_done = Signal()


class Updater:

    def __init__(self) -> None:
        self.signals = UpdateProgress()
        self._last_update: dict[str, datetime] = {}

    def update_all(self) -> dict[str, bool]:
        """Run all updates sequentially. Returns {component: success}."""
        results = {}
        results["metasploit"] = self.update_metasploit()
        results["nmap_scripts"] = self.update_nmap_scripts()
        results["cve_database"] = self.update_cve_database()
        self.signals.all_done.emit()
        return results

    def update_metasploit(self) -> bool:
        """Run msfupdate to update Metasploit framework."""
        component = "metasploit"
        self.signals.started.emit(component)
        log.info("Updating Metasploit database...")

        try:
            process = subprocess.Popen(
                ["sudo", "msfupdate"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            output_lines = []
            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if line:
                    output_lines.append(line)
                    log.debug(f"msfupdate: {line}")

            process.wait(timeout=600)
            success = process.returncode == 0

            if success:
                self._last_update[component] = datetime.now()
                log.info("Metasploit updated successfully")
            else:
                log.error(f"msfupdate exited with code {process.returncode}")

            self.signals.finished.emit(component, success, "\n".join(output_lines[-5:]))
            return success

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            log.error(f"Metasploit update failed: {e}")
            self.signals.finished.emit(component, False, str(e))
            return False

    def update_nmap_scripts(self) -> bool:
        """Update Nmap script database."""
        component = "nmap_scripts"
        self.signals.started.emit(component)
        log.info("Updating Nmap scripts...")

        try:
            result = subprocess.run(
                ["sudo", "nmap", "--script-updatedb"],
                capture_output=True, text=True, timeout=120,
            )
            success = result.returncode == 0
            msg = result.stdout.strip() or result.stderr.strip()

            if success:
                self._last_update[component] = datetime.now()
                log.info("Nmap scripts updated")
            else:
                log.error(f"Nmap script update failed: {msg}")

            self.signals.finished.emit(component, success, msg[:200])
            return success

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.error(f"Nmap script update failed: {e}")
            self.signals.finished.emit(component, False, str(e))
            return False

    def update_cve_database(self) -> bool:
        """Update local CVE cache from NVD API and save to SQLite."""
        component = "cve_database"
        self.signals.started.emit(component)
        log.info("Updating CVE database...")

        try:
            import requests
            import sqlite3
            from database.db_manager import get_cve_cache_db

            db_path = get_cve_cache_db()
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            total_inserted = 0
            # Fetch multiple pages of recent CVEs
            for start_index in range(0, 500, 100):
                url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?resultsPerPage=100&startIndex={start_index}"
                )
                response = requests.get(url, timeout=30)
                if response.status_code != 200:
                    log.warning(f"NVD API returned HTTP {response.status_code} at index {start_index}")
                    break

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                    # Extract CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_score = 0.0
                    severity = "info"
                    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        metric_list = metrics.get(version_key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "info").lower()
                            break

                    published = cve.get("published", "")[:10]

                    # Extract affected products from CPE
                    affected_product = ""
                    affected_version = ""
                    configs = cve.get("configurations", [])
                    for config in configs:
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                cpe = match.get("criteria", "")
                                parts = cpe.split(":")
                                if len(parts) >= 6:
                                    affected_product = parts[4]
                                    affected_version = parts[5] if parts[5] != "*" else ""
                                    break

                    cursor.execute("""
                        INSERT OR REPLACE INTO cve_entries
                        (cve_id, title, description, cvss_score, severity,
                         published_date, affected_product, affected_version, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id, cve_id, desc[:1000], cvss_score, severity,
                        published, affected_product, affected_version,
                        datetime.now().isoformat(),
                    ))
                    total_inserted += 1

                conn.commit()
                log.info(f"CVE batch: {start_index}-{start_index+100}, total so far: {total_inserted}")

            conn.close()
            self._last_update[component] = datetime.now()
            msg = f"Saved {total_inserted} CVE entries"
            log.info(msg)
            self.signals.finished.emit(component, True, msg)
            return True

        except Exception as e:
            log.error(f"CVE database update failed: {e}")
            self.signals.finished.emit(component, False, str(e))
            return False

    def last_update_time(self, component: str) -> Optional[datetime]:
        return self._last_update.get(component)
