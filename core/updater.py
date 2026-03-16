"""Handles updating of security databases: Metasploit, Nmap scripts, CVE cache."""

from __future__ import annotations

import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Signal

from core.logger import get_logger

log = get_logger("updater")

# NVD API rate limiting: 5 req/30s without key, 50 req/30s with key
NVD_RATE_LIMIT_DELAY = 6.5  # seconds between requests (safe for no-key)
NVD_RATE_LIMIT_DELAY_WITH_KEY = 0.7
NVD_PAGE_SIZE = 2000  # max allowed by NVD API
NVD_MAX_PAGES = 10    # 10 pages * 2000 = up to 20,000 CVEs per update


class UpdateProgress(QObject):
    """Signals for update progress tracking."""
    started = Signal(str)        # component name
    progress = Signal(str, int)  # component name, percent
    finished = Signal(str, bool, str)  # component name, success, message
    all_done = Signal()


class Updater:

    def __init__(self, nvd_api_key: str = "") -> None:
        self.signals = UpdateProgress()
        self._last_update: dict[str, datetime] = {}
        self._nvd_api_key = nvd_api_key
        self._abort = False

    def abort(self) -> None:
        self._abort = True

    def update_all(self) -> dict[str, bool]:
        """Run all updates sequentially. Returns {component: success}."""
        self._abort = False
        results = {}
        results["metasploit"] = self.update_metasploit()
        if not self._abort:
            results["nmap_scripts"] = self.update_nmap_scripts()
        if not self._abort:
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

    def _parse_cve_item(self, item: dict) -> dict | None:
        """Parse a single CVE item from NVD API response."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Extract CVSS score (try v3.1 -> v3.0 -> v2)
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

        # Extract affected products from CPE matches
        affected_product = ""
        affected_version = ""
        has_exploit = 0
        exploit_module = ""

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

        # Check references for exploit links
        references = cve.get("references", [])
        for ref in references:
            tags = ref.get("tags", [])
            if "Exploit" in tags:
                has_exploit = 1
                exploit_module = ref.get("url", "")[:200]
                break

        return {
            "cve_id": cve_id,
            "title": cve_id,
            "description": desc[:2000],
            "cvss_score": cvss_score,
            "severity": severity,
            "published_date": published,
            "affected_product": affected_product,
            "affected_version": affected_version,
            "has_exploit": has_exploit,
            "exploit_module": exploit_module,
            "last_updated": datetime.now().isoformat(),
        }

    def _nvd_request(self, params: dict) -> dict | None:
        """Make a rate-limited request to NVD API."""
        import requests

        headers = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        try:
            response = requests.get(url, params=params, headers=headers, timeout=60)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                log.warning("NVD API rate limit hit, waiting 30s...")
                time.sleep(30)
                response = requests.get(url, params=params, headers=headers, timeout=60)
                if response.status_code == 200:
                    return response.json()
            log.warning(f"NVD API returned HTTP {response.status_code}")
            return None
        except Exception as e:
            log.error(f"NVD API request failed: {e}")
            return None

    def update_cve_database(self) -> bool:
        """Update local CVE cache from NVD API.

        Strategy:
        1. Fetch CVEs modified in the last 120 days (recent + updated)
        2. Fetch high/critical severity CVEs from the last year
        3. Fetch CVEs for known products (cameras, routers, Windows, etc.)
        """
        component = "cve_database"
        self.signals.started.emit(component)
        log.info("Updating CVE database (comprehensive)...")

        try:
            from database.db_manager import get_cve_cache_db

            db_path = get_cve_cache_db()
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            delay = NVD_RATE_LIMIT_DELAY_WITH_KEY if self._nvd_api_key else NVD_RATE_LIMIT_DELAY
            total_saved = 0

            # === Phase 1: Recently modified CVEs (last 120 days) ===
            log.info("Phase 1: Fetching recently modified CVEs...")
            self.signals.progress.emit("CVE: fetching recent (phase 1/3)...", 5)

            now = datetime.utcnow()
            date_start = (now - timedelta(days=120)).strftime("%Y-%m-%dT00:00:00.000")
            date_end = now.strftime("%Y-%m-%dT23:59:59.999")

            saved = self._fetch_cve_batch(
                cursor, conn, delay,
                params={
                    "lastModStartDate": date_start,
                    "lastModEndDate": date_end,
                    "resultsPerPage": str(NVD_PAGE_SIZE),
                },
                max_pages=NVD_MAX_PAGES,
                phase_label="Phase 1 (recent)",
                progress_start=5,
                progress_end=35,
            )
            total_saved += saved

            if self._abort:
                conn.close()
                return False

            # === Phase 2: High/Critical severity CVEs (last 365 days) ===
            log.info("Phase 2: Fetching high/critical CVEs...")
            self.signals.progress.emit("CVE: fetching critical (phase 2/3)...", 35)

            year_start = (now - timedelta(days=365)).strftime("%Y-%m-%dT00:00:00.000")

            for sev in ("CRITICAL", "HIGH"):
                if self._abort:
                    break
                saved = self._fetch_cve_batch(
                    cursor, conn, delay,
                    params={
                        "pubStartDate": year_start,
                        "pubEndDate": date_end,
                        "cvssV3Severity": sev,
                        "resultsPerPage": str(NVD_PAGE_SIZE),
                    },
                    max_pages=5,
                    phase_label=f"Phase 2 ({sev})",
                    progress_start=35 if sev == "CRITICAL" else 50,
                    progress_end=50 if sev == "CRITICAL" else 65,
                )
                total_saved += saved

            if self._abort:
                conn.close()
                return False

            # === Phase 3: Product-specific CVEs (network equipment, cameras, etc.) ===
            log.info("Phase 3: Fetching product-specific CVEs...")
            self.signals.progress.emit("CVE: fetching product-specific (phase 3/3)...", 65)

            # Key products for network auditing
            target_keywords = [
                "cpe:2.3:h:hikvision:*",
                "cpe:2.3:h:dahua:*",
                "cpe:2.3:o:microsoft:windows",
                "cpe:2.3:a:apache:*",
                "cpe:2.3:a:nginx:*",
                "cpe:2.3:a:openssh:*",
                "cpe:2.3:o:mikrotik:*",
                "cpe:2.3:h:cisco:*",
                "cpe:2.3:a:samba:*",
                "cpe:2.3:a:proftpd:*",
                "cpe:2.3:a:vsftpd:*",
            ]

            products_done = 0
            for keyword in target_keywords:
                if self._abort:
                    break
                pct = 65 + int((products_done / len(target_keywords)) * 30)
                self.signals.progress.emit(
                    f"CVE: {keyword.split(':')[4]}...", pct
                )

                saved = self._fetch_cve_batch(
                    cursor, conn, delay,
                    params={
                        "virtualMatchString": keyword,
                        "resultsPerPage": str(NVD_PAGE_SIZE),
                    },
                    max_pages=3,
                    phase_label=f"Phase 3 ({keyword.split(':')[4]})",
                    progress_start=pct,
                    progress_end=pct + 2,
                )
                total_saved += saved
                products_done += 1

            # Get final count
            cursor.execute("SELECT COUNT(*) FROM cve_entries")
            total_in_db = cursor.fetchone()[0]

            conn.close()
            self._last_update[component] = datetime.now()
            msg = f"Done: {total_saved} new/updated, {total_in_db} total in database"
            log.info(msg)
            self.signals.progress.emit("CVE update complete", 100)
            self.signals.finished.emit(component, True, msg)
            return True

        except Exception as e:
            log.error(f"CVE database update failed: {e}")
            self.signals.finished.emit(component, False, str(e))
            return False

    def _fetch_cve_batch(
        self,
        cursor: sqlite3.Cursor,
        conn: sqlite3.Connection,
        delay: float,
        params: dict,
        max_pages: int,
        phase_label: str,
        progress_start: int,
        progress_end: int,
    ) -> int:
        """Fetch paginated CVE results from NVD and save to DB. Returns count saved."""
        saved = 0
        start_index = 0

        for page in range(max_pages):
            if self._abort:
                break

            params["startIndex"] = str(start_index)
            data = self._nvd_request(params)

            if not data:
                break

            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                parsed = self._parse_cve_item(item)
                if not parsed:
                    continue

                cursor.execute("""
                    INSERT OR REPLACE INTO cve_entries
                    (cve_id, title, description, cvss_score, severity,
                     published_date, affected_product, affected_version,
                     has_exploit, exploit_module, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    parsed["cve_id"], parsed["title"], parsed["description"],
                    parsed["cvss_score"], parsed["severity"],
                    parsed["published_date"], parsed["affected_product"],
                    parsed["affected_version"], parsed["has_exploit"],
                    parsed["exploit_module"], parsed["last_updated"],
                ))
                saved += 1

            conn.commit()

            start_index += len(vulnerabilities)
            pct = progress_start + int(
                (page / max_pages) * (progress_end - progress_start)
            )
            self.signals.progress.emit(
                f"{phase_label}: {saved} CVEs ({start_index}/{total_results})", pct
            )
            log.info(f"{phase_label}: page {page+1}, saved {saved}, "
                     f"progress {start_index}/{total_results}")

            # Stop if we've fetched all results
            if start_index >= total_results:
                break

            # Rate limit
            time.sleep(delay)

        return saved

    def last_update_time(self, component: str) -> Optional[datetime]:
        return self._last_update.get(component)
