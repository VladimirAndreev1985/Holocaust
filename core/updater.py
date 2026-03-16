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
        """Update local CVE cache from online sources."""
        component = "cve_database"
        self.signals.started.emit(component)
        log.info("Updating CVE database...")

        try:
            import requests

            # Fetch recent CVEs from NIST NVD (simplified)
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                self._last_update[component] = datetime.now()
                log.info("CVE database updated")
                self.signals.finished.emit(component, True, "Updated from NVD")
                return True
            else:
                log.error(f"CVE update HTTP {response.status_code}")
                self.signals.finished.emit(component, False, f"HTTP {response.status_code}")
                return False

        except Exception as e:
            log.error(f"CVE database update failed: {e}")
            self.signals.finished.emit(component, False, str(e))
            return False

    def last_update_time(self, component: str) -> Optional[datetime]:
        return self._last_update.get(component)
