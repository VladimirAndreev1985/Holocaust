"""Wi-Fi scanner — network discovery and connection via aircrack-ng suite."""

from __future__ import annotations

import csv
import io
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from core.logger import get_logger, get_audit_logger
from models.network_interface import WiFiNetwork

log = get_logger("wifi_scanner")


class WiFiScanner:
    """Scans for Wi-Fi networks using airodump-ng and handles connections."""

    def __init__(self) -> None:
        self._process: Optional[subprocess.Popen] = None
        self._networks: dict[str, WiFiNetwork] = {}
        self._temp_dir = tempfile.mkdtemp(prefix="holocaust_wifi_")

    @property
    def is_scanning(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def scan_networks(self, interface: str, duration: int = 15) -> list[WiFiNetwork]:
        """Scan for nearby Wi-Fi networks using airodump-ng."""
        audit = get_audit_logger()
        if audit:
            audit.log_action("wifi_scan", interface, f"duration={duration}s")

        log.info(f"Starting Wi-Fi scan on {interface} for {duration}s")

        output_prefix = Path(self._temp_dir) / "scan"

        try:
            self._process = subprocess.Popen(
                [
                    "sudo", "airodump-ng",
                    interface,
                    "--write", str(output_prefix),
                    "--write-interval", "3",
                    "--output-format", "csv",
                    "--band", "abg",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(duration)
            self.stop_scan()

            # Parse CSV output
            csv_file = Path(f"{output_prefix}-01.csv")
            if csv_file.exists():
                self._parse_airodump_csv(csv_file)
                log.info(f"Found {len(self._networks)} networks")
            else:
                log.warning("No airodump output file found")

        except FileNotFoundError:
            log.error("airodump-ng not found — is aircrack-ng installed?")
        except Exception as e:
            log.error(f"Wi-Fi scan error: {e}")

        return list(self._networks.values())

    def stop_scan(self) -> None:
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def connect_to_network(self, interface: str, ssid: str, password: str = "") -> bool:
        """Connect to a Wi-Fi network using wpa_supplicant."""
        audit = get_audit_logger()
        if audit:
            audit.log_action("wifi_connect", f"{interface} -> {ssid}")

        log.info(f"Connecting to '{ssid}' on {interface}")

        if not password:
            # Open network
            return self._connect_open(interface, ssid)

        return self._connect_wpa(interface, ssid, password)

    def disconnect(self, interface: str) -> bool:
        """Disconnect from current Wi-Fi network."""
        log.info(f"Disconnecting {interface}")
        try:
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                capture_output=True, timeout=10, check=True,
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except Exception as e:
            log.error(f"Disconnect failed: {e}")
            return False

    def get_networks(self) -> list[WiFiNetwork]:
        return list(self._networks.values())

    def get_network(self, bssid: str) -> Optional[WiFiNetwork]:
        return self._networks.get(bssid)

    # --- Private ---

    def _parse_airodump_csv(self, csv_path: Path) -> None:
        """Parse airodump-ng CSV output."""
        try:
            content = csv_path.read_text(encoding="utf-8", errors="ignore")
            sections = content.split("\r\n\r\n")

            if not sections:
                return

            # First section: access points
            ap_section = sections[0]
            reader = csv.reader(io.StringIO(ap_section))

            header = None
            for row in reader:
                row = [c.strip() for c in row]
                if not row:
                    continue
                if "BSSID" in row:
                    header = row
                    continue
                if header is None or len(row) < 11:
                    continue

                try:
                    bssid = row[0].strip()
                    if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                        continue

                    network = WiFiNetwork(
                        bssid=bssid,
                        ssid=row[13].strip() if len(row) > 13 else "",
                        channel=int(row[3].strip()) if row[3].strip().isdigit() else 0,
                        signal_strength=int(row[8].strip()) if row[8].strip().lstrip("-").isdigit() else 0,
                        encryption=row[5].strip(),
                        cipher=row[6].strip() if len(row) > 6 else "",
                        auth=row[7].strip() if len(row) > 7 else "",
                        first_seen=row[1].strip(),
                        last_seen=row[2].strip(),
                    )

                    self._networks[bssid] = network
                except (ValueError, IndexError):
                    continue

        except Exception as e:
            log.error(f"Failed to parse airodump CSV: {e}")

    @staticmethod
    def _connect_wpa(interface: str, ssid: str, password: str) -> bool:
        """Connect using wpa_supplicant."""
        try:
            # Generate wpa_supplicant config
            result = subprocess.run(
                ["wpa_passphrase", ssid, password],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                log.error(f"wpa_passphrase failed: {result.stderr}")
                return False

            config_path = Path(tempfile.mktemp(suffix=".conf"))
            config_path.write_text(result.stdout)

            # Kill existing wpa_supplicant
            subprocess.run(
                ["sudo", "killall", "wpa_supplicant"],
                capture_output=True, timeout=5,
            )
            time.sleep(1)

            # Start wpa_supplicant
            subprocess.Popen(
                ["sudo", "wpa_supplicant", "-B", "-i", interface, "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)

            # Get IP via DHCP
            subprocess.run(
                ["sudo", "dhclient", interface],
                capture_output=True, timeout=30,
            )

            log.info(f"Connected to {ssid}")
            return True

        except Exception as e:
            log.error(f"WPA connection failed: {e}")
            return False

    @staticmethod
    def _connect_open(interface: str, ssid: str) -> bool:
        """Connect to open network."""
        try:
            subprocess.run(
                ["sudo", "iwconfig", interface, "essid", ssid],
                capture_output=True, timeout=10, check=True,
            )
            subprocess.run(
                ["sudo", "dhclient", interface],
                capture_output=True, timeout=30,
            )
            log.info(f"Connected to open network {ssid}")
            return True
        except Exception as e:
            log.error(f"Open connection failed: {e}")
            return False

    def __del__(self) -> None:
        self.stop_scan()
